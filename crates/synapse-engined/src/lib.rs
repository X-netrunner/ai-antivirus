//! Synapse engine daemon (M3): follows the sensor's event log, keeps a process table, runs the file layers (pacman trust,
//! hash table, YARA-X) and the behavior rules, and stores alerts. It runs as the unprivileged `synapse` user and has no way
//! to act on the system: what a rule's `action` would do is recorded on the alert for the responder (M4).
//!
//! The engine reads the JSONL log instead of a socket from the sensor (spec 4 sketches IPC over Unix sockets). The log is
//! already the sensor's durable output, it decouples the two processes completely (either can restart alone) and it gives
//! replay for free; a socket can replace it once the responder needs low latency.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod engine;
pub mod files;
pub mod procs;

use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use synapse_common::config::Config;
use synapse_common::event::{now_ns, Envelope};
use synapse_common::eventlog::{self, Follower};
use synapse_common::store::{NewAlert, Store};
use synapse_rules::rule::RuleSet;
use synapse_rules::scan::Yara;
use tracing::{error, info, warn};

use crate::engine::{Alert, Engine};
use crate::files::FileCheck;

/// Lines of the existing log read at start to learn the running processes.
const WARMUP_LINES: usize = 200_000;
const POLL: Duration = Duration::from_millis(200);
const SWEEP_EVERY: Duration = Duration::from_secs(10);
const STATS_EVERY: Duration = Duration::from_secs(300);

/// Load the behavior rules and YARA rules under `rules_dir` and build an engine. Broken rules are an error: an engine that
/// silently runs without its rules is worse than one that does not start.
pub fn build(cfg: &Config, rules_dir: &Path) -> Result<Engine, String> {
    let set = RuleSet::load_dir(&rules_dir.join("behavior")).map_err(|e| e.to_string())?;
    let yara = Yara::load_dir(
        &rules_dir.join("yara"),
        Duration::from_millis(u64::from(cfg.engine.yara_timeout_ms)),
    )
    .map_err(|e| e.to_string())?;
    let yara = (yara.rule_count() > 0).then_some(yara);
    info!(
        behavior_rules = set.rules.len(),
        yara_rules = yara.as_ref().map_or(0, Yara::rule_count),
        dir = %rules_dir.display(),
        "rules loaded"
    );
    let files = FileCheck::new(
        yara,
        u64::from(cfg.engine.scan_max_mb) * 1024 * 1024,
        cfg.engine.max_scans_per_sec,
    );
    let mut engine = Engine::new(set.rules, files, cfg.engine.scan_on_write);
    engine.set_allow_exe(cfg.engine.allow_exe.clone());
    Ok(engine)
}

fn store_alert(store: &Store, a: &Alert) {
    let mut detail = a.detail.clone();
    if let Some(obj) = detail.as_object_mut() {
        obj.insert("action".into(), a.action.as_str().into());
        obj.insert("layer".into(), a.layer.into());
    }
    let row = NewAlert {
        ts_ns: a.ts_ns,
        rule_id: a.rule_id.clone(),
        severity: a.severity,
        confidence: a.confidence,
        title: a.title.clone(),
        proc_key: a.proc_key,
        event_id: None,
        detail,
    };
    if let Err(e) = store.insert_alert(&row) {
        error!(error = %e, rule = %a.rule_id, "cannot store alert");
    }
}

fn parse(line: &[u8]) -> Option<Envelope> {
    serde_json::from_slice(line).ok()
}

/// The daemon: warm up from the current log, then follow it until `shutdown`.
pub fn run(cfg: &Config, shutdown: &AtomicBool) -> Result<(), String> {
    let mut engine = build(cfg, &cfg.engine.rules_dir)?;
    let mut store = Store::open(&cfg.db_path()).map_err(|e| e.to_string())?;
    let log = eventlog::log_path(&cfg.paths.log_dir);

    // the processes that already run: learn them from what the sensor logged so far (no rules, no scans)
    let mut follower = Follower::from_end(&log).map_err(|e| e.to_string())?;
    match eventlog::last_lines(&log, WARMUP_LINES) {
        Ok(lines) => {
            for l in &lines {
                if let Some(env) = parse(l) {
                    engine.learn(&env);
                }
            }
            info!(
                processes = engine.procs.len(),
                lines = lines.len(),
                "process table warmed up from the event log"
            );
        }
        Err(e) => {
            warn!(error = %e, "cannot read the event log for warm-up; processes started earlier are unknown")
        }
    }
    info!(log = %log.display(), mode = cfg.general.mode.as_str(), "engine running (alerts only: nothing is acted on before M4)");

    let (mut last_sweep, mut last_stats) = (Instant::now(), Instant::now());
    let mut bad_lines = 0u64;
    while !shutdown.load(Ordering::Relaxed) {
        let lines = match follower.poll() {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "cannot read the event log");
                Vec::new()
            }
        };
        if lines.is_empty() {
            thread::sleep(POLL);
        }
        for l in &lines {
            let Some(env) = parse(l) else {
                bad_lines += 1;
                continue;
            };
            for a in engine.handle(&mut store, &env) {
                warn!(rule = %a.rule_id, severity = a.severity.as_str(), title = %a.title, pid = a.proc_key.map(|k| k.pid), action = a.action.as_str(), "ALERT");
                store_alert(&store, &a);
            }
        }
        if last_sweep.elapsed() >= SWEEP_EVERY {
            engine.sweep(now_ns());
            last_sweep = Instant::now();
        }
        if last_stats.elapsed() >= STATS_EVERY {
            let (e, f) = (engine.stats, engine.files.stats);
            info!(
                events = e.events,
                alerts = e.alerts,
                deduped = e.deduped,
                processes = engine.procs.len(),
                files_checked = f.checked,
                files_cached = f.cached,
                files_trusted = f.trusted,
                scans_skipped_rate = f.skipped_rate,
                files_unreadable = f.skipped_unreadable,
                bad_lines,
                "engine statistics"
            );
            last_stats = Instant::now();
        }
    }
    info!("engine stopped");
    Ok(())
}

/// `--replay FILE`: run a recorded log through the engine from its start, print each alert as one JSON line on `out`,
/// and return the alerts. Uses `store` for trust and hashes (an empty in-memory store = no trust, no hash table).
pub fn replay<R: BufRead, W: std::io::Write>(
    engine: &mut Engine,
    store: &mut Store,
    input: R,
    out: &mut W,
) -> Result<Vec<Alert>, String> {
    let mut all = Vec::new();
    for line in input.split(b'\n') {
        let line = line.map_err(|e| e.to_string())?;
        if line.is_empty() {
            continue;
        }
        let Some(env) = parse(&line) else { continue };
        for a in engine.handle(store, &env) {
            writeln!(out, "{}", a.to_json()).map_err(|e| e.to_string())?;
            all.push(a);
        }
    }
    Ok(all)
}
