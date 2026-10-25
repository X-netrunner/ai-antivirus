//! Synapse engine daemon (M3): follows the sensor's event log, keeps a process table, runs the file layers (pacman trust,
//! hash table, YARA-X) and the behavior rules, and stores alerts. It runs as the unprivileged `synapse` user and has no way
//! to act on the system: a rule's `action` is recorded on the alert, and the responder (M4) decides what of it may run.
//!
//! The engine reads the JSONL log instead of a socket from the sensor (spec 4 sketches IPC over Unix sockets). The log is
//! already the sensor's durable output, it decouples the two processes completely (either can restart alone) and it gives
//! replay for free; a socket can replace it once the responder needs low latency.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod ai;
pub mod engine;
pub mod files;
pub mod procs;
pub mod selfguard;

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use synapse_common::config::Config;
use synapse_common::event::{now_ns, Envelope};
use synapse_common::eventlog::{self, Follower};
use synapse_common::notify::Heartbeat;
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
const AI_EVERY: Duration = Duration::from_secs(2);

/// Names, sizes and times of the behavior rule files: changes when a rule is added, edited or removed.
fn rules_fingerprint(rules_dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64, std::time::SystemTime)>, depth: u32) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() && depth < 4 {
                walk(&p, out, depth + 1);
            } else if m.is_file() && p.extension().is_some_and(|x| x == "toml") {
                out.push((p, m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)));
            }
        }
    }
    let mut v = Vec::new();
    walk(&rules_dir.join("behavior"), &mut v, 0);
    v.sort();
    v
}

/// Load changed rules without a restart. A rule set that does not validate is refused and the running rules stay.
fn reload_rules_if_changed(
    cfg: &Config,
    engine: &mut Engine,
    seen: &mut Vec<(PathBuf, u64, std::time::SystemTime)>,
) -> Option<Alert> {
    let now = rules_fingerprint(&cfg.engine.rules_dir);
    if now == *seen {
        return None;
    }
    *seen = now;
    if let Err(e) = selfguard::verify_rules(cfg, &cfg.engine.rules_dir) {
        warn!(error = %e, "changed rules are not validly signed; the running rules stay");
        return Some(selfguard::bundle_invalid(now_ns(), &e));
    }
    match RuleSet::load_dir(&cfg.engine.rules_dir.join("behavior")) {
        Ok(set) => {
            info!(behavior_rules = set.rules.len(), "behavior rules reloaded");
            engine.replace_rules(set.rules);
        }
        Err(e) => warn!(error = %e, "changed rules are invalid; the running rules stay"),
    }
    None
}

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

fn store_alert(store: &Store, a: &Alert) -> Option<i64> {
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
    match store.insert_alert(&row) {
        Ok(id) => Some(id),
        Err(e) => {
            error!(error = %e, rule = %a.rule_id, "cannot store alert");
            None
        }
    }
}

fn parse(line: &[u8]) -> Option<Envelope> {
    serde_json::from_slice(line).ok()
}

/// The daemon: warm up from the current log, then follow it until `shutdown`.
pub fn run(cfg: &Config, shutdown: &AtomicBool) -> Result<(), String> {
    selfguard::verify_rules(cfg, &cfg.engine.rules_dir).map_err(|e| {
        format!("engine.require_signed_rules is on and the rules do not verify: {e}")
    })?;
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
    info!(log = %log.display(), mode = cfg.general.mode.as_str(), "engine running (alerts only: synapse-responderd acts on them)");

    let (mut last_sweep, mut last_stats, mut last_ai) =
        (Instant::now(), Instant::now(), Instant::now());
    let mut rules_seen = rules_fingerprint(&cfg.engine.rules_dir);
    let (mut last_ptrace, mut last_self_check) = (Instant::now(), Instant::now());
    let mut ptrace_reported = false;
    let mut sensor_watch = selfguard::SensorWatch::new();
    let mut heartbeat = Heartbeat::from_env();
    heartbeat.ready("following the event log");
    let mut bad_lines = 0u64;
    while !shutdown.load(Ordering::Relaxed) {
        heartbeat.tick();
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
        if !lines.is_empty() {
            sensor_watch.saw_line();
        }
        for l in &lines {
            let Some(env) = parse(l) else {
                bad_lines += 1;
                continue;
            };
            for a in engine.handle(&mut store, &env) {
                warn!(rule = %a.rule_id, severity = a.severity.as_str(), title = %a.title, pid = a.proc_key.map(|k| k.pid), action = a.action.as_str(), "ALERT");
                if let Some(id) = store_alert(&store, &a) {
                    if let Ok(Some(row)) = store.get_alert(id) {
                        ai::spool_alert(cfg, &row);
                    }
                }
            }
        }
        if last_sweep.elapsed() >= SWEEP_EVERY {
            engine.sweep(now_ns());
            last_sweep = Instant::now();
        }
        if last_ai.elapsed() >= AI_EVERY {
            last_ai = Instant::now();
            if cfg.ai.enabled {
                let n = ai::import_answers(cfg, &store);
                if n.notes + n.proposals + n.auto_rejected > 0 {
                    info!(
                        notes = n.notes,
                        proposals = n.proposals,
                        auto_rejected = n.auto_rejected,
                        "analyzer answers imported"
                    );
                }
            }
            if let Some(a) = reload_rules_if_changed(cfg, &mut engine, &mut rules_seen) {
                warn!(rule = %a.rule_id, "ALERT");
                store_alert(&store, &a);
            }
        }
        if last_ptrace.elapsed() >= selfguard::PTRACE_CHECK_EVERY {
            last_ptrace = Instant::now();
            if let Some(a) = selfguard::check_debugger(now_ns()) {
                if !ptrace_reported {
                    warn!(rule = %a.rule_id, "ALERT");
                    store_alert(&store, &a);
                }
                ptrace_reported = true;
            } else {
                ptrace_reported = false;
            }
            if let Some(a) = sensor_watch.check(now_ns()) {
                warn!(rule = %a.rule_id, "ALERT");
                store_alert(&store, &a);
            }
        }
        if last_self_check.elapsed() >= selfguard::SELF_CHECK_EVERY {
            last_self_check = Instant::now();
            let pacman = synapse_rules::mtree::pacman_active();
            for a in engine.self_check(&mut store, &cfg.engine.self_check_files, pacman, now_ns()) {
                warn!(rule = %a.rule_id, title = %a.title, "ALERT");
                store_alert(&store, &a);
            }
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
    heartbeat.stopping();
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
