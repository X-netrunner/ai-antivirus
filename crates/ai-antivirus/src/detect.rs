//! M3 commands: alerts, on-demand scans, rule checks, the pacman trust baseline and integrity check, and the hash table.

use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ai_antivirus_common::config::Config;
use ai_antivirus_common::event::{now_ns, Sha256};
use ai_antivirus_common::model::HashClass;
use ai_antivirus_common::store::Store;
use ai_antivirus_engined::files::{trust_entry, FileCheck, Finding, Outcome};
use ai_antivirus_rules::mtree;
use ai_antivirus_rules::rule::RuleSet;
use ai_antivirus_rules::scan::{self, Yara};

use crate::render::{format_ts, sanitize};

pub type Res = Result<(), String>;

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// The config if it loads; `scan` and `rules` also work without an installed one.
fn config_or_default(path: &Path) -> Result<Config, String> {
    if path.exists() {
        Config::load(path).map_err(s)
    } else {
        Ok(Config::default())
    }
}

pub fn open_db(cfg_path: &Path, db: Option<&Path>) -> Result<Store, String> {
    let path = match db {
        Some(p) => p.to_path_buf(),
        None => Config::load(cfg_path).map_err(s)?.db_path(),
    };
    Store::open(&path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn ack(cfg: &Path, db: Option<&Path>, ids: &[i64], all: bool) -> Res {
    if ids.is_empty() && !all {
        return Err("name alert ids, or use --all".into());
    }
    let store = open_db(cfg, db)?;
    let n = if all {
        store.ack_all_alerts().map_err(s)?
    } else {
        store.ack_alerts(ids).map_err(s)?
    };
    println!("acknowledged {n} alert{}", if n == 1 { "" } else { "s" });
    Ok(())
}

pub fn alerts(cfg: &Path, db: Option<&Path>, n: usize, json: bool, unacked: bool) -> Res {
    let store = open_db(cfg, db)?;
    let mut out = io::stdout().lock();
    let rows = if unacked {
        store.unacked_alerts(n)
    } else {
        store.recent_alerts(n)
    };
    for a in rows.map_err(s)? {
        let line = if json {
            serde_json::json!({
                "id": a.id, "ts_ns": a.ts_ns, "rule_id": a.rule_id, "severity": a.severity.as_str(),
                "confidence": a.confidence, "title": a.title, "acknowledged": a.acknowledged,
                "proc": a.proc_key.map(|k| serde_json::json!({"pid": k.pid, "start_ns": k.start_ns})),
                "detail": a.detail,
            })
            .to_string()
        } else {
            let what = a
                .detail
                .get("exe")
                .and_then(|v| v.as_str())
                .or_else(|| a.detail.get("path").and_then(|v| v.as_str()));
            format!(
                "{} #{:<5} {:<8} {:<26} {}{}{}",
                format_ts(a.ts_ns),
                a.id,
                a.severity.as_str(),
                sanitize(&a.rule_id),
                sanitize(&a.title),
                a.proc_key
                    .map(|k| format!("  pid={}", k.pid))
                    .unwrap_or_default(),
                what.map(|w| format!("  {}", sanitize(w)))
                    .unwrap_or_default(),
            )
        };
        writeln!(out, "{line}").map_err(s)?;
    }
    Ok(())
}

pub fn rules(cfg: &Path, dir: Option<&Path>) -> Res {
    let c = config_or_default(cfg)?;
    let dir = dir.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    let set = RuleSet::load_dir(&dir.join("behavior")).map_err(s)?;
    let yara = Yara::load_dir(&dir.join("yara"), Duration::from_secs(5)).map_err(s)?;
    println!("rules OK: {}", dir.display());
    for r in &set.rules {
        println!(
            "  {:<12} {:<9} {:<11} {}",
            r.id,
            r.severity.as_str(),
            r.action.as_str(),
            r.title
        );
    }
    println!(
        "{} behavior rules in {} files, {} YARA rules in {} files",
        set.rules.len(),
        set.files.len(),
        yara.rule_count(),
        yara.files().len()
    );
    Ok(())
}

/// Files under `p` (itself when it is a file); symlinks are not followed.
fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            if let Ok(rd) = fs::read_dir(p) {
                let mut kids: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
                kids.sort();
                for k in kids {
                    walk(&k, out);
                }
            }
        }
        Ok(m) if m.is_file() => out.push(p.to_path_buf()),
        _ => {}
    }
}

/// What `scan` should print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutput {
    /// Every file.
    All,
    /// Findings only.
    Quiet,
    /// One JSON object per finding, then a summary object (for the Halcyon Security center).
    Json,
}

/// Largest file an on-demand scan reads (each scan thread holds one file in memory for YARA).
const SCAN_MAX_BYTES: u64 = 512 << 20;

/// Scan threads: `jobs`, or one per core up to 8 (the work is mostly hashing and reading).
fn scan_threads(jobs: Option<usize>, files: usize) -> usize {
    let auto = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    jobs.unwrap_or(auto).clamp(1, 64).min(files.max(1))
}

/// Returns whether anything was found (the exit code says so).
pub fn scan(
    cfg: &Path,
    db: Option<&Path>,
    rules_dir: Option<&Path>,
    paths: &[PathBuf],
    output: ScanOutput,
    jobs: Option<usize>,
) -> Result<bool, String> {
    let c = config_or_default(cfg)?;
    let dir = rules_dir.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    let yara = Yara::load_dir(
        &dir.join("yara"),
        Duration::from_millis(u64::from(c.engine.yara_timeout_ms)),
    )
    .map_err(s)?;
    // the configured database gives trust and hashes; without access to it the scan still runs (YARA only)
    let db_path = db.map_or_else(|| c.db_path(), Path::to_path_buf);
    let shared_db = match Store::open(&db_path) {
        Ok(_) => true,
        Err(e) if db.is_some() => return Err(format!("{}: {e}", db_path.display())),
        Err(e) => {
            if output != ScanOutput::Json {
                eprintln!("note: no trust cache or hash table ({e}); scanning with YARA only");
            }
            false
        }
    };
    let mut files = Vec::new();
    for p in paths {
        walk(p, &mut files);
    }
    let pacman = mtree::pacman_active();
    let started = std::time::Instant::now();

    // Workers take the next file by index; results come back tagged with it and are printed in file order.
    let threads = scan_threads(jobs, files.len());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Outcome)>();
    let (mut found, mut clean, mut trusted, mut skipped) = (0u64, 0u64, 0u64, 0u64);
    std::thread::scope(|sc| -> Result<(), String> {
        for _ in 0..threads {
            let (tx, yara, files, next, db_path) =
                (tx.clone(), yara.clone(), &files, &next, &db_path);
            let mut store = if shared_db {
                Store::open(db_path)
            } else {
                Store::open_in_memory()
            }
            .map_err(s)?;
            sc.spawn(move || {
                let mut fc = FileCheck::new(Some(yara), SCAN_MAX_BYTES, u32::MAX);
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(f) = files.get(i) else { break };
                    if tx
                        .send((i, fc.check(&mut store, f, false, pacman, now_ns())))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut pending = std::collections::BTreeMap::new();
        let mut shown_upto = 0usize;
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        for (i, o) in rx {
            pending.insert(i, o);
            while let Some(o) = pending.remove(&shown_upto) {
                let f = &files[shown_upto];
                shown_upto += 1;
                match &o {
                    Outcome::Findings(_) => found += 1,
                    Outcome::Trusted { .. } => trusted += 1,
                    Outcome::KnownGood | Outcome::Clean => clean += 1,
                    Outcome::Skipped(_) => skipped += 1,
                }
                let line = match output {
                    ScanOutput::Json => scan_json(f, &o),
                    _ => scan_line(f, &o, output == ScanOutput::Quiet),
                };
                if let Some(line) = line {
                    let _ = writeln!(out, "{line}");
                }
            }
        }
        let _ = out.flush();
        Ok(())
    })?;
    let secs = started.elapsed().as_secs_f64();
    if output == ScanOutput::Json {
        println!(
            "{}",
            serde_json::json!({"summary": true, "files": files.len(), "found": found, "trusted": trusted,
                "clean": clean, "skipped": skipped, "seconds": (secs * 100.0).round() / 100.0, "threads": threads})
        );
    } else {
        eprintln!(
            "{} files in {secs:.1} s: {found} with findings, {trusted} trusted (pacman), {clean} clean, {skipped} skipped",
            files.len()
        );
    }
    Ok(found > 0)
}

/// The readable line for one scanned file (None: nothing to show).
fn scan_line(f: &Path, o: &Outcome, quiet: bool) -> Option<String> {
    let shown = sanitize(&f.to_string_lossy());
    match o {
        Outcome::Findings(list) => Some(
            list.iter()
                .map(|x| match x {
                    Finding::Modified { package, .. } => {
                        format!("MODIFIED  {shown}  (differs from package {package})")
                    }
                    Finding::KnownBad { label, .. } => {
                        format!(
                            "BAD HASH  {shown}  {}",
                            label.as_deref().unwrap_or_default()
                        )
                    }
                    Finding::Yara { hits, .. } => {
                        let names: Vec<String> = hits
                            .iter()
                            .map(|h| format!("{}.{}", h.namespace, h.rule))
                            .collect();
                        format!("YARA      {shown}  {}", names.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ if quiet => None,
        Outcome::Trusted { package } => Some(format!("trusted   {shown}  ({package})")),
        Outcome::KnownGood | Outcome::Clean => Some(format!("clean     {shown}")),
        Outcome::Skipped(why) => Some(format!("skipped   {shown}  ({why})")),
    }
}

/// One JSON object per file with findings (None for the rest).
fn scan_json(f: &Path, o: &Outcome) -> Option<String> {
    let Outcome::Findings(list) = o else {
        return None;
    };
    let findings: Vec<serde_json::Value> = list
        .iter()
        .map(|x| match x {
            Finding::Modified { package, .. } => {
                serde_json::json!({"kind": "modified", "detail": package})
            }
            Finding::KnownBad { label, .. } => {
                serde_json::json!({"kind": "bad_hash", "detail": label.clone().unwrap_or_default()})
            }
            Finding::Yara { hits, .. } => serde_json::json!({"kind": "yara", "detail": hits
                .iter()
                .map(|h| format!("{}.{}", h.namespace, h.rule))
                .collect::<Vec<_>>()
                .join(", ")}),
        })
        .collect();
    Some(serde_json::json!({"path": f.to_string_lossy(), "findings": findings}).to_string())
}

pub fn trust_baseline(cfg: &Path, db: Option<&Path>, local: Option<&Path>) -> Res {
    let mut store = open_db(cfg, db)?;
    let local = local.unwrap_or(Path::new(mtree::PACMAN_LOCAL));
    if mtree::pacman_active() {
        return Err("a pacman transaction is running (db.lck exists); run this afterwards".into());
    }
    let pkgs = mtree::local_packages(local).map_err(s)?;
    let (mut files, mut failed) = (0usize, 0usize);
    for p in &pkgs {
        match mtree::package_files(p) {
            Ok(list) => {
                let entries: Vec<_> = list.iter().map(|f| trust_entry(&p.name, f, 0)).collect();
                files += store.trust_replace_package(&p.name, &entries).map_err(s)?;
            }
            Err(e) => {
                failed += 1;
                eprintln!("warning: {e}");
            }
        }
    }
    println!(
        "trust cache: {} packages, {files} files{}",
        pkgs.len() - failed,
        if failed > 0 {
            format!(" ({failed} packages unreadable)")
        } else {
            String::new()
        }
    );
    Ok(())
}

/// Hash every file the trust cache lists and compare with pacman's record. Returns whether anything differs.
pub fn integrity(cfg: &Path, db: Option<&Path>, package: Option<&str>) -> Result<bool, String> {
    let store = open_db(cfg, db)?;
    let pkgs: Vec<String> = match package {
        Some(p) => vec![p.to_owned()],
        None => store
            .trust_packages()
            .map_err(s)?
            .into_iter()
            .map(|(p, _)| p)
            .collect(),
    };
    if pkgs.is_empty() {
        return Err("the trust cache is empty: run `ai-antivirus trust-baseline` first".into());
    }
    let (mut ok, mut bad, mut missing, mut unreadable) = (0u64, 0u64, 0u64, 0u64);
    for p in &pkgs {
        for e in store.trust_entries(p).map_err(s)? {
            let path = Path::new(std::ffi::OsStr::from_bytes(&e.path));
            let shown = sanitize(&path.to_string_lossy());
            match scan::open_regular(path, u64::MAX) {
                Ok(Some((f, _))) => match scan::sha256_file(&f) {
                    Ok(h) if h == e.sha256 => ok += 1,
                    Ok(h) => {
                        bad += 1;
                        println!("DIFFERS   {shown}  ({p}: expected {}, found {h})", e.sha256);
                    }
                    Err(_) => unreadable += 1,
                },
                Ok(None) => {
                    bad += 1;
                    println!("CHANGED   {shown}  ({p}: no longer a regular file)");
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    missing += 1;
                    println!("MISSING   {shown}  ({p})");
                }
                Err(_) => unreadable += 1,
            }
        }
    }
    eprintln!("{} packages: {ok} files match, {bad} differ, {missing} missing, {unreadable} unreadable (run as root to read them all)", pkgs.len());
    Ok(bad > 0)
}

pub fn hash_add(cfg: &Path, db: Option<&Path>, what: &str, good: bool, label: Option<&str>) -> Res {
    let store = open_db(cfg, db)?;
    let sha: Sha256 = match what.parse() {
        Ok(h) => h,
        Err(_) => {
            let p = Path::new(what);
            let (f, _) = scan::open_regular(p, u64::MAX)
                .map_err(|e| format!("{what}: {e}"))?
                .ok_or_else(|| format!("{what}: not a regular file"))?;
            scan::sha256_file(&f).map_err(s)?
        }
    };
    let class = if good {
        HashClass::Good
    } else {
        HashClass::Bad
    };
    store
        .put_hash(&sha, class, label, "ai-antivirus", now_ns())
        .map_err(s)?;
    println!("{sha} recorded as {}", class.as_str());
    Ok(())
}
