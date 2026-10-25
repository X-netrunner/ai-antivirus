//! M3 commands: alerts, on-demand scans, rule checks, the pacman trust baseline and integrity check, and the hash table.

use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use synapse_common::config::Config;
use synapse_common::event::{now_ns, Sha256};
use synapse_common::model::HashClass;
use synapse_common::store::Store;
use synapse_engined::files::{trust_entry, FileCheck, Finding, Outcome};
use synapse_rules::mtree;
use synapse_rules::rule::RuleSet;
use synapse_rules::scan::{self, Yara};

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

fn open_db(cfg_path: &Path, db: Option<&Path>) -> Result<Store, String> {
    let path = match db {
        Some(p) => p.to_path_buf(),
        None => Config::load(cfg_path).map_err(s)?.db_path(),
    };
    Store::open(&path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn alerts(cfg: &Path, db: Option<&Path>, n: usize, json: bool) -> Res {
    let store = open_db(cfg, db)?;
    let mut out = io::stdout().lock();
    for a in store.recent_alerts(n).map_err(s)? {
        let line = if json {
            serde_json::json!({
                "id": a.id, "ts_ns": a.ts_ns, "rule_id": a.rule_id, "severity": a.severity.as_str(),
                "confidence": a.confidence, "title": a.title,
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

/// Returns whether anything was found (the exit code says so).
pub fn scan(
    cfg: &Path,
    db: Option<&Path>,
    rules_dir: Option<&Path>,
    paths: &[PathBuf],
    quiet: bool,
) -> Result<bool, String> {
    let c = config_or_default(cfg)?;
    let dir = rules_dir.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    let yara = Yara::load_dir(
        &dir.join("yara"),
        Duration::from_millis(u64::from(c.engine.yara_timeout_ms)),
    )
    .map_err(s)?;
    // the configured database gives trust and hashes; without access to it the scan still runs (YARA only)
    let mut store = match db {
        Some(p) => Store::open(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => match Store::open(&c.db_path()) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("note: no trust cache or hash table ({e}); scanning with YARA only");
                Store::open_in_memory().map_err(s)?
            }
        },
    };
    // on demand: no rate limit, and up to 1 GiB per file
    let mut fc = FileCheck::new(Some(yara), 1 << 30, u32::MAX);
    let mut files = Vec::new();
    for p in paths {
        walk(p, &mut files);
    }
    let pacman = mtree::pacman_active();
    let (mut found, mut clean, mut trusted, mut skipped) = (0u64, 0u64, 0u64, 0u64);
    for f in &files {
        let shown = sanitize(&f.to_string_lossy());
        match fc.check(&mut store, f, false, pacman, now_ns()) {
            Outcome::Findings(list) => {
                found += 1;
                for x in list {
                    match x {
                        Finding::Modified { package, .. } => {
                            println!("MODIFIED  {shown}  (differs from package {package})")
                        }
                        Finding::KnownBad { label, .. } => {
                            println!("BAD HASH  {shown}  {}", label.unwrap_or_default())
                        }
                        Finding::Yara { hits, .. } => {
                            let names: Vec<String> = hits
                                .iter()
                                .map(|h| format!("{}.{}", h.namespace, h.rule))
                                .collect();
                            println!("YARA      {shown}  {}", names.join(", "));
                        }
                    }
                }
            }
            Outcome::Trusted { package } => {
                trusted += 1;
                if !quiet {
                    println!("trusted   {shown}  ({package})");
                }
            }
            Outcome::KnownGood | Outcome::Clean => {
                clean += 1;
                if !quiet {
                    println!("clean     {shown}");
                }
            }
            Outcome::Skipped(why) => {
                skipped += 1;
                if !quiet {
                    println!("skipped   {shown}  ({why})");
                }
            }
        }
    }
    eprintln!("{} files: {found} with findings, {trusted} trusted (pacman), {clean} clean, {skipped} skipped", files.len());
    Ok(found > 0)
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
        return Err("the trust cache is empty: run `synapsectl trust-baseline` first".into());
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
        .put_hash(&sha, class, label, "synapsectl", now_ns())
        .map_err(s)?;
    println!("{sha} recorded as {}", class.as_str());
    Ok(())
}
