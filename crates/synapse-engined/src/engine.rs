//! The detection pipeline for one event: update the process table, run the file layers (L0 to L2) where a file is
//! involved, then the behavior rules (L3). Produces alerts; never acts (synapse-responderd does, M4).

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use synapse_common::event::{Envelope, Event, ProcKey};
use synapse_common::model::Severity;
use synapse_common::store::Store;
use synapse_rules::matcher::Facts;
use synapse_rules::rule::{Action, EventKind, Rule, Scope};
use synapse_rules::window::Windows;

use crate::files::{FileCheck, Finding, Outcome};
use crate::procs::{Proc, ProcTable};

/// The same rule for the same process and path alerts at most once in this time.
const DEDUPE_NS: u64 = 300 * 1_000_000_000;
const MAX_DEDUPE: usize = 20_000;

/// Folders where written files are checked even when they are not executable.
const WRITE_SCAN_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];
const WRITE_SCAN_HOME: &[&str] = &["Downloads/"];

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub ts_ns: u64,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    /// What the rule asks the responder to do (capped at `notify` for `engine.allow_exe`).
    pub action: Action,
    /// L0 trust, L1 hash, L2 yara, L3 behavior
    pub layer: &'static str,
    pub proc_key: Option<ProcKey>,
    pub detail: Value,
}

impl Alert {
    pub fn to_json(&self) -> Value {
        json!({
            "ts_ns": self.ts_ns,
            "rule_id": self.rule_id,
            "severity": self.severity.as_str(),
            "confidence": self.confidence,
            "title": self.title,
            "action": self.action.as_str(),
            "layer": self.layer,
            "proc": self.proc_key.map(|k| json!({"pid": k.pid, "start_ns": k.start_ns})),
            "detail": self.detail,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EngineStats {
    pub events: u64,
    pub alerts: u64,
    pub deduped: u64,
}

pub struct Engine {
    rules: Vec<Rule>,
    windows: Vec<Option<Windows<ProcKey>>>,
    wants_setuid: bool,
    pub procs: ProcTable,
    pub files: FileCheck,
    scan_on_write: bool,
    pacman_active: Box<dyn Fn() -> bool + Send>,
    /// `engine.allow_exe`: alerts about these programs never ask for more than a notification.
    allow_exe: Vec<PathBuf>,
    dedupe: HashMap<String, u64>,
    pub stats: EngineStats,
}

fn lossy(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn finding_sha(f: &Finding) -> String {
    match f {
        Finding::Modified { actual, .. } => actual.to_string(),
        Finding::KnownBad { sha256, .. } | Finding::Yara { sha256, .. } => sha256.to_string(),
    }
}

fn argv_json(argv: &[OsString]) -> Value {
    Value::Array(
        argv.iter()
            .take(64)
            .map(|a| Value::String(a.to_string_lossy().chars().take(512).collect()))
            .collect(),
    )
}

fn severity_of(s: Option<&str>) -> Severity {
    s.and_then(|s| s.parse().ok()).unwrap_or(Severity::Medium)
}

impl Engine {
    pub fn new(rules: Vec<Rule>, files: FileCheck, scan_on_write: bool) -> Engine {
        let windows = rules
            .iter()
            .map(|r| match (&r.threshold, r.window_secs) {
                (Some(t), Some(w)) => Some(Windows::new(w, t.clone())),
                _ => None,
            })
            .collect();
        let wants_setuid = rules.iter().any(|r| r.matcher.wants_setuid());
        Engine {
            rules,
            windows,
            wants_setuid,
            procs: ProcTable::default(),
            files,
            scan_on_write,
            pacman_active: Box::new(synapse_rules::mtree::pacman_active),
            allow_exe: Vec::new(),
            dedupe: HashMap::new(),
            stats: EngineStats::default(),
        }
    }

    /// Swap in a new rule set (rules edited or approved while running). Window counters of rules that stay are lost;
    /// the process table is kept.
    pub fn replace_rules(&mut self, rules: Vec<Rule>) {
        self.windows = rules
            .iter()
            .map(|r| match (&r.threshold, r.window_secs) {
                (Some(t), Some(w)) => Some(Windows::new(w, t.clone())),
                _ => None,
            })
            .collect();
        self.wants_setuid = rules.iter().any(|r| r.matcher.wants_setuid());
        self.rules = rules;
    }

    /// Replace how "a pacman transaction runs" is decided (tests, replay).
    pub fn set_pacman_probe(&mut self, f: impl Fn() -> bool + Send + 'static) {
        self.pacman_active = Box::new(f);
    }

    /// Programs whose alerts are capped at `notify` (spec 8: the allowlist is enforced in the engine and, again, in
    /// the responder).
    pub fn set_allow_exe(&mut self, exes: Vec<PathBuf>) {
        self.allow_exe = exes;
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Feed only the process table (warm-up from the existing log at start: no rules, no scans).
    pub fn learn(&mut self, env: &Envelope) {
        match &env.event {
            Event::Exec {
                proc,
                parent,
                uid,
                exe,
                argv,
                stdio,
                lineage,
                ..
            } => {
                let p = Proc {
                    exe: exe.clone(),
                    argv: argv.clone(),
                    uid: *uid,
                    parent: *parent,
                    stdio: stdio.clone(),
                    lineage: lineage.clone(),
                    exited_ns: None,
                };
                self.procs.on_exec(*proc, p, env.ts_ns);
            }
            Event::Exit { proc, .. } => self.procs.on_exit(*proc, env.ts_ns),
            _ => {}
        }
    }

    pub fn handle(&mut self, store: &mut Store, env: &Envelope) -> Vec<Alert> {
        self.stats.events += 1;
        let ts = env.ts_ns;
        let pacman = (self.pacman_active)();
        let mut out = Vec::new();
        match &env.event {
            Event::Exec {
                proc,
                parent,
                uid,
                exe,
                argv,
                stdio,
                lineage,
                ..
            } => {
                let p = Proc {
                    exe: exe.clone(),
                    argv: argv.clone(),
                    uid: *uid,
                    parent: *parent,
                    stdio: stdio.clone(),
                    lineage: lineage.clone(),
                    exited_ns: None,
                };
                let waiting_reader = self.procs.on_exec(*proc, p, ts);
                // L0 to L2 on the program that runs
                let outcome = self.files.check(store, exe, true, pacman, ts);
                self.file_alerts(&mut out, &outcome, exe, *proc, ts, "exec");
                // L3
                self.eval_exec(&mut out, *proc, ts, pacman, false);
                if let Some(reader) = waiting_reader {
                    self.eval_exec(&mut out, reader, ts, pacman, true);
                }
            }
            Event::Exit { proc, .. } => self.procs.on_exit(*proc, ts),
            Event::Connect { proc, dst, .. } => {
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::Connect, *proc, pacman);
                    f.port = Some(dst.port());
                    (self.matched(&f), f.exe.map(lossy))
                };
                let detail = json!({"dst": dst.to_string(), "exe": exe});
                self.apply(&mut out, matched, *proc, ts, None, None, &detail);
            }
            Event::Listen { proc, addr } => {
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::Listen, *proc, pacman);
                    f.port = Some(addr.port());
                    (self.matched(&f), f.exe.map(lossy))
                };
                let detail = json!({"addr": addr.to_string(), "exe": exe});
                self.apply(&mut out, matched, *proc, ts, None, None, &detail);
            }
            Event::FileWrite {
                proc,
                path,
                size,
                head_entropy,
                ..
            } => {
                let setuid = self.wants_setuid.then(|| setuid_root(path));
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::FileWrite, *proc, pacman);
                    f.path = Some(path);
                    f.setuid_root = setuid;
                    (self.matched(&f), f.exe.map(lossy))
                };
                let detail = json!({"path": lossy(path), "size": size, "head_entropy": head_entropy, "exe": exe});
                self.apply(
                    &mut out,
                    matched,
                    *proc,
                    ts,
                    Some(path),
                    *head_entropy,
                    &detail,
                );
                if self.should_scan_write(path) {
                    let outcome = self.files.check(store, path, true, pacman, ts);
                    self.file_alerts(&mut out, &outcome, path, *proc, ts, "write");
                }
            }
            Event::FileCreate { proc, path } | Event::FileUnlink { proc, path } => {
                let kind = if matches!(env.event, Event::FileCreate { .. }) {
                    EventKind::FileCreate
                } else {
                    EventKind::FileUnlink
                };
                let (matched, exe) = {
                    let mut f = self.facts(kind, *proc, pacman);
                    f.path = Some(path);
                    (self.matched(&f), f.exe.map(lossy))
                };
                let detail = json!({"path": lossy(path), "exe": exe});
                self.apply(&mut out, matched, *proc, ts, Some(path), None, &detail);
            }
            Event::FileRename { proc, from, to } => {
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::FileRename, *proc, pacman);
                    f.path = Some(to);
                    (self.matched(&f), f.exe.map(lossy))
                };
                let detail = json!({"from": lossy(from), "to": lossy(to), "exe": exe});
                self.apply(&mut out, matched, *proc, ts, Some(to), None, &detail);
            }
            Event::Tamper { what } => out.push(crate::selfguard::from_tamper(ts, what)),
            Event::ModuleLoad { .. } | Event::Ptrace { .. } | Event::SensorHealth { .. } => {}
        }
        self.cap_allowlisted(&mut out);
        self.stats.alerts += out.len() as u64;
        out
    }

    fn cap_allowlisted(&self, out: &mut [Alert]) {
        for a in out.iter_mut().filter(|a| a.action > Action::Notify) {
            let Some(exe) = a.proc_key.and_then(|k| self.procs.exe(k)) else {
                continue;
            };
            if self.allow_exe.iter().any(|p| p == exe) {
                if let Some(obj) = a.detail.as_object_mut() {
                    obj.insert("allowlisted".into(), lossy(exe).into());
                    obj.insert("rule_action".into(), a.action.as_str().into());
                }
                a.action = Action::Notify;
            }
        }
    }

    /// Facts every event has: the acting process and its parent.
    fn facts(&self, kind: EventKind, key: ProcKey, pacman: bool) -> Facts<'_> {
        let mut f = Facts::new(kind);
        if let Some(p) = self.procs.get(key) {
            f.exe = Some(p.exe.as_path());
            f.parent_exe = self.procs.exe(p.parent);
        }
        f.ancestors = self.procs.ancestors(key);
        f.pacman_active = pacman;
        f
    }

    /// Indices of the rules whose `match` holds for `f`.
    fn matched(&self, f: &Facts<'_>) -> Vec<usize> {
        (0..self.rules.len())
            .filter(|&i| self.rules[i].matches(f))
            .collect()
    }

    /// Exec rules for `key`. `only_pipe_rules`: the second look once the writer of the process's stdin pipe is known.
    fn eval_exec(
        &mut self,
        out: &mut Vec<Alert>,
        key: ProcKey,
        ts: u64,
        pacman: bool,
        only_pipe_rules: bool,
    ) {
        let (matched, detail) = {
            let Some(p) = self.procs.get(key) else { return };
            let mut f = Facts::new(EventKind::Exec);
            f.exe = Some(p.exe.as_path());
            f.parent_exe = self.procs.exe(p.parent);
            f.argv = &p.argv;
            f.stdin = p
                .stdio
                .first()
                .map(OsString::as_os_str)
                .filter(|s| !s.is_empty());
            f.stdout = p
                .stdio
                .get(1)
                .map(OsString::as_os_str)
                .filter(|s| !s.is_empty());
            f.stdin_writer_exe = self.procs.stdin_writer_exe(key);
            f.ancestors = self.procs.ancestors(key);
            f.pacman_active = pacman;
            let matched: Vec<usize> = self
                .matched(&f)
                .into_iter()
                .filter(|&i| {
                    !only_pipe_rules || !self.rules[i].matcher.stdin_from_exe_in.is_empty()
                })
                .collect();
            let detail = json!({
                "exe": lossy(&p.exe),
                "argv": argv_json(&p.argv),
                "uid": p.uid,
                "parent": {"pid": p.parent.pid, "exe": f.parent_exe.map(lossy)},
                "stdin": f.stdin.map(|s| s.to_string_lossy().into_owned()),
                "stdin_from": f.stdin_writer_exe.map(lossy),
            });
            (matched, detail)
        };
        self.apply(out, matched, key, ts, None, None, &detail);
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        out: &mut Vec<Alert>,
        matched: Vec<usize>,
        key: ProcKey,
        ts: u64,
        path: Option<&Path>,
        entropy: Option<u16>,
        detail: &Value,
    ) {
        for i in matched {
            if self.rules[i].threshold.is_some() {
                self.count(out, i, key, ts, path, entropy, detail);
            } else {
                self.push_rule_alert(out, i, key, ts, path, detail.clone());
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn count(
        &mut self,
        out: &mut Vec<Alert>,
        i: usize,
        key: ProcKey,
        ts: u64,
        path: Option<&Path>,
        entropy: Option<u16>,
        detail: &Value,
    ) {
        let group = match self.rules[i].scope {
            Scope::ProcessTree => self.procs.tree_root(key),
            Scope::Process | Scope::Event => key,
        };
        let Some(w) = self.windows[i].as_mut() else {
            return;
        };
        if let Some(fired) = w.push(&group, ts, path, entropy) {
            let mut d = detail.clone();
            if let Some(obj) = d.as_object_mut() {
                obj.insert(
                    "window".into(),
                    json!({
                        "events": fired.events,
                        "distinct_files": fired.distinct_files,
                        "high_entropy_ratio": (fired.high_entropy_ratio * 1000.0).round() / 1000.0,
                        "sample": fired.sample.iter().map(|p| lossy(p)).collect::<Vec<_>>(),
                        "group": {"pid": group.pid, "exe": self.procs.exe(group).map(lossy)},
                    }),
                );
            }
            self.push_rule_alert(out, i, group, ts, None, d);
        }
    }

    fn push_rule_alert(
        &mut self,
        out: &mut Vec<Alert>,
        i: usize,
        key: ProcKey,
        ts: u64,
        path: Option<&Path>,
        detail: Value,
    ) {
        let dk = format!(
            "{}|{}:{}|{}",
            self.rules[i].id,
            key.pid,
            key.start_ns,
            path.map(lossy).unwrap_or_default()
        );
        if !self.first_time(dk, ts) {
            return;
        }
        let r = &self.rules[i];
        out.push(Alert {
            ts_ns: ts,
            rule_id: r.id.clone(),
            severity: r.severity,
            confidence: r.confidence,
            title: r.title.clone(),
            action: r.action,
            layer: "L3 behavior",
            proc_key: Some(key),
            detail,
        });
    }

    fn file_alerts(
        &mut self,
        out: &mut Vec<Alert>,
        outcome: &Outcome,
        path: &Path,
        key: ProcKey,
        ts: u64,
        trigger: &str,
    ) {
        let Outcome::Findings(findings) = outcome else {
            return;
        };
        let exe = self.procs.exe(key).map(lossy);
        for f in findings {
            let (rule_id, severity, confidence, title, action, layer, extra) = match f {
                Finding::Modified {
                    package,
                    expected,
                    actual,
                } => (
                    "SYN-I-0001".to_owned(),
                    Severity::High,
                    0.9,
                    format!("File of package {package} differs from what pacman installed"),
                    Action::Restore,
                    "L0 trust",
                    json!({"package": package, "expected_sha256": expected.to_string(), "sha256": actual.to_string()}),
                ),
                Finding::KnownBad { sha256, label } => (
                    "SYN-H-0001".to_owned(),
                    Severity::Critical,
                    1.0,
                    format!(
                        "Known-bad file{}",
                        label
                            .as_deref()
                            .map(|l| format!(" ({l})"))
                            .unwrap_or_default()
                    ),
                    Action::Quarantine,
                    "L1 hash",
                    json!({"sha256": sha256.to_string(), "label": label}),
                ),
                Finding::Yara { sha256, hits } => {
                    // one alert per file: the most severe rule names it, all hits are listed
                    let worst = hits
                        .iter()
                        .map(|h| severity_of(h.severity.as_deref()))
                        .max()
                        .unwrap_or(Severity::Medium);
                    let names: Vec<String> = hits
                        .iter()
                        .map(|h| format!("{}.{}", h.namespace, h.rule))
                        .collect();
                    (
                        format!("YARA:{}", names.first().cloned().unwrap_or_default()),
                        worst,
                        0.8,
                        format!(
                            "YARA match in {}",
                            if trigger == "exec" {
                                "a program that ran"
                            } else {
                                "a written file"
                            }
                        ),
                        Action::Quarantine,
                        "L2 yara",
                        json!({"sha256": sha256.to_string(), "rules": names}),
                    )
                }
            };
            // the file's hash is part of the key: a file tampered with again, differently, alerts again
            let dk = format!("{rule_id}|{}|{}", lossy(path), finding_sha(f));
            if !self.first_time(dk, ts) {
                continue;
            }
            out.push(Alert {
                ts_ns: ts,
                rule_id,
                severity,
                confidence,
                title,
                action,
                layer,
                proc_key: Some(key),
                detail: json!({"path": lossy(path), "trigger": trigger, "exe": exe, "finding": extra}),
            });
        }
    }

    /// true the first time `key` is seen within `DEDUPE_NS`.
    fn first_time(&mut self, key: String, ts: u64) -> bool {
        if self.dedupe.len() >= MAX_DEDUPE {
            self.dedupe.retain(|_, t| ts.saturating_sub(*t) < DEDUPE_NS);
            if self.dedupe.len() >= MAX_DEDUPE {
                self.dedupe.clear();
            }
        }
        match self.dedupe.get(&key) {
            Some(t) if ts.saturating_sub(*t) < DEDUPE_NS => {
                self.stats.deduped += 1;
                false
            }
            _ => {
                self.dedupe.insert(key, ts);
                true
            }
        }
    }

    fn should_scan_write(&self, path: &Path) -> bool {
        if !self.scan_on_write {
            return false;
        }
        let raw = path.to_string_lossy();
        if WRITE_SCAN_PREFIXES.iter().any(|p| raw.starts_with(p)) {
            return true;
        }
        if let Some(rest) = raw.strip_prefix("/home/") {
            if let Some((_, tail)) = rest.split_once('/') {
                if WRITE_SCAN_HOME.iter().any(|p| tail.starts_with(p)) {
                    return true;
                }
            }
        }
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
    }

    /// Housekeeping, every few seconds: forget old processes, pipe ends and empty windows.
    pub fn sweep(&mut self, now_ns: u64) {
        self.procs.sweep(now_ns);
        for w in self.windows.iter_mut().flatten() {
            w.sweep(now_ns);
        }
        self.dedupe
            .retain(|_, t| now_ns.saturating_sub(*t) < DEDUPE_NS);
    }
}

/// The file is a regular file, setuid, and owned by root (lstat: a symlink is not followed).
fn setuid_root(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_file() && m.mode() & 0o4000 != 0 && m.uid() == 0)
}
