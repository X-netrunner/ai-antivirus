//! The detection pipeline for one event: update the process table, run the file layers (L0 to L2) where a file is
//! involved, then the behavior rules (L3). Produces alerts; never acts (ai-antivirus-responderd does, M4).

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ai_antivirus_common::event::{Envelope, Event, ProcKey};
use ai_antivirus_common::exceptions::{Matcher, NEVER_EXCEPTED_RULES};
use ai_antivirus_common::model::Severity;
use ai_antivirus_common::store::Store;
use ai_antivirus_rules::matcher::Facts;
use ai_antivirus_rules::rule::{Action, EventKind, Rule, Scope};
use ai_antivirus_rules::window::Windows;
use serde_json::{json, Value};

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
    /// Alerts dropped because of an exception (`ai-antivirus exceptions`).
    pub excepted: u64,
}

/// A running process read from /proc (one that started before the engine, so the table does not know it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProc {
    pub ppid: u32,
    /// The executable, or argv[0] when the link cannot be read (another user's process).
    pub exe: PathBuf,
    pub argv: Vec<OsString>,
}

/// `/proc/<pid>`: parent, executable (or argv[0]) and arguments.
pub fn live_proc(pid: u32) -> Option<LiveProc> {
    use std::os::unix::ffi::OsStringExt;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let ppid: u32 = rest.split_whitespace().nth(1)?.parse().ok()?;
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv: Vec<OsString> = raw
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .take(8)
        .map(|a| OsString::from_vec(a.to_vec()))
        .collect();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .or_else(|| argv.first().map(PathBuf::from))?;
    Some(LiveProc { ppid, exe, argv })
}

/// A rule that matched and now waits to see whether the process keeps the CPU busy (`min_cpu_percent`).
struct CpuCheck {
    rule: usize,
    key: ProcKey,
    first_cpu_ns: u64,
    first_ns: u64,
    due_ns: u64,
    detail: Value,
}

const PACMAN_TTL: std::time::Duration = std::time::Duration::from_millis(100);

/// Most CPU checks waiting at once; more are dropped (a flood of connects must not grow memory).
const MAX_CPU_CHECKS: usize = 256;

/// CPU time a process has used so far, in ns, from /proc/<pid>/stat (utime + stime, in USER_HZ = 100 ticks per second).
pub fn proc_cpu_ns(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // the command name may contain spaces and parentheses: fields start after the last ')'
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    Some((utime + stime) * 10_000_000)
}

fn ancestor_kinds(rules: &[Rule]) -> Vec<EventKind> {
    let mut v: Vec<EventKind> = Vec::new();
    for r in rules.iter().filter(|r| !r.exclude_ancestor_exe.is_empty()) {
        if !v.contains(&r.matcher.event) {
            v.push(r.matcher.event);
        }
    }
    v
}

pub struct Engine {
    rules: Vec<Rule>,
    cpu_checks: Vec<CpuCheck>,
    cpu_probe: Box<dyn Fn(ProcKey) -> Option<u64> + Send>,
    /// Is this socket inode a Unix-domain socket? (None: could not tell.) Asked only for an exec whose stdin is a socket.
    unix_socket_probe: Box<dyn Fn(u64) -> Option<bool> + Send>,
    windows: Vec<Option<Windows<ProcKey>>>,
    wants_setuid: bool,
    /// Event kinds with a rule that looks at the ancestors (`exclude_ancestor_exe`): only those walk the process tree.
    ancestor_kinds: Vec<EventKind>,
    pub procs: ProcTable,
    pub files: FileCheck,
    scan_on_write: bool,
    pacman_active: Box<dyn Fn() -> bool + Send>,
    /// The last answer of `pacman_active` and when it was asked: the probe is a stat(2), once per event was the
    /// biggest cost of a quiet event.
    pacman_cached: Option<(std::time::Instant, bool)>,
    /// `engine.allow_exe`: alerts about these programs never ask for more than a notification.
    allow_exe: Vec<PathBuf>,
    /// Programs and folders left alone (`engine.exceptions_file`).
    exceptions: Matcher,
    live_probe: Box<dyn Fn(u32) -> Option<LiveProc> + Send>,
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
        let ancestor_kinds = ancestor_kinds(&rules);
        Engine {
            rules,
            cpu_checks: Vec::new(),
            cpu_probe: Box::new(|k: ProcKey| proc_cpu_ns(k.pid)),
            unix_socket_probe: Box::new(is_unix_socket),
            windows,
            wants_setuid,
            ancestor_kinds,
            procs: ProcTable::default(),
            files,
            scan_on_write,
            pacman_active: Box::new(ai_antivirus_rules::mtree::pacman_active),
            pacman_cached: None,
            allow_exe: Vec::new(),
            exceptions: Matcher::default(),
            live_probe: Box::new(live_proc),
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
        self.ancestor_kinds = ancestor_kinds(&rules);
        self.cpu_checks.clear(); // they point at rule indices of the old set
        self.rules = rules;
    }

    /// Replace how a process's CPU time is read (tests, replay).
    pub fn set_cpu_probe(&mut self, f: impl Fn(ProcKey) -> Option<u64> + Send + 'static) {
        self.cpu_probe = Box::new(f);
    }

    /// Replace how a socket inode is classified (tests, replay).
    pub fn set_unix_socket_probe(&mut self, f: impl Fn(u64) -> Option<bool> + Send + 'static) {
        self.unix_socket_probe = Box::new(f);
    }

    /// CPU checks still waiting.
    pub fn cpu_checks_waiting(&self) -> usize {
        self.cpu_checks.len()
    }

    /// Finish the CPU checks whose window has passed: an alert for each process that kept the CPU busy enough.
    /// Called every few seconds by the main loop with the current time.
    pub fn tick(&mut self, now: u64) -> Vec<Alert> {
        let mut out = Vec::new();
        let (due, wait): (Vec<CpuCheck>, Vec<CpuCheck>) = std::mem::take(&mut self.cpu_checks)
            .into_iter()
            .partition(|c| c.due_ns <= now);
        self.cpu_checks = wait;
        for c in due {
            let Some((min, _)) = self.rules.get(c.rule).and_then(|r| r.matcher.cpu_check()) else {
                continue;
            };
            // gone, or another process reusing the pid (its CPU time went down): no verdict
            let Some(cpu) = (self.cpu_probe)(c.key).filter(|v| *v >= c.first_cpu_ns) else {
                continue;
            };
            let span = now.saturating_sub(c.first_ns).max(1);
            let percent = (cpu - c.first_cpu_ns).saturating_mul(100) / span;
            if percent >= u64::from(min) {
                let mut detail = c.detail;
                if let Some(o) = detail.as_object_mut() {
                    o.insert("cpu_percent".into(), percent.into());
                    o.insert("cpu_window_secs".into(), (span / 1_000_000_000).into());
                }
                self.push_rule_alert(&mut out, c.rule, c.key, now, None, detail);
            }
        }
        self.apply_exceptions(&mut out);
        self.cap_allowlisted(&mut out);
        self.stats.alerts += out.len() as u64;
        out
    }

    /// Whether a pacman transaction runs, asked at most every PACMAN_TTL. pacman takes its lock before it writes any
    /// file, so a 100 ms old answer never hides the start of a transaction from the file checks.
    fn pacman_now(&mut self) -> bool {
        let now = std::time::Instant::now();
        if let Some((at, v)) = self.pacman_cached {
            if now.duration_since(at) < PACMAN_TTL {
                return v;
            }
        }
        let v = (self.pacman_active)();
        self.pacman_cached = Some((now, v));
        v
    }

    /// Replace how "a pacman transaction runs" is decided (tests, replay).
    pub fn set_pacman_probe(&mut self, f: impl Fn() -> bool + Send + 'static) {
        self.pacman_active = Box::new(f);
        self.pacman_cached = None;
    }

    /// Programs whose alerts are capped at `notify` (spec 8: the allowlist is enforced in the engine and, again, in
    /// the responder).
    pub fn set_allow_exe(&mut self, exes: Vec<PathBuf>) {
        self.allow_exe = exes;
    }

    /// Programs and folders whose alerts are dropped (behavior) or kept as notifications (malware in a file).
    pub fn set_exceptions(&mut self, m: Matcher) {
        self.exceptions = m;
    }

    pub fn exceptions(&self) -> &Matcher {
        &self.exceptions
    }

    /// Replace how a process that the table does not know is read (tests).
    pub fn set_live_probe(&mut self, f: impl Fn(u32) -> Option<LiveProc> + Send + 'static) {
        self.live_probe = Box::new(f);
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
        let pacman = self.pacman_now();
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
                // L0 to L2 on the program that runs (not in an excepted folder: its alerts would be dropped anyway)
                if self.exceptions.folder(exe).is_none() {
                    let outcome = self.files.check(store, exe, true, pacman, ts);
                    self.file_alerts(&mut out, &outcome, exe, *proc, ts, "exec");
                }
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
                    {
                        // nothing below is needed when no rule matched (most events): skip the string work
                        let m = self.matched(&f);
                        let exe = if m.is_empty() { None } else { f.exe.map(lossy) };
                        (m, exe)
                    }
                };
                let detail = if matched.is_empty() {
                    Value::Null
                } else {
                    json!({"dst": dst.to_string(), "exe": exe})
                };
                self.apply(&mut out, matched, *proc, ts, None, None, &detail);
            }
            Event::Listen { proc, addr } => {
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::Listen, *proc, pacman);
                    f.port = Some(addr.port());
                    {
                        // nothing below is needed when no rule matched (most events): skip the string work
                        let m = self.matched(&f);
                        let exe = if m.is_empty() { None } else { f.exe.map(lossy) };
                        (m, exe)
                    }
                };
                let detail = if matched.is_empty() {
                    Value::Null
                } else {
                    json!({"addr": addr.to_string(), "exe": exe})
                };
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
                    {
                        // nothing below is needed when no rule matched (most events): skip the string work
                        let m = self.matched(&f);
                        let exe = if m.is_empty() { None } else { f.exe.map(lossy) };
                        (m, exe)
                    }
                };
                let detail = if matched.is_empty() {
                    Value::Null
                } else {
                    json!({"path": lossy(path), "size": size, "head_entropy": head_entropy, "exe": exe})
                };
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
                    {
                        // nothing below is needed when no rule matched (most events): skip the string work
                        let m = self.matched(&f);
                        let exe = if m.is_empty() { None } else { f.exe.map(lossy) };
                        (m, exe)
                    }
                };
                let detail = if matched.is_empty() {
                    Value::Null
                } else {
                    json!({"path": lossy(path), "exe": exe})
                };
                self.apply(&mut out, matched, *proc, ts, Some(path), None, &detail);
            }
            Event::FileRename { proc, from, to } => {
                let (matched, exe) = {
                    let mut f = self.facts(EventKind::FileRename, *proc, pacman);
                    f.path = Some(to);
                    {
                        // nothing below is needed when no rule matched (most events): skip the string work
                        let m = self.matched(&f);
                        let exe = if m.is_empty() { None } else { f.exe.map(lossy) };
                        (m, exe)
                    }
                };
                let detail = if matched.is_empty() {
                    Value::Null
                } else {
                    json!({"from": lossy(from), "to": lossy(to), "exe": exe})
                };
                self.apply(&mut out, matched, *proc, ts, Some(to), None, &detail);
            }
            Event::Tamper { what } => out.push(crate::selfguard::from_tamper(ts, what)),
            Event::ModuleLoad { .. } | Event::Ptrace { .. } | Event::SensorHealth { .. } => {}
        }
        self.apply_exceptions(&mut out);
        self.cap_allowlisted(&mut out);
        self.stats.alerts += out.len() as u64;
        out
    }

    /// The exception covering `key`'s process or one of the processes above it.
    fn excepted_proc(&self, key: ProcKey) -> Option<usize> {
        let (chain, unknown) = self.procs.chain(key);
        if let Some(i) = chain
            .iter()
            .find_map(|p| self.exceptions.program(&p.exe, &p.argv))
        {
            return Some(i);
        }
        // the chain left the table at a process older than the engine (a Claude Code session started before it):
        // follow the live parents in /proc
        let mut pid = unknown?;
        for _ in 0..32 {
            if pid <= 1 {
                break;
            }
            let p = (self.live_probe)(pid)?;
            if let Some(i) = self.exceptions.program(&p.exe, &p.argv) {
                return Some(i);
            }
            if p.ppid == pid {
                break;
            }
            pid = p.ppid;
        }
        None
    }

    /// Exceptions (`ai-antivirus exceptions`): alerts about files in an excepted folder, and behavior alerts about an
    /// excepted program or anything it started, are dropped. Malware found in a file by an excepted program is still
    /// reported, capped at a notification. Self-protection and `NEVER_EXCEPTED_RULES` are never touched.
    fn apply_exceptions(&mut self, out: &mut Vec<Alert>) {
        if self.exceptions.is_empty() || out.is_empty() {
            return;
        }
        let mut dropped = 0u64;
        let mut keep = Vec::with_capacity(out.len());
        for mut a in out.drain(..) {
            if a.layer == "self-protection" || NEVER_EXCEPTED_RULES.contains(&a.rule_id.as_str()) {
                keep.push(a);
                continue;
            }
            let path = ["path", "to"]
                .iter()
                .find_map(|k| a.detail.get(*k).and_then(Value::as_str))
                .map(PathBuf::from);
            let by_folder = path.as_deref().and_then(|p| self.exceptions.folder(p));
            let hit = by_folder.map(|i| (i, true)).or_else(|| {
                a.proc_key
                    .and_then(|k| self.excepted_proc(k))
                    .map(|i| (i, false))
            });
            let Some((i, folder)) = hit else {
                keep.push(a);
                continue;
            };
            let label = self
                .exceptions
                .get(i)
                .map(|e| e.label().to_owned())
                .unwrap_or_default();
            if folder || a.layer.starts_with("L3") {
                tracing::info!(rule = %a.rule_id, exception = %label, pid = a.proc_key.map(|k| k.pid), "alert dropped by an exception");
                dropped += 1;
                continue;
            }
            if let Some(obj) = a.detail.as_object_mut() {
                obj.insert("exception".into(), label.into());
                if a.action > Action::Notify {
                    obj.insert("rule_action".into(), a.action.as_str().into());
                }
            }
            a.action = a.action.min(Action::Notify);
            keep.push(a);
        }
        *out = keep;
        self.stats.excepted += dropped;
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
        if self.ancestor_kinds.contains(&kind) {
            f.ancestors = self.procs.ancestors(key);
        }
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
            f.stdin_unix_socket = f
                .stdin
                .and_then(socket_inode)
                .and_then(|i| (self.unix_socket_probe)(i));
            if self.ancestor_kinds.contains(&EventKind::Exec) {
                f.ancestors = self.procs.ancestors(key);
            }
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
            if let Some((_, window)) = self.rules[i].matcher.cpu_check() {
                let waiting = self.cpu_checks.iter().any(|c| c.rule == i && c.key == key);
                if waiting || self.cpu_checks.len() >= MAX_CPU_CHECKS {
                    continue;
                }
                if let Some(cpu) = (self.cpu_probe)(key) {
                    self.cpu_checks.push(CpuCheck {
                        rule: i,
                        key,
                        first_cpu_ns: cpu,
                        first_ns: ts,
                        due_ns: ts.saturating_add(window.saturating_mul(1_000_000_000)),
                        detail: detail.clone(),
                    });
                }
            } else if self.rules[i].threshold.is_some() {
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
                    "AV-I-0001".to_owned(),
                    Severity::High,
                    0.9,
                    format!("File of package {package} differs from what pacman installed"),
                    Action::Restore,
                    "L0 trust",
                    json!({"package": package, "expected_sha256": expected.to_string(), "sha256": actual.to_string()}),
                ),
                Finding::KnownBad { sha256, label } => (
                    "AV-H-0001".to_owned(),
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
        if !self.scan_on_write || self.exceptions.folder(path).is_some() {
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

/// The inode of `socket:[123]`.
fn socket_inode(fd: &std::ffi::OsStr) -> Option<u64> {
    let s = fd.to_str()?;
    s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Whether a socket inode is local (not a network socket): listed in /proc/net/unix (this network namespace's Unix-domain
/// sockets), or listed nowhere because it is already closed (a short-lived shell, e.g. an editor's or agent's hook, is
/// often gone before the engine looks; a reverse shell keeps its socket open). Found in /proc/net/{tcp,udp}[6]: network.
/// None: /proc/net/unix is unreadable, so the caller treats the socket as network.
fn is_unix_socket(inode: u64) -> Option<bool> {
    let unix = std::fs::read_to_string("/proc/net/unix").ok()?;
    if unix_table_has(&unix, inode) {
        return Some(true);
    }
    let inet = ["tcp", "tcp6", "udp", "udp6"].iter().any(|f| {
        std::fs::read_to_string(format!("/proc/net/{f}")).is_ok_and(|t| inet_table_has(&t, inode))
    });
    Some(!inet)
}

/// /proc/net/tcp and friends: the inode is the 10th column.
fn inet_table_has(table: &str, inode: u64) -> bool {
    table.lines().skip(1).any(|l| {
        l.split_whitespace()
            .nth(9)
            .and_then(|v| v.parse::<u64>().ok())
            == Some(inode)
    })
}

/// /proc/net/unix: `Num RefCount Protocol Flags Type St Inode Path`; the inode is the 7th column.
fn unix_table_has(table: &str, inode: u64) -> bool {
    table.lines().skip(1).any(|l| {
        l.split_whitespace()
            .nth(6)
            .and_then(|v| v.parse::<u64>().ok())
            == Some(inode)
    })
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[test]
    fn socket_inodes_and_the_unix_table() {
        assert_eq!(
            socket_inode(std::ffi::OsStr::new("socket:[2187683]")),
            Some(2_187_683)
        );
        assert_eq!(socket_inode(std::ffi::OsStr::new("pipe:[5]")), None);
        let table = "Num       RefCount Protocol Flags    Type St Inode Path\n\
                     0000000000000000: 00000003 00000000 00000000 0001 03 2187683\n\
                     0000000000000000: 00000002 00000000 00010000 0001 01 17 /run/systemd/notify\n";
        assert!(unix_table_has(table, 2_187_683));
        assert!(unix_table_has(table, 17));
        assert!(!unix_table_has(table, 4242));
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   0: 0100007F:1F90 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000  1000        0 55501 1\n";
        assert!(inet_table_has(tcp, 55_501));
        assert!(!inet_table_has(tcp, 1000));
    }
}
