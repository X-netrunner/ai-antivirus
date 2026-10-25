//! Behavior rules (spec 7, layer L3): the TOML schema, its validation, and loading a rules directory.
//!
//! A rule file holds `[[rule]]` tables. Every key is checked: unknown keys, a key that does not apply to the rule's event kind
//! (a `path_prefix` on an `exec` rule, say), relative paths, empty lists and out-of-range numbers are errors, and all problems
//! in a directory are reported at once. The same schema is what the AI analyzer will have to produce for proposals (M5).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ai_antivirus_common::model::Severity;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Longest accepted rule file. Rules are small; a huge file is a mistake or an attack on the parser.
const MAX_RULE_FILE_BYTES: u64 = 1024 * 1024;
/// Longest window a threshold rule may keep state for.
const MAX_WINDOW_SECS: u64 = 3600;
/// Most entries in any one list.
const MAX_LIST: usize = 256;

/// One `.toml` file: `[[rule]]` tables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `AV-B-0001` (shipped behavior rules) or `LOCAL-<name>` (your own and approved proposals).
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// 0.0 to 1.0.
    pub confidence: f64,
    #[serde(rename = "match")]
    pub matcher: Match,
    /// What one threshold counts over. Rules without a threshold fire per event and ignore this.
    #[serde(default)]
    pub scope: Scope,
    /// Length of the sliding window for `threshold`, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Threshold>,
    /// Acting executables this rule never fires for (exact paths).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_exe: Vec<PathBuf>,
    /// The rule never fires when one of these runs anywhere above the acting process (its parent, grandparent ...):
    /// `['/usr/bin/pacman']` leaves pacman's hooks and install scriptlets alone (spec 8: pacman and its children).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_ancestor_exe: Vec<PathBuf>,
    /// What the responder would do. In M3 nothing executes: the action is recorded on the alert.
    pub action: Action,
}

/// Conditions on one event. All given conditions must hold; lists match when any entry matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// The event kind, as in the event log: `exec`, `exit`, `connect`, `listen`, `file_write` ...
    pub event: EventKind,
    /// The acting process's executable is one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exe_in: Vec<PathBuf>,
    /// The executable path starts with one of these (`/tmp/`, `/memfd:`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exe_prefix: Vec<String>,
    /// The executable path ends with one of these (` (deleted)`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exe_suffix: Vec<String>,
    /// The parent's executable is one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_exe_in: Vec<PathBuf>,
    /// `exec` only: the command line (arguments joined by spaces) contains one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv_contains: Vec<String>,
    /// `exec` only: stdin is (true) or is not (false) a socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_is_socket: Option<bool>,
    /// `exec` only: stdout is (true) or is not (false) a socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_is_socket: Option<bool>,
    /// `exec` only: stdin is (true) or is not (false) a network socket. A Unix-domain socket (how terminals in editors and
    /// coding agents hand a shell its input) is not one, nor is one already closed; when the tables cannot be read it counts as network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_socket_network: Option<bool>,
    /// `exec` only: stdin is a pipe whose writing end belongs to one of these executables (`curl ... | sh`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stdin_from_exe_in: Vec<PathBuf>,
    /// File events: the path is one of these. `~/x` stands for `x` in every home directory (`/home/*/x` and `/root/x`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_in: Vec<String>,
    /// File events: the path starts with one of these (`~/` as above).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefix: Vec<String>,
    /// File events: the path starts with none of these (`~/` as above): folders a rule leaves alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_not_prefix: Vec<String>,
    /// File events: the path ends with one of these (`.service`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_suffix: Vec<String>,
    /// `file_write` only: the file now has the setuid bit and is owned by root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setuid_file: Option<bool>,
    /// `connect` / `listen`: the port is one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_in: Vec<u16>,
    /// true: only while no pacman transaction runs (`/var/lib/pacman/db.lck` absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside_pacman: Option<bool>,
    /// `connect` / `listen`: the acting process then keeps using at least this much CPU (percent of one core, so
    /// above 100 means several cores) over `cpu_window_secs`. The engine samples /proc/<pid>/stat at the event and
    /// again after the window, and only for events that matched every other condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cpu_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_window_secs: Option<u64>,
}

/// Highest `min_cpu_percent` accepted (64 cores fully busy).
pub const MAX_CPU_PERCENT: u32 = 6400;
/// Shortest and longest CPU sampling window.
pub const CPU_WINDOW_SECS: std::ops::RangeInclusive<u64> = 5..=600;

/// Event kinds a rule can match (the `type` tag of the event log).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    #[default]
    Exec,
    Exit,
    Connect,
    Listen,
    FileWrite,
    FileCreate,
    FileRename,
    FileUnlink,
    ModuleLoad,
    Ptrace,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Exec => "exec",
            EventKind::Exit => "exit",
            EventKind::Connect => "connect",
            EventKind::Listen => "listen",
            EventKind::FileWrite => "file_write",
            EventKind::FileCreate => "file_create",
            EventKind::FileRename => "file_rename",
            EventKind::FileUnlink => "file_unlink",
            EventKind::ModuleLoad => "module_load",
            EventKind::Ptrace => "ptrace",
        }
    }

    fn is_file(self) -> bool {
        matches!(
            self,
            EventKind::FileWrite
                | EventKind::FileCreate
                | EventKind::FileRename
                | EventKind::FileUnlink
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Each event on its own (no state).
    #[default]
    Event,
    /// Counted per process.
    Process,
    /// Counted per process tree: a process and its descendants up to the nearest session root (a shell, terminal, login
    /// manager or systemd), so the workers of one program are counted together.
    ProcessTree,
}

/// Counts over `window_secs`. Every given figure must be reached.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    /// Matching events in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<u32>,
    /// Distinct file paths among the matching `file_write` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct_files_written: Option<u32>,
    /// Share (0.0 to 1.0) of those writes whose first 4 KiB look random (entropy at least 7.2 bits per byte). Writes the
    /// sensor could not sample count as not random.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_entropy_ratio: Option<f64>,
}

/// Response levels from spec section 8. Ordered by level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Log,
    Notify,
    Freeze,
    Kill,
    Quarantine,
    Block,
    Restore,
}

impl Action {
    pub fn level(self) -> u8 {
        match self {
            Action::Log => 0,
            Action::Notify => 1,
            Action::Freeze => 2,
            Action::Kill => 3,
            Action::Quarantine => 4,
            Action::Block => 5,
            Action::Restore => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Log => "log",
            Action::Notify => "notify",
            Action::Freeze => "freeze",
            Action::Kill => "kill",
            Action::Quarantine => "quarantine",
            Action::Block => "block",
            Action::Restore => "restore",
        }
    }
}

/// Entropy (milli-bits per byte) from which a sampled write counts as random.
pub const HIGH_ENTROPY_MILLI: u16 = 7200;

fn valid_id(id: &str) -> bool {
    let shipped = id
        .strip_prefix("AV-B-")
        .is_some_and(|n| n.len() == 4 && n.bytes().all(|b| b.is_ascii_digit()));
    let local = id.strip_prefix("LOCAL-").is_some_and(|n| {
        (1..=48).contains(&n.len())
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    shipped || local
}

/// `~/x` (any home) or an absolute path; no `..` components and no NUL.
fn valid_path_pattern(p: &str) -> bool {
    let rest = p.strip_prefix("~/").unwrap_or(p);
    (p.starts_with('/') || p.starts_with("~/"))
        && !rest.split('/').any(|c| c == "..")
        && !p.contains('\0')
}

impl Rule {
    /// Every problem with this rule, as human-readable lines (empty = valid).
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut bad = |msg: String| out.push(format!("rule {:?}: {msg}", self.id));
        let m = &self.matcher;
        let kind = m.event;

        if !valid_id(&self.id) {
            bad("id must be AV-B-NNNN or LOCAL-<letters, digits, - or _>".into());
        }
        if self.title.trim().is_empty() || self.title.len() > 200 {
            bad("title must be 1 to 200 characters".into());
        }
        if !(0.0..=1.0).contains(&self.confidence) || self.confidence.is_nan() {
            bad("confidence must be within 0.0..=1.0".into());
        }

        // lists: not too long, no empty strings
        let lists: [(&str, usize, bool); 12] = [
            (
                "path_not_prefix",
                m.path_not_prefix.len(),
                m.path_not_prefix.iter().any(String::is_empty),
            ),
            (
                "exe_in",
                m.exe_in.len(),
                m.exe_in.iter().any(|p| p.as_os_str().is_empty()),
            ),
            (
                "exe_prefix",
                m.exe_prefix.len(),
                m.exe_prefix.iter().any(String::is_empty),
            ),
            (
                "exe_suffix",
                m.exe_suffix.len(),
                m.exe_suffix.iter().any(String::is_empty),
            ),
            (
                "parent_exe_in",
                m.parent_exe_in.len(),
                m.parent_exe_in.iter().any(|p| p.as_os_str().is_empty()),
            ),
            (
                "argv_contains",
                m.argv_contains.len(),
                m.argv_contains.iter().any(String::is_empty),
            ),
            (
                "stdin_from_exe_in",
                m.stdin_from_exe_in.len(),
                m.stdin_from_exe_in.iter().any(|p| p.as_os_str().is_empty()),
            ),
            (
                "path_in",
                m.path_in.len(),
                m.path_in.iter().any(String::is_empty),
            ),
            (
                "path_prefix",
                m.path_prefix.len(),
                m.path_prefix.iter().any(String::is_empty),
            ),
            (
                "path_suffix",
                m.path_suffix.len(),
                m.path_suffix.iter().any(String::is_empty),
            ),
            (
                "exclude_exe",
                self.exclude_exe.len(),
                self.exclude_exe.iter().any(|p| p.as_os_str().is_empty()),
            ),
            (
                "exclude_ancestor_exe",
                self.exclude_ancestor_exe.len(),
                self.exclude_ancestor_exe
                    .iter()
                    .any(|p| p.as_os_str().is_empty()),
            ),
        ];
        for (name, len, has_empty) in lists {
            if len > MAX_LIST {
                bad(format!("{name} has more than {MAX_LIST} entries"));
            }
            if has_empty {
                bad(format!("{name} has an empty entry"));
            }
        }
        for (name, paths) in [
            ("exe_in", &m.exe_in),
            ("parent_exe_in", &m.parent_exe_in),
            ("stdin_from_exe_in", &m.stdin_from_exe_in),
            ("exclude_exe", &self.exclude_exe),
            ("exclude_ancestor_exe", &self.exclude_ancestor_exe),
        ] {
            if paths.iter().any(|p| !p.is_absolute()) {
                bad(format!("{name} entries must be absolute paths"));
            }
        }
        for (name, pats) in [
            ("path_in", &m.path_in),
            ("path_prefix", &m.path_prefix),
            ("path_not_prefix", &m.path_not_prefix),
        ] {
            if pats.iter().any(|p| !valid_path_pattern(p)) {
                bad(format!(
                    "{name} entries must be absolute or start with ~/, without .."
                ));
            }
        }

        // keys that only make sense for some event kinds
        let exec_only = !m.argv_contains.is_empty()
            || m.stdin_is_socket.is_some()
            || m.stdout_is_socket.is_some()
            || m.stdin_socket_network.is_some()
            || !m.stdin_from_exe_in.is_empty();
        if exec_only && kind != EventKind::Exec {
            bad("argv_contains, stdin_is_socket, stdout_is_socket, stdin_socket_network and stdin_from_exe_in need event = 'exec'".into());
        }
        let file_keys = !m.path_in.is_empty()
            || !m.path_prefix.is_empty()
            || !m.path_not_prefix.is_empty()
            || !m.path_suffix.is_empty();
        if file_keys && !kind.is_file() {
            bad("path_in, path_prefix, path_not_prefix and path_suffix need a file event".into());
        }
        if m.setuid_file.is_some() && kind != EventKind::FileWrite {
            bad("setuid_file needs event = 'file_write'".into());
        }
        if !m.port_in.is_empty() && !matches!(kind, EventKind::Connect | EventKind::Listen) {
            bad("port_in needs event = 'connect' or 'listen'".into());
        }
        if m.port_in.contains(&0) {
            bad("port_in cannot contain 0".into());
        }
        match (m.min_cpu_percent, m.cpu_window_secs) {
            (None, None) => {}
            (Some(p), Some(w)) => {
                if !matches!(kind, EventKind::Connect | EventKind::Listen) {
                    bad("min_cpu_percent needs event = 'connect' or 'listen'".into());
                }
                if p == 0 || p > MAX_CPU_PERCENT {
                    bad(format!("min_cpu_percent must be 1 to {MAX_CPU_PERCENT}"));
                }
                if !CPU_WINDOW_SECS.contains(&w) {
                    bad(format!(
                        "cpu_window_secs must be {} to {}",
                        CPU_WINDOW_SECS.start(),
                        CPU_WINDOW_SECS.end()
                    ));
                }
                if self.threshold.is_some() {
                    bad("min_cpu_percent cannot be combined with a threshold".into());
                }
            }
            _ => bad("min_cpu_percent and cpu_window_secs go together".into()),
        }

        // thresholds
        match (&self.threshold, self.window_secs) {
            (None, None) => {
                if self.scope != Scope::Event {
                    bad("scope needs a threshold".into());
                }
            }
            (None, Some(_)) => bad("window_secs needs a threshold".into()),
            (Some(_), None) => bad("a threshold needs window_secs".into()),
            (Some(t), Some(w)) => {
                if w == 0 || w > MAX_WINDOW_SECS {
                    bad(format!("window_secs must be 1 to {MAX_WINDOW_SECS}"));
                }
                if self.scope == Scope::Event {
                    bad("a threshold needs scope = 'process' or 'process_tree'".into());
                }
                if t.events.is_none() && t.distinct_files_written.is_none() {
                    bad("a threshold needs events or distinct_files_written".into());
                }
                if t.events == Some(0) || t.distinct_files_written == Some(0) {
                    bad("threshold counts must be at least 1".into());
                }
                if (t.distinct_files_written.is_some() || t.high_entropy_ratio.is_some())
                    && kind != EventKind::FileWrite
                {
                    bad(
                        "distinct_files_written and high_entropy_ratio need event = 'file_write'"
                            .into(),
                    );
                }
                if let Some(r) = t.high_entropy_ratio {
                    if !(0.0..=1.0).contains(&r) || r.is_nan() {
                        bad("high_entropy_ratio must be within 0.0..=1.0".into());
                    }
                    if t.distinct_files_written.is_none() {
                        bad("high_entropy_ratio needs distinct_files_written".into());
                    }
                }
            }
        }
        out
    }
}

/// A validated set of rules, in load order.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// The files they came from (for `ai-antivirus rules`).
    pub files: Vec<PathBuf>,
}

impl RuleSet {
    /// Parse and validate one file's text. `origin` names it in error messages.
    pub fn parse_str(text: &str, origin: &str) -> Result<Vec<Rule>> {
        let file: RuleFile =
            toml::from_str(text).map_err(|e| Error::Rules(vec![format!("{origin}: {e}")]))?;
        let problems: Vec<String> = file
            .rule
            .iter()
            .flat_map(|r| r.problems())
            .map(|p| format!("{origin}: {p}"))
            .collect();
        if problems.is_empty() {
            Ok(file.rule)
        } else {
            Err(Error::Rules(problems))
        }
    }

    /// Load every `*.toml` under `dir` and its subdirectories (sorted, so the order is stable). Duplicate ids across files
    /// are an error. All problems are collected before failing.
    pub fn load_dir(dir: &Path) -> Result<RuleSet> {
        let mut files = Vec::new();
        collect_toml(dir, &mut files, 0)?;
        files.sort();
        let mut set = RuleSet::default();
        let mut problems = Vec::new();
        let mut ids = BTreeSet::new();
        for f in &files {
            let meta = fs::symlink_metadata(f).map_err(|e| Error::io(f, e))?;
            if meta.len() > MAX_RULE_FILE_BYTES {
                problems.push(format!(
                    "{}: larger than {MAX_RULE_FILE_BYTES} bytes",
                    f.display()
                ));
                continue;
            }
            let text = fs::read_to_string(f).map_err(|e| Error::io(f, e))?;
            match RuleSet::parse_str(&text, &f.display().to_string()) {
                Ok(rules) => {
                    for r in rules {
                        if !ids.insert(r.id.clone()) {
                            problems.push(format!("{}: duplicate rule id {:?}", f.display(), r.id));
                            continue;
                        }
                        set.rules.push(r);
                    }
                }
                Err(Error::Rules(p)) => problems.extend(p),
                Err(e) => return Err(e),
            }
        }
        if problems.is_empty() {
            set.files = files;
            Ok(set)
        } else {
            Err(Error::Rules(problems))
        }
    }
}

/// Regular files only: a symlink in a rules directory is refused (it could point anywhere).
fn collect_toml(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) -> Result<()> {
    if depth > 4 {
        return Ok(());
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    for entry in rd {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| Error::io(&path, e))?;
        if ft.is_dir() {
            collect_toml(&path, out, depth + 1)?;
        } else if ft.is_file() && path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVERSE_SHELL: &str = r#"
[[rule]]
id = 'AV-B-0001'
title = 'Shell with a socket as stdin (reverse shell)'
severity = 'high'
confidence = 0.9
match = { event = 'exec', exe_in = ['/usr/bin/bash', '/usr/bin/sh'], stdin_is_socket = true }
action = 'freeze'
"#;

    const RANSOM: &str = r#"
[[rule]]
id = 'AV-B-0010'
title = 'Mass file rewrite in home directory'
severity = 'critical'
confidence = 0.8
scope = 'process_tree'
window_secs = 10
threshold = { distinct_files_written = 200, high_entropy_ratio = 0.7 }
match = { event = 'file_write', path_prefix = ['~/'] }
exclude_exe = ['/usr/bin/pacman', '/usr/bin/rsync']
action = 'freeze'
"#;

    #[test]
    fn the_spec_examples_parse() {
        let r = RuleSet::parse_str(REVERSE_SHELL, "t").unwrap();
        assert_eq!(r[0].matcher.stdin_is_socket, Some(true));
        assert_eq!(r[0].action, Action::Freeze);
        let r = RuleSet::parse_str(RANSOM, "t").unwrap();
        assert_eq!(r[0].scope, Scope::ProcessTree);
        assert_eq!(
            r[0].threshold
                .as_ref()
                .and_then(|t| t.distinct_files_written),
            Some(200)
        );
    }

    #[test]
    fn unknown_keys_and_misplaced_keys_are_refused() {
        let typo = REVERSE_SHELL.replace("stdin_is_socket", "stdin_is_sockets");
        assert!(RuleSet::parse_str(&typo, "t").is_err());
        let wrong_kind = REVERSE_SHELL.replace("event = 'exec'", "event = 'connect'");
        let Err(Error::Rules(p)) = RuleSet::parse_str(&wrong_kind, "t") else {
            panic!("accepted")
        };
        assert!(p[0].contains("need event = 'exec'"), "{p:?}");
        let extra =
            REVERSE_SHELL.replace("action = 'freeze'", "action = 'freeze'\nrun = 'rm -rf /'");
        assert!(RuleSet::parse_str(&extra, "t").is_err());
        let action = REVERSE_SHELL.replace("'freeze'", "'reboot'");
        assert!(RuleSet::parse_str(&action, "t").is_err());
    }

    #[test]
    fn bad_values_are_all_reported() {
        let bad = REVERSE_SHELL
            .replace("AV-B-0001", "evil id")
            .replace("0.9", "1.5")
            .replace("'/usr/bin/sh'", "'sh'");
        let Err(Error::Rules(p)) = RuleSet::parse_str(&bad, "t") else {
            panic!("accepted")
        };
        assert_eq!(p.len(), 3, "{p:?}");
    }

    #[test]
    fn cpu_conditions_are_validated() {
        let ok = "[[rule]]\nid = 'LOCAL-cpu'\ntitle = 't'\nseverity = 'medium'\nconfidence = 0.5\n\
                  match = { event = 'connect', port_in = [3333], min_cpu_percent = 50, cpu_window_secs = 60 }\naction = 'notify'\n";
        assert!(
            RuleSet::parse_str(ok, "t").is_ok(),
            "{:?}",
            RuleSet::parse_str(ok, "t").err()
        );
        for (from, to, why) in [
            (", cpu_window_secs = 60", "", "go together"),
            ("min_cpu_percent = 50", "min_cpu_percent = 0", "1 to"),
            (
                "cpu_window_secs = 60",
                "cpu_window_secs = 1",
                "cpu_window_secs must be",
            ),
            (
                "event = 'connect', port_in = [3333]",
                "event = 'exec'",
                "needs event = 'connect'",
            ),
        ] {
            let text = ok.replace(from, to);
            let err = RuleSet::parse_str(&text, "t").unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn threshold_rules_need_a_window_and_a_scope() {
        let no_window = RANSOM.replace("window_secs = 10\n", "");
        assert!(RuleSet::parse_str(&no_window, "t").is_err());
        let no_scope = RANSOM.replace("scope = 'process_tree'\n", "");
        assert!(RuleSet::parse_str(&no_scope, "t").is_err());
        let huge = RANSOM.replace("window_secs = 10", "window_secs = 999999");
        assert!(RuleSet::parse_str(&huge, "t").is_err());
        let dotdot = RANSOM.replace("['~/']", "['/home/../etc']");
        assert!(RuleSet::parse_str(&dotdot, "t").is_err());
    }

    #[test]
    fn a_directory_loads_sorted_and_rejects_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.toml"), RANSOM).unwrap();
        fs::create_dir(dir.path().join("local")).unwrap();
        fs::write(dir.path().join("local/a.toml"), REVERSE_SHELL).unwrap();
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let set = RuleSet::load_dir(dir.path()).unwrap();
        assert_eq!(set.rules.len(), 2);
        fs::write(dir.path().join("c.toml"), REVERSE_SHELL).unwrap();
        let Err(Error::Rules(p)) = RuleSet::load_dir(dir.path()) else {
            panic!("duplicate accepted")
        };
        assert!(p[0].contains("duplicate"), "{p:?}");
        // a missing directory is an empty set, not an error
        assert!(RuleSet::load_dir(&dir.path().join("nope"))
            .unwrap()
            .rules
            .is_empty());
    }

    #[test]
    fn local_ids_are_allowed() {
        let local = REVERSE_SHELL.replace("AV-B-0001", "LOCAL-my_rule-2");
        assert!(RuleSet::parse_str(&local, "t").is_ok());
    }
}
