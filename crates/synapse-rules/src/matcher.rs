//! Evaluating a rule's `match` table against the facts about one event.
//!
//! The engine gathers the facts (the acting process from its process table, the file's mode, whether pacman is running);
//! this module only compares. Paths are compared as bytes: Linux paths need not be UTF-8.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::rule::{EventKind, Match, Rule};

/// What is known about one event. `None` = not known (an unknown fact never satisfies a condition on it).
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub kind: EventKind,
    /// The acting process's executable.
    pub exe: Option<&'a Path>,
    pub parent_exe: Option<&'a Path>,
    /// `exec`: the arguments.
    pub argv: &'a [OsString],
    /// `exec`: what fds 0 and 1 point to (`socket:[1]`, `pipe:[2]`, `/dev/pts/0`).
    pub stdin: Option<&'a OsStr>,
    pub stdout: Option<&'a OsStr>,
    /// `exec`: the executable writing into stdin, when stdin is a pipe the engine has seen from the other end.
    pub stdin_writer_exe: Option<&'a Path>,
    /// File events: the path (for a rename, the new name).
    pub path: Option<&'a Path>,
    /// `file_write`: the file is setuid and owned by root.
    pub setuid_root: Option<bool>,
    /// `connect` / `listen`: the port.
    pub port: Option<u16>,
    pub pacman_active: bool,
}

impl<'a> Facts<'a> {
    pub fn new(kind: EventKind) -> Facts<'a> {
        Facts {
            kind,
            exe: None,
            parent_exe: None,
            argv: &[],
            stdin: None,
            stdout: None,
            stdin_writer_exe: None,
            path: None,
            setuid_root: None,
            port: None,
            pacman_active: false,
        }
    }
}

fn is_socket(fd: Option<&OsStr>) -> Option<bool> {
    fd.map(|s| s.as_bytes().starts_with(b"socket:"))
}

/// `~/rest` matches `/root/rest` and `/home/<user>/rest`; anything else is compared literally.
/// `prefix = true` compares only the beginning.
fn path_matches(path: &[u8], pattern: &str, prefix: bool) -> bool {
    let pat = pattern.as_bytes();
    let cmp = |p: &[u8], tail: &[u8]| if prefix { p.starts_with(tail) } else { p == tail };
    let Some(rest) = pat.strip_prefix(b"~/") else {
        return cmp(path, pat);
    };
    if let Some(p) = path.strip_prefix(b"/root/") {
        return cmp(p, rest);
    }
    if let Some(p) = path.strip_prefix(b"/home/") {
        // exactly one component for the user name
        if let Some(slash) = p.iter().position(|&b| b == b'/') {
            if slash > 0 {
                return cmp(&p[slash + 1..], rest);
            }
        }
    }
    false
}

fn any_path(list: &[std::path::PathBuf], value: Option<&Path>) -> bool {
    list.is_empty() || value.is_some_and(|v| list.iter().any(|p| p == v))
}

impl Match {
    /// True when every condition given in the table holds for `f`.
    pub fn matches(&self, f: &Facts<'_>) -> bool {
        if self.event != f.kind {
            return false;
        }
        if !any_path(&self.exe_in, f.exe) || !any_path(&self.parent_exe_in, f.parent_exe) {
            return false;
        }
        let exe = f.exe.map(|p| p.as_os_str().as_bytes());
        if !self.exe_prefix.is_empty() && !exe.is_some_and(|e| self.exe_prefix.iter().any(|p| e.starts_with(p.as_bytes()))) {
            return false;
        }
        if !self.exe_suffix.is_empty() && !exe.is_some_and(|e| self.exe_suffix.iter().any(|s| e.ends_with(s.as_bytes()))) {
            return false;
        }
        if !self.argv_contains.is_empty() {
            let line = f.argv.iter().map(|a| a.as_bytes()).collect::<Vec<_>>().join(&b' ');
            if !self.argv_contains.iter().any(|s| contains(&line, s.as_bytes())) {
                return false;
            }
        }
        if let Some(want) = self.stdin_is_socket {
            if is_socket(f.stdin) != Some(want) {
                return false;
            }
        }
        if let Some(want) = self.stdout_is_socket {
            if is_socket(f.stdout) != Some(want) {
                return false;
            }
        }
        if !any_path(&self.stdin_from_exe_in, f.stdin_writer_exe) {
            return false;
        }
        let path = f.path.map(|p| p.as_os_str().as_bytes());
        if !self.path_in.is_empty() && !path.is_some_and(|p| self.path_in.iter().any(|pat| path_matches(p, pat, false))) {
            return false;
        }
        if !self.path_prefix.is_empty() && !path.is_some_and(|p| self.path_prefix.iter().any(|pat| path_matches(p, pat, true))) {
            return false;
        }
        if !self.path_suffix.is_empty() && !path.is_some_and(|p| self.path_suffix.iter().any(|s| p.ends_with(s.as_bytes()))) {
            return false;
        }
        if let Some(want) = self.setuid_file {
            if f.setuid_root != Some(want) {
                return false;
            }
        }
        if !self.port_in.is_empty() && !f.port.is_some_and(|p| self.port_in.contains(&p)) {
            return false;
        }
        if self.outside_pacman == Some(true) && f.pacman_active {
            return false;
        }
        true
    }

    /// Whether this rule needs the file's mode (the engine stats the file only then).
    pub fn wants_setuid(&self) -> bool {
        self.setuid_file.is_some()
    }
}

impl Rule {
    /// The `match` table holds and the acting executable is not excluded.
    pub fn matches(&self, f: &Facts<'_>) -> bool {
        if f.exe.is_some_and(|e| self.exclude_exe.iter().any(|x| x == e)) {
            return false;
        }
        self.matcher.matches(f)
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleSet;
    use std::path::PathBuf;

    fn rule(toml: &str) -> Rule {
        RuleSet::parse_str(toml, "t").unwrap().remove(0)
    }

    #[test]
    fn reverse_shell_needs_a_shell_and_a_socket() {
        let r = rule(
            "[[rule]]\nid='SYN-B-0001'\ntitle='t'\nseverity='high'\nconfidence=0.9\naction='freeze'\n\
             match={event='exec', exe_in=['/usr/bin/bash'], stdin_is_socket=true}",
        );
        let bash = PathBuf::from("/usr/bin/bash");
        let sock = OsString::from("socket:[99]");
        let tty = OsString::from("/dev/pts/3");
        let mut f = Facts::new(EventKind::Exec);
        f.exe = Some(&bash);
        f.stdin = Some(&sock);
        assert!(r.matches(&f));
        f.stdin = Some(&tty);
        assert!(!r.matches(&f));
        f.stdin = None; // not collected: unknown never matches
        assert!(!r.matches(&f));
        f.stdin = Some(&sock);
        f.kind = EventKind::Connect;
        assert!(!r.matches(&f));
    }

    #[test]
    fn home_patterns_cover_every_home_and_nothing_else() {
        assert!(path_matches(b"/home/nex/.ssh/authorized_keys", "~/.ssh/authorized_keys", false));
        assert!(path_matches(b"/root/.ssh/authorized_keys", "~/.ssh/authorized_keys", false));
        assert!(!path_matches(b"/home/a/b/.ssh/authorized_keys", "~/.ssh/authorized_keys", false));
        assert!(!path_matches(b"/home//.ssh/authorized_keys", "~/.ssh/authorized_keys", false));
        assert!(!path_matches(b"/tmp/.ssh/authorized_keys", "~/.ssh/authorized_keys", false));
        assert!(path_matches(b"/home/nex/.config/systemd/user/x.service", "~/.config/systemd/user/", true));
        assert!(path_matches(b"/etc/ld.so.preload", "/etc/ld.so.preload", false));
        assert!(!path_matches(b"/etc/ld.so.preload.bak", "/etc/ld.so.preload", false));
    }

    #[test]
    fn exclusions_win_and_pacman_pauses_rules_that_ask_for_it() {
        let r = rule(
            "[[rule]]\nid='SYN-B-0005'\ntitle='t'\nseverity='medium'\nconfidence=0.6\naction='notify'\n\
             exclude_exe=['/usr/bin/pacman']\n\
             match={event='file_write', path_prefix=['/etc/systemd/'], path_suffix=['.service','.timer'], outside_pacman=true}",
        );
        let unit = PathBuf::from("/etc/systemd/system/evil.service");
        let other = PathBuf::from("/etc/systemd/system/evil.conf");
        let curl = PathBuf::from("/usr/bin/curl");
        let pacman = PathBuf::from("/usr/bin/pacman");
        let mut f = Facts::new(EventKind::FileWrite);
        f.path = Some(&unit);
        f.exe = Some(&curl);
        assert!(r.matches(&f));
        f.path = Some(&other);
        assert!(!r.matches(&f));
        f.path = Some(&unit);
        f.exe = Some(&pacman);
        assert!(!r.matches(&f));
        f.exe = Some(&curl);
        f.pacman_active = true;
        assert!(!r.matches(&f));
    }

    #[test]
    fn argv_ports_and_exe_prefixes() {
        let r = rule(
            "[[rule]]\nid='SYN-B-0002'\ntitle='t'\nseverity='high'\nconfidence=0.7\naction='notify'\n\
             match={event='exec', exe_prefix=['/tmp/','/dev/shm/'], argv_contains=['--hidden']}",
        );
        let t = PathBuf::from("/tmp/x/run");
        let u = PathBuf::from("/usr/bin/run");
        let argv = vec![OsString::from("run"), OsString::from("--hidden")];
        let mut f = Facts::new(EventKind::Exec);
        f.exe = Some(&t);
        f.argv = &argv;
        assert!(r.matches(&f));
        f.exe = Some(&u);
        assert!(!r.matches(&f));

        let m = rule(
            "[[rule]]\nid='SYN-B-0012'\ntitle='t'\nseverity='medium'\nconfidence=0.5\naction='notify'\n\
             match={event='connect', port_in=[3333, 14444]}",
        );
        let mut c = Facts::new(EventKind::Connect);
        c.port = Some(3333);
        assert!(m.matches(&c));
        c.port = Some(443);
        assert!(!m.matches(&c));
    }
}
