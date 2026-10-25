//! The engine's view of running processes, built from `exec` / `exit` events (the engine has no privileges and does not
//! read `/proc` of other users). Also pairs the two ends of pipes seen in `exec` stdio, so `curl ... | sh` can be told apart
//! from `cat file | sh` whichever side the kernel reports first.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use synapse_common::event::ProcKey;

/// Most processes remembered; beyond this the longest-exited ones go first, then the table is cleared.
const MAX_PROCS: usize = 65_536;
/// Exited processes are kept this long, for events that arrive after the exit (a file closed on exit).
const KEEP_EXITED_NS: u64 = 120 * 1_000_000_000;
/// A pipe end is remembered this long for pairing.
const PIPE_TTL_NS: u64 = 30 * 1_000_000_000;
const MAX_PIPES: usize = 16_384;

/// Programs that start sessions rather than work: a process tree (rule scope `process_tree`) stops below them.
const TREE_STOP: &[&str] = &[
    "/usr/lib/systemd/systemd",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/dash",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/bin/sshd",
    "/usr/lib/ssh/sshd-session",
    "/usr/bin/login",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/doas",
    "/usr/bin/tmux",
    "/usr/bin/screen",
    "/usr/bin/foot",
    "/usr/bin/kitty",
    "/usr/bin/alacritty",
    "/usr/bin/wezterm-gui",
    "/usr/bin/konsole",
    "/usr/lib/gnome-terminal-server",
    "/usr/bin/Hyprland",
    "/usr/bin/sway",
    "/usr/bin/gnome-shell",
    "/usr/bin/kwin_wayland",
    "/usr/bin/sddm",
    "/usr/bin/gdm",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub exe: PathBuf,
    pub argv: Vec<OsString>,
    pub uid: u32,
    pub parent: ProcKey,
    pub stdio: Vec<OsString>,
    /// Ancestors as the sensor saw them, nearest first, including ones that only forked.
    pub lineage: Vec<ProcKey>,
    pub exited_ns: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ProcTable {
    procs: HashMap<ProcKey, Proc>,
    by_pid: HashMap<u32, ProcKey>,
    /// pipe inode -> the process writing into it (its stdout), and when it was seen
    writers: HashMap<u64, (ProcKey, u64)>,
    /// pipe inode -> the process reading from it (its stdin)
    readers: HashMap<u64, (ProcKey, u64)>,
}

/// `pipe:[12345]` -> 12345.
pub fn pipe_inode(fd: &OsStr) -> Option<u64> {
    let s = fd.as_bytes().strip_prefix(b"pipe:[")?.strip_suffix(b"]")?;
    std::str::from_utf8(s).ok()?.parse().ok()
}

impl ProcTable {
    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// Record an exec. Returns the reader that was waiting for this process's stdout pipe, if any (the engine re-checks
    /// it now that the writer is known).
    pub fn on_exec(&mut self, key: ProcKey, proc: Proc, ts_ns: u64) -> Option<ProcKey> {
        if self.procs.len() >= MAX_PROCS {
            self.sweep(u64::MAX);
            if self.procs.len() >= MAX_PROCS {
                self.procs.clear();
                self.by_pid.clear();
            }
        }
        let stdin_pipe = proc.stdio.first().and_then(|s| pipe_inode(s));
        let stdout_pipe = proc.stdio.get(1).and_then(|s| pipe_inode(s));
        self.by_pid.insert(key.pid, key);
        self.procs.insert(key, proc);
        if self.writers.len() + self.readers.len() >= MAX_PIPES {
            self.writers.clear();
            self.readers.clear();
        }
        if let Some(n) = stdin_pipe {
            self.readers.insert(n, (key, ts_ns));
        }
        stdout_pipe.and_then(|n| {
            self.writers.insert(n, (key, ts_ns));
            self.readers
                .get(&n)
                .filter(|(r, _)| *r != key)
                .map(|(r, _)| *r)
        })
    }

    pub fn on_exit(&mut self, key: ProcKey, ts_ns: u64) {
        if let Some(p) = self.procs.get_mut(&key) {
            p.exited_ns = Some(ts_ns);
        }
    }

    /// The process for an event's key. Falls back to the newest process with that pid when the key is not known (the
    /// sensor fell back to `/proc` polling, which keys processes slightly differently), but only if it has not exited.
    pub fn get(&self, key: ProcKey) -> Option<&Proc> {
        if let Some(p) = self.procs.get(&key) {
            return Some(p);
        }
        let k = self.by_pid.get(&key.pid)?;
        self.procs.get(k).filter(|p| p.exited_ns.is_none())
    }

    pub fn exe(&self, key: ProcKey) -> Option<&Path> {
        self.get(key).map(|p| p.exe.as_path())
    }

    /// The executable writing into this process's stdin pipe, if the other end has been seen.
    pub fn stdin_writer_exe(&self, key: ProcKey) -> Option<&Path> {
        let n = self.get(key)?.stdio.first().and_then(|s| pipe_inode(s))?;
        let (w, _) = self.writers.get(&n)?;
        self.exe(*w)
    }

    /// The top of `key`'s process tree: walk up while the parent is known and is not a session program (`TREE_STOP`).
    pub fn tree_root(&self, key: ProcKey) -> ProcKey {
        let mut cur = key;
        for _ in 0..32 {
            let Some(p) = self.get(cur) else { break };
            let parent = p.parent;
            if parent.pid <= 1 {
                break;
            }
            match self.get(parent) {
                Some(pp)
                    if !TREE_STOP
                        .iter()
                        .any(|s| pp.exe.as_os_str().as_bytes() == s.as_bytes()) =>
                {
                    cur = parent
                }
                _ => break,
            }
        }
        cur
    }

    /// Executables above `key` (parent first), as far as the table knows them; at most 32 levels.
    pub fn ancestors(&self, key: ProcKey) -> Vec<&Path> {
        let mut out: Vec<&Path> = Vec::new();
        // the sensor's lineage covers ancestors that only forked (a script's subshells never exec, so no exec event
        // describes them): skip the ones the table does not know and keep going to the programs that did exec
        if let Some(p) = self.get(key) {
            for k in &p.lineage {
                if let Some(a) = self.get(*k) {
                    out.push(a.exe.as_path());
                }
            }
        }
        // logs from before the lineage field existed, and the /proc poller, only have parent links
        let mut cur = key;
        for _ in 0..32 {
            let Some(p) = self.get(cur) else { break };
            if p.parent.pid == 0 || p.parent == cur {
                break;
            }
            let Some(pp) = self.get(p.parent) else { break };
            if !out.contains(&pp.exe.as_path()) {
                out.push(pp.exe.as_path());
            }
            cur = p.parent;
        }
        out
    }

    /// Forget processes that exited more than two minutes before `now_ns`, and old pipe ends.
    pub fn sweep(&mut self, now_ns: u64) {
        let gone: Vec<ProcKey> = self
            .procs
            .iter()
            .filter(|(_, p)| {
                p.exited_ns
                    .is_some_and(|t| now_ns.saturating_sub(t) > KEEP_EXITED_NS)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in gone {
            self.procs.remove(&k);
            if self.by_pid.get(&k.pid) == Some(&k) {
                self.by_pid.remove(&k.pid);
            }
        }
        self.writers
            .retain(|_, (_, t)| now_ns.saturating_sub(*t) < PIPE_TTL_NS);
        self.readers
            .retain(|_, (_, t)| now_ns.saturating_sub(*t) < PIPE_TTL_NS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(pid: u32) -> ProcKey {
        ProcKey {
            pid,
            start_ns: u64::from(pid) * 10,
        }
    }

    fn proc(exe: &str, parent: u32, stdio: &[&str]) -> Proc {
        Proc {
            exe: PathBuf::from(exe),
            argv: vec![OsString::from(exe)],
            uid: 1000,
            parent: k(parent),
            stdio: stdio.iter().map(OsString::from).collect(),
            lineage: Vec::new(),
            exited_ns: None,
        }
    }

    #[test]
    fn pipes_pair_in_either_order() {
        let mut t = ProcTable::default();
        // sh first, curl second: the reader is handed back when the writer arrives
        assert_eq!(
            t.on_exec(
                k(10),
                proc("/usr/bin/sh", 5, &["pipe:[77]", "/dev/pts/0"]),
                1
            ),
            None
        );
        assert_eq!(t.stdin_writer_exe(k(10)), None);
        assert_eq!(
            t.on_exec(
                k(11),
                proc("/usr/bin/curl", 5, &["/dev/pts/0", "pipe:[77]"]),
                2
            ),
            Some(k(10))
        );
        assert_eq!(t.stdin_writer_exe(k(10)), Some(Path::new("/usr/bin/curl")));
        // curl first, sh second: known at once
        t.on_exec(k(20), proc("/usr/bin/wget", 5, &["", "pipe:[88]"]), 3);
        t.on_exec(k(21), proc("/usr/bin/bash", 5, &["pipe:[88]"]), 4);
        assert_eq!(t.stdin_writer_exe(k(21)), Some(Path::new("/usr/bin/wget")));
        assert_eq!(pipe_inode(OsStr::new("socket:[1]")), None);
    }

    #[test]
    fn trees_stop_at_session_programs() {
        let mut t = ProcTable::default();
        t.on_exec(k(2), proc("/usr/bin/fish", 1, &[]), 0);
        t.on_exec(k(3), proc("/home/u/evil", 2, &[]), 0);
        t.on_exec(k(4), proc("/home/u/evil", 3, &[]), 0);
        t.on_exec(k(5), proc("/home/u/evil", 4, &[]), 0);
        assert_eq!(t.tree_root(k(5)), k(3));
        assert_eq!(t.tree_root(k(3)), k(3));
        assert_eq!(
            t.tree_root(k(99)),
            k(99),
            "unknown processes are their own tree"
        );
    }

    #[test]
    fn ancestors_follow_the_sensors_lineage_across_subshells_that_never_exec() {
        let mut t = ProcTable::default();
        t.on_exec(k(10), proc("/usr/bin/pacman", 1, &[]), 0);
        t.on_exec(k(11), proc("/usr/bin/bash", 10, &[]), 0); // the hook script
                                                             // pid 12 and 13 are subshells: forked, never exec'd, so the table has no entry for them
        let mut leaf = proc("/usr/bin/bash", 13, &["socket:[9]"]);
        leaf.lineage = vec![k(13), k(12), k(11), k(10)];
        t.on_exec(k(14), leaf, 0);
        let names: Vec<_> = t
            .ancestors(k(14))
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["/usr/bin/bash", "/usr/bin/pacman"]);
        // without the lineage (an old log) the broken parent chain finds nothing
        let mut old = proc("/usr/bin/bash", 13, &[]);
        old.lineage = Vec::new();
        t.on_exec(k(15), old, 0);
        assert!(t.ancestors(k(15)).is_empty());
    }

    #[test]
    fn exited_processes_linger_then_go() {
        let mut t = ProcTable::default();
        t.on_exec(k(7), proc("/usr/bin/true", 1, &[]), 0);
        t.on_exit(k(7), 1_000);
        t.sweep(2_000);
        assert!(t.get(k(7)).is_some(), "late events still find it");
        t.sweep(1_000 + KEEP_EXITED_NS + 1);
        assert!(t.get(k(7)).is_none());
        // the pid fallback does not hand out an exited process under a new key
        t.on_exec(k(8), proc("/usr/bin/a", 1, &[]), 0);
        t.on_exit(k(8), 5);
        assert!(t
            .get(ProcKey {
                pid: 8,
                start_ns: 12345
            })
            .is_none());
    }
}
