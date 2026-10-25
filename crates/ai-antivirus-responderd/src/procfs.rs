//! The live facts the responder checks before it touches a process: identity (start time), parent, session, kernel
//! thread flag, executable and cgroup. Read from `/proc` (a fake root in tests) at the moment of acting, never taken from
//! the alert, because the alert may be minutes old.

use std::fs;
use std::path::{Path, PathBuf};

use ai_antivirus_common::event::ProcKey;

/// `/proc/<pid>/stat` times are in ticks of `USER_HZ` (100 on every Linux architecture Arch supports).
const NS_PER_TICK: u64 = 10_000_000;
/// A `ProcKey` start time and the `/proc` start time this close are the same process (the sensor uses the same figure:
/// `/proc` has 10 ms resolution and an eBPF key may come from the fork timestamp).
pub const START_TOLERANCE_NS: u64 = 50_000_000;
/// `PF_KTHREAD` in the `flags` field of `stat`.
const PF_KTHREAD: u64 = 0x0020_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProc {
    pub pid: u32,
    pub ppid: u32,
    pub sid: u32,
    pub start_ns: u64,
    pub kernel_thread: bool,
    /// `None` for kernel threads and when the link cannot be read.
    pub exe: Option<PathBuf>,
    /// cgroup v2 path (the `0::` line), e.g. `/user.slice/user-1000.slice/session-2.scope`.
    pub cgroup: String,
}

impl LiveProc {
    /// Is this the process `key` names (and not a later one that reused the PID)?
    pub fn is(&self, key: ProcKey) -> bool {
        self.pid == key.pid
            && key.start_ns != 0
            && self.start_ns.abs_diff(key.start_ns) <= START_TOLERANCE_NS
    }
}

/// `/proc` or a fake tree with the same layout.
#[derive(Debug, Clone)]
pub struct ProcFs {
    root: PathBuf,
}

/// The fields of one `stat` line the responder uses: (ppid, session, flags, start ticks).
fn parse_stat(text: &str) -> Option<(u32, u32, u64, u64)> {
    // `comm` is in parentheses and may contain anything, so split after the last `)`
    let close = text.rfind(')')?;
    let f: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    let ppid = f.get(1)?.parse().ok()?;
    let sid = f.get(3)?.parse().ok()?;
    let flags = f.get(6)?.parse().ok()?;
    let start = f.get(19)?.parse().ok()?;
    Some((ppid, sid, flags, start))
}

impl ProcFs {
    pub fn new(root: impl Into<PathBuf>) -> ProcFs {
        ProcFs { root: root.into() }
    }

    pub fn system() -> ProcFs {
        ProcFs::new("/proc")
    }

    fn dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    pub fn get(&self, pid: u32) -> Option<LiveProc> {
        let dir = self.dir(pid);
        let stat = fs::read(dir.join("stat")).ok()?;
        let (ppid, sid, flags, ticks) = parse_stat(&String::from_utf8_lossy(&stat))?;
        let kernel_thread = flags & PF_KTHREAD != 0 || pid == 2 || ppid == 2;
        let exe = if kernel_thread {
            None
        } else {
            fs::read_link(dir.join("exe")).ok()
        };
        let cgroup = fs::read_to_string(dir.join("cgroup"))
            .ok()
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("0::"))
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Some(LiveProc {
            pid,
            ppid,
            sid,
            start_ns: ticks.saturating_mul(NS_PER_TICK),
            kernel_thread,
            exe,
            cgroup,
        })
    }

    /// The live process `key` names, or `None` when it is gone or its PID now belongs to another process.
    pub fn resolve(&self, key: ProcKey) -> Option<LiveProc> {
        self.get(key.pid).filter(|p| p.is(key))
    }

    /// Every PID on the system (numeric directory names).
    pub fn pids(&self) -> Vec<u32> {
        let Ok(rd) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect()
    }

    /// `pid` and all its descendants, parents before children. Bounded so a fork bomb cannot stall the responder.
    pub fn tree(&self, pid: u32, max: usize) -> Vec<LiveProc> {
        let all: Vec<LiveProc> = self
            .pids()
            .into_iter()
            .filter_map(|p| self.get(p))
            .collect();
        let mut out: Vec<LiveProc> = all.iter().filter(|p| p.pid == pid).cloned().collect();
        let mut i = 0;
        while i < out.len() && out.len() < max {
            let parent = out[i].pid;
            for p in all.iter().filter(|p| p.ppid == parent && p.pid != parent) {
                if out.len() >= max {
                    break;
                }
                if !out.iter().any(|o| o.pid == p.pid) {
                    out.push(p.clone());
                }
            }
            i += 1;
        }
        out
    }

    /// The executables of `pid`'s ancestors, nearest first (stops at PID 1 or after 64 steps).
    pub fn ancestor_exes(&self, pid: u32) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut cur = self.get(pid).map(|p| p.ppid);
        while let Some(ppid) = cur {
            if ppid <= 1 || out.len() >= 64 {
                break;
            }
            let Some(p) = self.get(ppid) else { break };
            if let Some(exe) = &p.exe {
                out.push(exe.clone());
            }
            cur = Some(p.ppid);
        }
        out
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
pub mod fake {
    //! A fake `/proc` for tests.
    use super::*;

    /// One `stat` line. `start_ticks` is in 10 ms ticks.
    pub fn stat_line(
        pid: u32,
        comm: &str,
        ppid: u32,
        sid: u32,
        flags: u64,
        start_ticks: u64,
    ) -> String {
        // fields 3..=21 then starttime (22) and a few more
        format!(
            "{pid} ({comm}) S {ppid} {pid} {sid} 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 {start_ticks} 0 0\n"
        )
    }

    pub struct FakeProc {
        pub dir: tempfile::TempDir,
    }

    impl Default for FakeProc {
        fn default() -> FakeProc {
            FakeProc::new()
        }
    }

    impl FakeProc {
        pub fn new() -> FakeProc {
            FakeProc {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        pub fn fs(&self) -> ProcFs {
            ProcFs::new(self.dir.path())
        }

        /// Add a process. `exe` becomes a symlink (it need not exist).
        pub fn add(
            &self,
            pid: u32,
            ppid: u32,
            sid: u32,
            start_ticks: u64,
            exe: &str,
            cgroup: &str,
        ) {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                stat_line(pid, "x", ppid, sid, 0, start_ticks),
            )
            .unwrap();
            if !exe.is_empty() {
                std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
            }
            fs::write(d.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        }

        pub fn add_kthread(&self, pid: u32) {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                stat_line(pid, "kworker/0:1", 2, 0, PF_KTHREAD, 5),
            )
            .unwrap();
        }

        pub fn remove(&self, pid: u32) {
            fs::remove_dir_all(self.dir.path().join(pid.to_string())).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeProc;
    use super::*;

    #[test]
    fn parses_stat_with_odd_comm() {
        let line = fake::stat_line(42, "a) b (c", 7, 40, 0x40, 123);
        assert_eq!(parse_stat(&line), Some((7, 40, 0x40, 123)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn identity_tree_and_ancestors() {
        let f = FakeProc::new();
        f.add(1, 0, 1, 1, "/usr/lib/systemd/systemd", "/init.scope");
        f.add(100, 1, 100, 500, "/usr/bin/bash", "/user.slice/s.scope");
        f.add(
            101,
            100,
            100,
            600,
            "/usr/bin/python3",
            "/user.slice/s.scope",
        );
        f.add(102, 101, 100, 700, "/usr/bin/sh", "/user.slice/s.scope");
        f.add(200, 1, 200, 800, "/usr/bin/other", "/user.slice/o.scope");
        f.add_kthread(3);
        let fs = f.fs();

        let p = fs.get(101).unwrap();
        assert_eq!((p.ppid, p.sid, p.start_ns), (100, 100, 6_000_000_000));
        assert_eq!(p.cgroup, "/user.slice/s.scope");
        assert!(p.is(ProcKey {
            pid: 101,
            start_ns: 6_000_000_000 + 20_000_000
        }));
        assert!(
            !p.is(ProcKey {
                pid: 101,
                start_ns: 7_000_000_000
            }),
            "reused pid"
        );
        assert!(
            !p.is(ProcKey {
                pid: 101,
                start_ns: 0
            }),
            "unknown start is never trusted"
        );
        assert!(fs.get(3).unwrap().kernel_thread);
        assert!(fs.get(3).unwrap().exe.is_none());

        let tree: Vec<u32> = fs.tree(100, 100).iter().map(|p| p.pid).collect();
        assert_eq!(tree, [100, 101, 102]);
        assert_eq!(fs.tree(100, 2).len(), 2, "bounded");
        assert_eq!(
            fs.ancestor_exes(102),
            [
                PathBuf::from("/usr/bin/python3"),
                PathBuf::from("/usr/bin/bash")
            ]
        );
        f.remove(101);
        assert!(fs
            .resolve(ProcKey {
                pid: 101,
                start_ns: 6_000_000_000
            })
            .is_none());
    }

    #[test]
    fn reads_the_real_proc_for_ourselves() {
        let fs = ProcFs::system();
        let me = fs.get(std::process::id()).unwrap();
        assert!(!me.kernel_thread);
        assert!(me.exe.is_some());
    }
}
