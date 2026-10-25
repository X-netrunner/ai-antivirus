//! `/proc` process poller: the M1 source of `Exec` and `Exit` events.
//!
//! Limits (by design, fixed by the eBPF sensor in M2):
//! * A process that starts and exits between two scans is never seen.
//! * Exit codes are not observable by polling, so `Exit` carries
//!   [`UNKNOWN_EXIT_CODE`].
//! * `Exec` describes the process as found at scan time, which for a fork
//!   that has not yet exec'd is the pre-exec image.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use synapse_common::event::{Event, ProcKey};

use crate::procinfo::{self, Probe};

/// `Event::Exit::code` value meaning "the poller cannot know".
pub const UNKNOWN_EXIT_CODE: i32 = -1;

/// A tracked process and whether an `Exec` was reported for it (kernel
/// threads are tracked but never reported, so they never produce `Exit`).
type Tracked = (ProcKey, bool);

#[derive(Debug)]
pub struct Poller {
    root: PathBuf,
    known: HashMap<u32, Tracked>,
}

impl Poller {
    /// A poller reading from `root` (normally `/proc`).
    pub fn new(root: impl Into<PathBuf>) -> Poller {
        Poller {
            root: root.into(),
            known: HashMap::new(),
        }
    }

    /// Record every running process without reporting it. Call once at
    /// startup so existing processes do not flood the log as "new".
    /// Returns the number of processes seen.
    pub fn baseline(&mut self) -> io::Result<usize> {
        self.scan()?;
        Ok(self.known.len())
    }

    /// Compare `/proc` with the previous scan. `Exit` events come first
    /// (so a reused PID shows exit-then-exec), then `Exec` events.
    pub fn scan(&mut self) -> io::Result<Vec<Event>> {
        let mut current: HashMap<u32, Tracked> = HashMap::with_capacity(self.known.len() + 16);
        let mut execs = Vec::new();

        for entry in fs::read_dir(&self.root)? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(stat) = procinfo::read_stat(&self.root, pid) else {
                continue;
            };
            let key = ProcKey {
                pid,
                start_ns: procinfo::start_ns(stat.start_ticks),
            };

            if let Some(previous) = self.known.get(&pid) {
                if previous.0 == key {
                    current.insert(pid, *previous);
                    continue;
                }
            }

            match procinfo::probe(&self.root, pid, &stat) {
                Probe::Process(info) => {
                    let parent = self.parent_key(info.ppid, &current);
                    execs.push(Event::Exec {
                        proc: info.key,
                        parent,
                        uid: info.uid,
                        exe: info.exe,
                        argv: info.argv,
                        cwd: info.cwd,
                        cgroup: info.cgroup,
                    });
                    current.insert(pid, (key, true));
                }
                Probe::KernelThread => {
                    current.insert(pid, (key, false));
                }
                Probe::Gone => {}
            }
        }

        let mut events = Vec::new();
        for (pid, (key, reported)) in &self.known {
            let still_running = current.get(pid).map(|tracked| tracked.0) == Some(*key);
            if *reported && !still_running {
                events.push(Event::Exit {
                    proc: *key,
                    code: UNKNOWN_EXIT_CODE,
                });
            }
        }
        events.extend(execs);
        self.known = current;
        Ok(events)
    }

    fn parent_key(&self, ppid: u32, current: &HashMap<u32, Tracked>) -> ProcKey {
        if ppid == 0 {
            return ProcKey {
                pid: 0,
                start_ns: 0,
            };
        }
        if let Some((key, _)) = current.get(&ppid).or_else(|| self.known.get(&ppid)) {
            return *key;
        }
        ProcKey {
            pid: ppid,
            start_ns: procinfo::read_stat(&self.root, ppid)
                .map_or(0, |stat| procinfo::start_ns(stat.start_ticks)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procinfo::testing::stat_line;
    use std::ffi::OsString;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::Command;

    fn make_proc(root: &Path, pid: u32, comm: &str, ppid: u32, start: u64, cmdline: &[u8]) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat_line(pid, comm, ppid, start)).unwrap();
        fs::write(dir.join("cmdline"), cmdline).unwrap();
        fs::write(dir.join("cgroup"), "0::/user.slice/app.service\n").unwrap();
        symlink(format!("/usr/bin/{comm}"), dir.join("exe")).unwrap();
        symlink("/tmp", dir.join("cwd")).unwrap();
    }

    fn exec_pids(events: &[Event]) -> Vec<u32> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Exec { proc, .. } => Some(proc.pid),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn reports_new_processes_and_their_exit_from_a_fake_proc() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut poller = Poller::new(root);
        assert!(poller.scan().unwrap().is_empty());

        make_proc(root, 42, "foo", 1, 500, b"foo\0--bar\0");
        // Things the poller must ignore:
        make_proc(root, 7, "kworker", 2, 10, b""); // kernel thread
        fs::create_dir_all(root.join("self")).unwrap(); // non-numeric
        fs::create_dir_all(root.join("99")).unwrap(); // no stat file

        let events = poller.scan().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        let Event::Exec {
            proc,
            parent,
            exe,
            argv,
            cwd,
            cgroup,
            ..
        } = &events[0]
        else {
            panic!("expected Exec, got {:?}", events[0]);
        };
        assert_eq!(
            *proc,
            ProcKey {
                pid: 42,
                start_ns: 5_000_000_000
            }
        );
        assert_eq!(parent.pid, 1);
        assert_eq!(exe, Path::new("/usr/bin/foo"));
        assert_eq!(
            argv,
            &vec![OsString::from("foo"), OsString::from("--bar")]
        );
        assert_eq!(cwd, Path::new("/tmp"));
        assert_eq!(cgroup, "/user.slice/app.service");

        // Unchanged /proc: nothing new.
        assert!(poller.scan().unwrap().is_empty());

        fs::remove_dir_all(root.join("42")).unwrap();
        fs::remove_dir_all(root.join("7")).unwrap();
        let events = poller.scan().unwrap();
        assert_eq!(
            events,
            vec![Event::Exit {
                proc: *proc,
                code: UNKNOWN_EXIT_CODE
            }]
        );
    }

    #[test]
    fn baseline_hides_existing_processes_but_still_reports_their_exit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        make_proc(root, 10, "old", 1, 100, b"old\0");
        let mut poller = Poller::new(root);
        assert_eq!(poller.baseline().unwrap(), 1);
        assert!(poller.scan().unwrap().is_empty());

        fs::remove_dir_all(root.join("10")).unwrap();
        let events = poller.scan().unwrap();
        assert!(matches!(events.as_slice(), [Event::Exit { proc, .. }] if proc.pid == 10));
    }

    #[test]
    fn a_reused_pid_is_exit_then_exec() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        make_proc(root, 20, "first", 1, 100, b"first\0");
        let mut poller = Poller::new(root);
        poller.baseline().unwrap();

        fs::remove_dir_all(root.join("20")).unwrap();
        make_proc(root, 20, "second", 1, 900, b"second\0");
        let events = poller.scan().unwrap();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(matches!(&events[0], Event::Exit { proc, .. } if proc.start_ns == 1_000_000_000));
        assert!(matches!(&events[1], Event::Exec { proc, .. } if proc.start_ns == 9_000_000_000));
    }

    #[test]
    fn missing_proc_root_is_an_error() {
        let mut poller = Poller::new("/definitely/not/a/proc");
        assert!(poller.scan().is_err());
    }

    #[test]
    fn sees_a_real_child_process_start_and_exit() {
        let mut poller = Poller::new("/proc");
        poller.baseline().unwrap();

        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let events = poller.scan().unwrap();
        let exec = events.iter().find_map(|e| match e {
            Event::Exec {
                proc,
                parent,
                argv,
                exe,
                ..
            } if proc.pid == pid => Some((*proc, *parent, argv.clone(), exe.clone())),
            _ => None,
        });
        let (key, parent, argv, exe) = exec.expect("no Exec event for the child");
        assert_eq!(parent.pid, std::process::id());
        assert_eq!(argv, vec![OsString::from("sleep"), OsString::from("30")]);
        assert_eq!(exe.file_name(), Some(std::ffi::OsStr::new("sleep")));
        assert_ne!(key.start_ns, 0);

        child.kill().unwrap();
        child.wait().unwrap();
        let events = poller.scan().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Exit { proc, .. } if *proc == key)),
            "no Exit event for the child: {events:?}"
        );
        assert!(exec_pids(&events).iter().all(|p| *p != pid));
    }
}
