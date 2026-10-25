//! The sensor's view of running processes: identity (`ProcKey`) and parentage.
//!
//! Why this exists: the eBPF programs cannot read a process's start time or its
//! parent from the kernel (that needs `task_struct` offsets, which are not
//! portable across Arch kernels). They report what is stable instead: fork
//! edges (`parent -> child pid`, with a boot-clock timestamp), execs, exits and
//! connects. This table turns those into `ProcKey`s and `parent` links, and
//! gives the fanotify sensor the same keys, so one process has one identity in
//! the whole event stream.
//!
//! Identity rules (all keys are by process id = thread group id):
//! * A key is made **lazily**, the first time an event needs it, and never
//!   changes afterwards. Most forks (shell subprocesses, threads) never need
//!   one, so they cost one small map insert and no `/proc` read.
//! * Preferred source: `/proc/<pid>/stat` start time, accepted only if it is
//!   consistent with the fork timestamp (same process, not a reused PID).
//! * Fallback, when the process is already gone: the fork timestamp rounded
//!   down to a clock tick, which is how `/proc` reports start times.
//!
//! The kernel does not say whether a fork created a process or a thread, so
//! thread creations leave harmless entries in the fork map. It is bounded and
//! evicts the oldest half when full.
//!
//! Exited processes stay in a bounded "tombstone" map so a child that is
//! `exec`ed after its parent already exited (double fork, daemons) still gets
//! the right `parent` key.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use synapse_common::event::ProcKey;

use crate::procinfo::{self, StatInfo};

/// Most fork edges remembered at once.
const FORK_CAP: usize = 32_768;
/// Most exited processes remembered for parent lookups.
const EXITED_CAP: usize = 4_096;
/// Two start times this close (nanoseconds) are the same process: `/proc` has
/// 10 ms resolution, and the fork timestamp is taken a little after the start.
const TOLERANCE_NS: u64 = 50_000_000;
/// `/proc` start times are whole clock ticks.
const TICK_NS: u64 = 1_000_000_000 / procinfo::USER_HZ;
const MAX_CMDLINE_BYTES: u64 = 64 * 1024;

/// Read-only access to `/proc`, so tests can use a fake.
pub trait ProcFs: Send {
    fn stat(&self, pid: u32) -> Option<StatInfo>;
    fn exe(&self, pid: u32) -> Option<PathBuf>;
    fn cwd(&self, pid: u32) -> Option<PathBuf>;
    fn cgroup(&self, pid: u32) -> String;
    fn cmdline(&self, pid: u32) -> Vec<OsString>;
    /// Every numeric directory in the proc root.
    fn pids(&self) -> io::Result<Vec<u32>>;
}

/// The real `/proc` (or another root, for tests that build a fake tree).
#[derive(Debug, Clone)]
pub struct RealProcFs {
    root: PathBuf,
}

impl RealProcFs {
    pub fn new(root: impl Into<PathBuf>) -> RealProcFs {
        RealProcFs { root: root.into() }
    }

    fn dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }
}

impl ProcFs for RealProcFs {
    fn stat(&self, pid: u32) -> Option<StatInfo> {
        procinfo::read_stat(&self.root, pid)
    }

    fn exe(&self, pid: u32) -> Option<PathBuf> {
        fs::read_link(self.dir(pid).join("exe")).ok()
    }

    fn cwd(&self, pid: u32) -> Option<PathBuf> {
        fs::read_link(self.dir(pid).join("cwd")).ok()
    }

    fn cgroup(&self, pid: u32) -> String {
        fs::read(self.dir(pid).join("cgroup"))
            .map(|bytes| procinfo::parse_cgroup(&String::from_utf8_lossy(&bytes)))
            .unwrap_or_default()
    }

    fn cmdline(&self, pid: u32) -> Vec<OsString> {
        let Ok(file) = fs::File::open(self.dir(pid).join("cmdline")) else {
            return Vec::new();
        };
        let mut bytes = Vec::new();
        match file.take(MAX_CMDLINE_BYTES).read_to_end(&mut bytes) {
            Ok(_) => procinfo::parse_cmdline(&bytes),
            Err(_) => Vec::new(),
        }
    }

    fn pids(&self) -> io::Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let Ok(entry) = entry else { continue };
            if let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: ProcKey,
    parent_pid: u32,
    /// An `Exec` was reported (or it was running at start-up), so its `Exit`
    /// must be reported too. Same rule as the M1 poller.
    reported: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForkEdge {
    parent_tgid: u32,
    ts_ns: u64,
    seq: u64,
}

#[derive(Debug, Clone, Copy)]
struct Exited {
    key: ProcKey,
    parent_pid: u32,
    seq: u64,
}

/// `ProcTable` shared between the eBPF consumer and the fanotify thread.
pub type SharedTable = Arc<Mutex<ProcTable>>;

/// Lock a shared table. A poisoned lock (a panic elsewhere) is recovered: the
/// table only holds caches that heal themselves.
pub fn lock(table: &SharedTable) -> MutexGuard<'_, ProcTable> {
    table.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct ProcTable {
    fs: Box<dyn ProcFs>,
    entries: HashMap<u32, Entry>,
    forks: HashMap<u32, ForkEdge>,
    exited: HashMap<u32, Exited>,
    seq: u64,
}

fn floor_tick(ns: u64) -> u64 {
    ns - ns % TICK_NS
}

fn is_kernel_thread(pid: u32, ppid: u32) -> bool {
    pid == 2 || ppid == 2
}

impl ProcTable {
    pub fn new(fs: Box<dyn ProcFs>) -> ProcTable {
        ProcTable {
            fs,
            entries: HashMap::new(),
            forks: HashMap::new(),
            exited: HashMap::new(),
            seq: 0,
        }
    }

    /// The `/proc` access this table uses, for callers that need more facts.
    pub fn fs(&self) -> &dyn ProcFs {
        &*self.fs
    }

    /// Number of live processes tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record every running process. Returns how many were found. Existing
    /// processes are marked as reported so their `Exit` is reported later,
    /// matching the M1 poller. Kernel threads are tracked but never reported.
    pub fn baseline(&mut self) -> io::Result<usize> {
        let mut found = 0usize;
        for pid in self.fs.pids()? {
            let Some(stat) = self.fs.stat(pid) else {
                continue;
            };
            let key = ProcKey {
                pid,
                start_ns: procinfo::start_ns(stat.start_ticks),
            };
            self.entries.insert(
                pid,
                Entry {
                    key,
                    parent_pid: stat.ppid,
                    reported: !is_kernel_thread(pid, stat.ppid),
                },
            );
            found += 1;
        }
        Ok(found)
    }

    /// A fork (or thread creation) by `parent_tgid` of task `child_pid`, at
    /// boot-clock time `ts_ns`.
    pub fn on_fork(&mut self, parent_tgid: u32, child_pid: u32, ts_ns: u64) {
        self.seq += 1;
        if self.forks.len() >= FORK_CAP {
            let floor = self.seq.saturating_sub((FORK_CAP / 2) as u64);
            self.forks.retain(|_, edge| edge.seq > floor);
            if self.forks.len() >= FORK_CAP {
                self.forks.clear();
            }
        }
        self.forks.insert(
            child_pid,
            ForkEdge {
                parent_tgid,
                ts_ns,
                seq: self.seq,
            },
        );
    }

    /// The key of process `pid`, creating its entry if there is enough to go on.
    /// `event_ts_ns` is the boot-clock time of the event being handled, when
    /// known; a `/proc` process that started after it is a reused PID.
    fn ensure(&mut self, pid: u32, event_ts_ns: Option<u64>) -> Option<ProcKey> {
        if let Some(entry) = self.entries.get(&pid) {
            return Some(entry.key);
        }
        let edge = self.forks.remove(&pid);
        let from_edge = |edge: Option<ForkEdge>| {
            edge.map(|e| {
                (
                    ProcKey {
                        pid,
                        start_ns: floor_tick(e.ts_ns),
                    },
                    e.parent_tgid,
                )
            })
        };
        let (key, parent_pid) = match self.fs.stat(pid) {
            Some(stat) => {
                let start = procinfo::start_ns(stat.start_ticks);
                let reused = event_ts_ns.is_some_and(|ts| start > ts.saturating_add(TOLERANCE_NS));
                if reused {
                    from_edge(edge)?
                } else {
                    let parent = match edge {
                        Some(e) if e.ts_ns.abs_diff(start) <= TOLERANCE_NS => e.parent_tgid,
                        _ => stat.ppid,
                    };
                    (ProcKey { pid, start_ns: start }, parent)
                }
            }
            None => from_edge(edge)?,
        };
        self.entries.insert(
            pid,
            Entry {
                key,
                parent_pid,
                reported: false,
            },
        );
        Some(key)
    }

    /// The key to use for events of process `pid`. Never creates an entry for a
    /// process nothing is known about; that gets `start_ns = 0`, the same
    /// "already gone" marker the M1 sensors use.
    pub fn resolve(&mut self, pid: u32, event_ts_ns: Option<u64>) -> ProcKey {
        self.ensure(pid, event_ts_ns)
            .unwrap_or(ProcKey { pid, start_ns: 0 })
    }

    fn parent_key(&self, ppid: u32) -> ProcKey {
        if ppid == 0 {
            return ProcKey { pid: 0, start_ns: 0 };
        }
        if let Some(entry) = self.entries.get(&ppid) {
            return entry.key;
        }
        if let Some(gone) = self.exited.get(&ppid) {
            return gone.key;
        }
        ProcKey {
            pid: ppid,
            start_ns: self
                .fs
                .stat(ppid)
                .map_or(0, |stat| procinfo::start_ns(stat.start_ticks)),
        }
    }

    /// `pid` finished an `execve` at `ts_ns`. Returns its key and its parent's,
    /// and marks it so its exit will be reported.
    pub fn on_exec(&mut self, pid: u32, ts_ns: u64) -> (ProcKey, ProcKey) {
        let key = self.resolve(pid, Some(ts_ns));
        let parent_pid = match self.entries.get_mut(&pid) {
            Some(entry) => {
                entry.reported = true;
                entry.parent_pid
            }
            None => 0,
        };
        (key, self.parent_key(parent_pid))
    }

    /// Task `tid` of process `tgid` exited. Returns the key to report an `Exit`
    /// for, or `None` if nothing should be reported (a thread, or a process
    /// that was never reported as started).
    pub fn on_exit(&mut self, tgid: u32, tid: u32) -> Option<ProcKey> {
        if tid != tgid {
            self.forks.remove(&tid);
            return None;
        }
        self.forks.remove(&tgid);
        let entry = self.entries.remove(&tgid)?;
        self.bury(tgid, entry);
        entry.reported.then_some(entry.key)
    }

    fn bury(&mut self, pid: u32, entry: Entry) {
        self.seq += 1;
        if self.exited.len() >= EXITED_CAP {
            let floor = self.seq.saturating_sub((EXITED_CAP / 2) as u64);
            self.exited.retain(|_, gone| gone.seq > floor);
            if self.exited.len() >= EXITED_CAP {
                self.exited.clear();
            }
        }
        self.exited.insert(
            pid,
            Exited {
                key: entry.key,
                parent_pid: entry.parent_pid,
                seq: self.seq,
            },
        );
    }

    /// Ancestors of `pid`, nearest first, at most `max` of them. Uses only what
    /// the table knows (live and recently exited processes) and stops at the
    /// first unknown or repeated process.
    pub fn ancestry(&self, pid: u32, max: usize) -> Vec<ProcKey> {
        let mut chain = Vec::new();
        let mut current = match self.entries.get(&pid) {
            Some(entry) => entry.parent_pid,
            None => return chain,
        };
        while chain.len() < max && current != 0 {
            let (key, next) = match (self.entries.get(&current), self.exited.get(&current)) {
                (Some(entry), _) => (entry.key, entry.parent_pid),
                (None, Some(gone)) => (gone.key, gone.parent_pid),
                (None, None) => break,
            };
            if chain.contains(&key) {
                break;
            }
            chain.push(key);
            current = next;
        }
        chain
    }

    /// Forget processes that are gone or replaced (their exit event was lost,
    /// for example because the ring buffer overflowed). Call now and then.
    /// Returns how many were removed.
    pub fn sweep(&mut self) -> usize {
        let stale: Vec<u32> = self
            .entries
            .iter()
            .filter(|(pid, entry)| match self.fs.stat(**pid) {
                Some(stat) => {
                    procinfo::start_ns(stat.start_ticks).abs_diff(entry.key.start_ns)
                        > TOLERANCE_NS
                        && entry.key.start_ns != 0
                }
                None => true,
            })
            .map(|(pid, _)| *pid)
            .collect();
        for pid in &stale {
            if let Some(entry) = self.entries.remove(pid) {
                self.bury(*pid, entry);
            }
        }
        stale.len()
    }
}

/// A fake `/proc` the test can change after handing it to a table.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    #[derive(Clone, Default)]
    pub struct FakeProc {
        pub stat: Option<StatInfo>,
        pub exe: Option<PathBuf>,
        pub cwd: Option<PathBuf>,
        pub cgroup: String,
        pub cmdline: Vec<OsString>,
    }

    #[derive(Clone, Default)]
    pub struct FakeFs(pub Arc<Mutex<HashMap<u32, FakeProc>>>);

    impl FakeFs {
        pub fn set(&self, pid: u32, ppid: u32, start_ticks: u64) {
            let mut map = self.0.lock().unwrap();
            map.entry(pid).or_default().stat = Some(StatInfo { ppid, start_ticks });
        }

        pub fn details(&self, pid: u32, exe: &str, cwd: &str, cgroup: &str, argv: &[&str]) {
            let mut map = self.0.lock().unwrap();
            let p = map.entry(pid).or_default();
            p.exe = Some(PathBuf::from(exe));
            p.cwd = Some(PathBuf::from(cwd));
            p.cgroup = cgroup.to_owned();
            p.cmdline = argv.iter().map(OsString::from).collect();
        }

        pub fn remove(&self, pid: u32) {
            self.0.lock().unwrap().remove(&pid);
        }
    }

    impl ProcFs for FakeFs {
        fn stat(&self, pid: u32) -> Option<StatInfo> {
            self.0.lock().unwrap().get(&pid).and_then(|p| p.stat)
        }
        fn exe(&self, pid: u32) -> Option<PathBuf> {
            self.0.lock().unwrap().get(&pid).and_then(|p| p.exe.clone())
        }
        fn cwd(&self, pid: u32) -> Option<PathBuf> {
            self.0.lock().unwrap().get(&pid).and_then(|p| p.cwd.clone())
        }
        fn cgroup(&self, pid: u32) -> String {
            self.0
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.cgroup.clone())
                .unwrap_or_default()
        }
        fn cmdline(&self, pid: u32) -> Vec<OsString> {
            self.0
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.cmdline.clone())
                .unwrap_or_default()
        }
        fn pids(&self) -> io::Result<Vec<u32>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, p)| p.stat.is_some())
                .map(|(pid, _)| *pid)
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeFs;
    use super::*;

    fn table() -> (ProcTable, FakeFs) {
        let fake = FakeFs::default();
        (ProcTable::new(Box::new(fake.clone())), fake)
    }

    fn key(pid: u32, start_ns: u64) -> ProcKey {
        ProcKey { pid, start_ns }
    }

    // 500 ticks = 5 s since boot.
    const T5: u64 = 5_000_000_000;

    #[test]
    fn baseline_reports_exit_of_normal_processes_but_not_kernel_threads() {
        let (mut t, fake) = table();
        fake.set(1, 0, 10);
        fake.set(2, 0, 10); // kthreadd
        fake.set(7, 2, 11); // a kernel thread
        fake.set(100, 1, 20);
        assert_eq!(t.baseline().unwrap(), 4);
        assert_eq!(t.on_exit(100, 100), Some(key(100, 200_000_000)));
        assert_eq!(t.on_exit(7, 7), None);
        assert_eq!(t.on_exit(2, 2), None);
    }

    #[test]
    fn fork_then_exec_uses_proc_when_consistent_and_the_fork_parent() {
        let (mut t, fake) = table();
        fake.set(10, 1, 400);
        t.baseline().unwrap();
        // Child 20 forked by 10 at 5.003 s; /proc says it started at 500 ticks.
        t.on_fork(10, 20, T5 + 3_000_000);
        fake.set(20, 999, 500); // /proc ppid is wrong on purpose: the edge wins
        let (me, parent) = t.on_exec(20, T5 + 4_000_000);
        assert_eq!(me, key(20, T5));
        assert_eq!(parent, key(10, 4_000_000_000));
        // The key never changes afterwards.
        assert_eq!(t.resolve(20, None), me);
        assert_eq!(t.on_exit(20, 20), Some(me));
        assert_eq!(t.on_exit(20, 20), None, "second exit reports nothing");
    }

    #[test]
    fn a_process_already_gone_gets_its_key_from_the_fork_timestamp() {
        let (mut t, fake) = table();
        fake.set(10, 1, 400);
        t.baseline().unwrap();
        t.on_fork(10, 30, T5 + 7_300_000); // rounds down to the 5.00 s tick
        let (me, parent) = t.on_exec(30, T5 + 9_000_000);
        assert_eq!(me, key(30, T5));
        assert_eq!(parent.pid, 10);
    }

    #[test]
    fn a_reused_pid_in_proc_is_not_mistaken_for_the_process() {
        let (mut t, fake) = table();
        t.on_fork(10, 40, T5);
        // The process 40 we care about exited; /proc now shows a newer one.
        fake.set(40, 1, 900); // starts at 9 s, after the 5 s event
        let me = t.resolve(40, Some(T5 + 1_000_000));
        assert_eq!(me, key(40, T5));
    }

    #[test]
    fn a_stale_fork_edge_does_not_override_proc() {
        let (mut t, fake) = table();
        t.on_fork(77, 50, 1_000_000_000); // an older, unrelated task 50
        fake.set(50, 5, 800); // the live process 50 started at 8 s
        let (me, parent) = t.on_exec(50, 8_100_000_000);
        assert_eq!(me, key(50, 8_000_000_000));
        assert_eq!(parent.pid, 5, "parent comes from /proc, not the stale edge");
    }

    #[test]
    fn unknown_processes_get_start_zero_and_no_entry() {
        let (mut t, _fake) = table();
        assert_eq!(t.resolve(999, None), key(999, 0));
        assert!(t.is_empty());
    }

    #[test]
    fn thread_exit_only_drops_its_fork_edge() {
        let (mut t, fake) = table();
        fake.set(10, 1, 400);
        t.baseline().unwrap();
        t.on_fork(10, 61, T5);
        assert_eq!(t.on_exit(10, 61), None);
        // The edge is gone, so a later lookup of 61 knows nothing.
        assert_eq!(t.resolve(61, None), key(61, 0));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn exit_of_a_process_never_reported_is_silent() {
        let (mut t, fake) = table();
        fake.set(70, 1, 500);
        // Resolved (say, by a file write) but never exec'd: not "reported".
        assert_eq!(t.resolve(70, None), key(70, T5));
        assert_eq!(t.on_exit(70, 70), None);
        assert_eq!(t.on_exit(71, 71), None);
    }

    #[test]
    fn parent_key_survives_the_parent_exiting_first() {
        let (mut t, fake) = table();
        fake.set(10, 1, 400);
        t.baseline().unwrap();
        t.on_fork(10, 80, T5);
        fake.set(80, 10, 500);
        assert!(t.on_exit(10, 10).is_some());
        fake.remove(10);
        let (_, parent) = t.on_exec(80, T5 + 1_000_000);
        assert_eq!(parent, key(10, 4_000_000_000));
    }

    #[test]
    fn ancestry_walks_live_and_exited_parents_and_stops() {
        let (mut t, fake) = table();
        fake.set(1, 0, 10);
        fake.set(10, 1, 400);
        t.baseline().unwrap();
        t.on_fork(10, 20, T5);
        fake.set(20, 10, 500);
        t.on_exec(20, T5);
        t.on_fork(20, 30, T5 + 100_000_000);
        fake.set(30, 20, 510);
        t.on_exec(30, T5 + 100_000_000);

        let chain: Vec<u32> = t.ancestry(30, 10).iter().map(|k| k.pid).collect();
        assert_eq!(chain, vec![20, 10, 1]);
        assert_eq!(t.ancestry(30, 2).len(), 2);
        assert!(t.ancestry(12345, 5).is_empty());

        t.on_exit(20, 20);
        let chain: Vec<u32> = t.ancestry(30, 10).iter().map(|k| k.pid).collect();
        assert_eq!(chain, vec![20, 10, 1], "tombstones keep the chain intact");
    }

    #[test]
    fn sweep_forgets_vanished_and_replaced_processes() {
        let (mut t, fake) = table();
        fake.set(10, 1, 400);
        fake.set(11, 1, 401);
        fake.set(12, 1, 402);
        t.baseline().unwrap();
        fake.remove(10);
        fake.set(11, 1, 9000); // pid reused by a new process
        assert_eq!(t.sweep(), 2);
        assert_eq!(t.len(), 1);
        assert_eq!(t.sweep(), 0);
    }

    #[test]
    fn the_fork_map_stays_bounded() {
        let (mut t, _fake) = table();
        for i in 0..(FORK_CAP as u32 * 3) {
            t.on_fork(1, 1000 + i, u64::from(i));
        }
        assert!(t.forks.len() <= FORK_CAP);
        // Recent edges survive eviction.
        let newest = 1000 + FORK_CAP as u32 * 3 - 1;
        assert!(t.forks.contains_key(&newest));
    }

    #[test]
    fn the_tombstone_map_stays_bounded() {
        let (mut t, fake) = table();
        for pid in 100..(100 + EXITED_CAP as u32 * 2) {
            fake.set(pid, 1, 100);
        }
        t.baseline().unwrap();
        for pid in 100..(100 + EXITED_CAP as u32 * 2) {
            t.on_exit(pid, pid);
        }
        assert!(t.exited.len() <= EXITED_CAP);
    }

    #[test]
    fn real_proc_fs_reads_this_process() {
        let fs = RealProcFs::new("/proc");
        let pid = std::process::id();
        assert!(fs.stat(pid).is_some());
        assert!(fs.exe(pid).is_some());
        assert!(fs.pids().unwrap().contains(&pid));
        assert!(!fs.cmdline(pid).is_empty());
    }
}
