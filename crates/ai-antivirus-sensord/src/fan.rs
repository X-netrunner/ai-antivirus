//! fanotify file-write sensor: the M1 source of `FileWrite` events.
//!
//! Scope of M1: notification-class events only (`FAN_CLOSE_WRITE`), reported
//! with the writing process, path and size. Create/delete/rename events need
//! fanotify's FID mode and permission events need a scanner; both come in
//! later milestones.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ai_antivirus_common::entropy;
use ai_antivirus_common::event::{Event, ProcKey};
use ai_antivirus_sys::{FanEvent, Fanotify, FAN_CLOSE_WRITE, FAN_Q_OVERFLOW};
use tracing::{error, warn};

use crate::procinfo;
use crate::proctree::{lock, SharedTable};
use crate::sink::Sink;

/// Identical (process, path) writes within this window are reported once.
const COALESCE_WINDOW: Duration = Duration::from_secs(1);
/// Upper bound on remembered (process, path) pairs.
const COALESCE_MAX_ENTRIES: usize = 4096;
/// How long to sleep when the kernel queue is empty.
const IDLE_SLEEP: Duration = Duration::from_millis(25);
const READ_BUF_BYTES: usize = 64 * 1024;

/// Turns raw fanotify records into `FileWrite` events.
pub struct Handler {
    own_pid: u32,
    exclude: Vec<PathBuf>,
    proc_root: PathBuf,
    recent: HashMap<(u32, PathBuf), Instant>,
    sink: Sink,
    /// When the eBPF sensor runs, process identities come from its table so a
    /// file write and the process's `exec` carry the same `ProcKey`.
    table: Option<SharedTable>,
}

impl Handler {
    pub fn new(own_pid: u32, exclude: Vec<PathBuf>, sink: Sink) -> Handler {
        Handler {
            own_pid,
            exclude,
            proc_root: PathBuf::from("/proc"),
            recent: HashMap::new(),
            sink,
            table: None,
        }
    }

    /// Resolve process identities through the shared process table.
    pub fn with_table(mut self, table: SharedTable) -> Handler {
        self.table = Some(table);
        self
    }

    /// The identity of process `pid`. `start_ns` 0 means it was already gone.
    fn proc_key(&self, pid: u32) -> ProcKey {
        if let Some(table) = &self.table {
            return lock(table).resolve(pid, None);
        }
        let start_ns = procinfo::read_stat(&self.proc_root, pid)
            .map_or(0, |stat| procinfo::start_ns(stat.start_ticks));
        ProcKey { pid, start_ns }
    }

    /// Process one record. Always consumes (and so closes) its descriptor.
    pub fn handle(&mut self, event: FanEvent, now: Instant) {
        if event.mask & FAN_Q_OVERFLOW != 0 {
            // The kernel does not say how many events were lost; count one.
            self.sink.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if event.mask & FAN_CLOSE_WRITE == 0 {
            return;
        }
        let Some(fd) = event.fd else { return };
        let Ok(pid) = u32::try_from(event.pid) else {
            return;
        };
        // Never report our own writes: the event log would feed itself.
        if pid == self.own_pid {
            return;
        }
        let Some(path) = path_of(&fd) else { return };
        if self.exclude.iter().any(|prefix| path.starts_with(prefix)) {
            return;
        }
        if self.is_repeat(pid, &path, now) {
            self.sink.stats.coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let file = File::from(fd);
        let size = file.metadata().map_or(0, |meta| meta.len());
        let head_entropy = head_entropy(&file);
        let proc = self.proc_key(pid);
        self.sink.send(Event::FileWrite {
            proc,
            path,
            size,
            sha256: None,
            head_entropy,
        });
    }

    /// True if the same process wrote the same path within the window.
    /// Otherwise remembers it and returns false.
    fn is_repeat(&mut self, pid: u32, path: &Path, now: Instant) -> bool {
        if self.recent.len() >= COALESCE_MAX_ENTRIES {
            self.recent
                .retain(|_, seen| now.saturating_duration_since(*seen) < COALESCE_WINDOW);
            if self.recent.len() >= COALESCE_MAX_ENTRIES {
                self.recent.clear();
            }
        }
        let key = (pid, path.to_path_buf());
        if let Some(seen) = self.recent.get(&key) {
            if now.saturating_duration_since(*seen) < COALESCE_WINDOW {
                return true;
            }
        }
        self.recent.insert(key, now);
        false
    }
}

/// Entropy of the first 4 KiB, read through the event's own descriptor (the kernel opened it read-only for us), so no path
/// lookup races with a rename.
fn head_entropy(file: &File) -> Option<u16> {
    let mut buf = [0u8; entropy::SAMPLE_BYTES];
    let n = file.read_at(&mut buf, 0).ok()?;
    entropy::shannon_milli(&buf[..n])
}

/// Resolve an event descriptor to the file's path via `/proc/self/fd`.
/// Deleted files come back with a ` (deleted)` suffix, which is kept: it is
/// itself a useful signal.
fn path_of(fd: &OwnedFd) -> Option<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
}

/// Read events until `shutdown` is set or the descriptor fails. Clears
/// `stats.fan_alive` on the way out so health reports the sensor as down.
pub fn run(fan: &Fanotify, mut handler: Handler, shutdown: &AtomicBool) {
    let mut buf = vec![0u8; READ_BUF_BYTES];
    while !shutdown.load(Ordering::Relaxed) {
        match fan.read_events(&mut buf) {
            Ok(events) => {
                let now = Instant::now();
                for event in events {
                    handler.handle(event, now);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(IDLE_SLEEP),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                error!(error = %e, "fanotify read failed; file events are no longer collected");
                break;
            }
        }
    }
    handler.sink.stats.fan_alive.store(false, Ordering::Relaxed);
}

/// Create the group and mark each configured filesystem. Returns `None`
/// (after logging why) when fanotify cannot be used, so the daemon keeps
/// running on `/proc` polling alone.
pub fn setup(marks: &[PathBuf]) -> Option<Fanotify> {
    let fan = match Fanotify::init() {
        Ok(fan) => fan,
        Err(e) => {
            warn!(
                error = %e,
                "fanotify unavailable (it needs CAP_SYS_ADMIN); file events are disabled"
            );
            return None;
        }
    };
    let mut marked = 0usize;
    for path in marks {
        match fan.mark_filesystem(path, FAN_CLOSE_WRITE) {
            Ok(()) => marked += 1,
            Err(e) => warn!(path = %path.display(), error = %e, "cannot watch filesystem"),
        }
    }
    if marked == 0 {
        warn!("no filesystem could be marked; file events are disabled");
        return None;
    }
    Some(fan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    use crate::sink::Stamped;

    fn close_write(fd: OwnedFd, pid: i32) -> FanEvent {
        FanEvent {
            mask: FAN_CLOSE_WRITE,
            pid,
            fd: Some(fd),
        }
    }

    fn open_file(dir: &Path, name: &str, content: &[u8]) -> (PathBuf, OwnedFd) {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        let fd = OwnedFd::from(File::open(&path).unwrap());
        (fs::canonicalize(&path).unwrap(), fd)
    }

    fn drain(rx: &Receiver<Stamped>) -> Vec<Event> {
        rx.try_iter().map(|(_, event)| event).collect()
    }

    // PID 1 always exists on Linux, so the process lookup has something to find.
    const OTHER_PID: i32 = 1;

    #[test]
    fn reports_a_write_with_path_size_and_process() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, rx) = Sink::channel(16);
        let mut handler = Handler::new(std::process::id(), Vec::new(), sink);

        let (path, fd) = open_file(dir.path(), "a.txt", b"hello");
        handler.handle(close_write(fd, OTHER_PID), Instant::now());

        let events = drain(&rx);
        let [Event::FileWrite {
            proc,
            path: got,
            size,
            sha256,
            head_entropy,
        }] = events.as_slice()
        else {
            panic!("expected one FileWrite, got {events:?}");
        };
        assert_eq!(proc.pid, 1);
        assert_eq!(*got, path);
        assert_eq!(*size, 5);
        assert!(sha256.is_none());
        assert!(head_entropy.is_none(), "5 bytes are too few for a figure");
    }

    #[test]
    fn own_writes_are_never_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, rx) = Sink::channel(16);
        let own = std::process::id();
        let mut handler = Handler::new(own, Vec::new(), sink);

        let (_, fd) = open_file(dir.path(), "mine.txt", b"x");
        handler.handle(close_write(fd, i32::try_from(own).unwrap()), Instant::now());
        assert!(drain(&rx).is_empty());
    }

    #[test]
    fn excluded_prefixes_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let excluded = fs::canonicalize(dir.path()).unwrap().join("journal");
        fs::create_dir_all(&excluded).unwrap();
        let (sink, rx) = Sink::channel(16);
        let mut handler = Handler::new(std::process::id(), vec![excluded.clone()], sink);

        let (_, fd) = open_file(&excluded, "skip.log", b"x");
        handler.handle(close_write(fd, OTHER_PID), Instant::now());
        let (_, fd) = open_file(dir.path(), "keep.log", b"x");
        handler.handle(close_write(fd, OTHER_PID), Instant::now());

        let events = drain(&rx);
        assert_eq!(events.len(), 1, "{events:?}");
    }

    #[test]
    fn repeated_writes_are_coalesced_within_the_window_only() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, rx) = Sink::channel(16);
        let stats = sink.stats.clone();
        let mut handler = Handler::new(std::process::id(), Vec::new(), sink);
        let t0 = Instant::now();

        for offset_ms in [0, 200, 400] {
            let (_, fd) = open_file(dir.path(), "busy.db", b"x");
            handler.handle(
                close_write(fd, OTHER_PID),
                t0 + Duration::from_millis(offset_ms),
            );
        }
        assert_eq!(drain(&rx).len(), 1);
        assert_eq!(stats.coalesced.load(Ordering::Relaxed), 2);

        let (_, fd) = open_file(dir.path(), "busy.db", b"x");
        handler.handle(close_write(fd, OTHER_PID), t0 + Duration::from_secs(5));
        assert_eq!(drain(&rx).len(), 1, "window expired, so report again");
    }

    #[test]
    fn queue_overflow_counts_as_dropped_and_other_masks_are_ignored() {
        let (sink, rx) = Sink::channel(16);
        let stats = sink.stats.clone();
        let mut handler = Handler::new(std::process::id(), Vec::new(), sink);

        handler.handle(
            FanEvent {
                mask: FAN_Q_OVERFLOW,
                pid: 0,
                fd: None,
            },
            Instant::now(),
        );
        handler.handle(
            FanEvent {
                mask: 0x1, // FAN_ACCESS: not requested, must be ignored
                pid: OTHER_PID,
                fd: None,
            },
            Instant::now(),
        );
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 1);
        assert!(drain(&rx).is_empty());
    }

    #[test]
    fn the_coalescing_table_stays_bounded() {
        let (sink, _rx) = Sink::channel(1);
        let mut handler = Handler::new(0, Vec::new(), sink);
        let now = Instant::now();
        for i in 0..(COALESCE_MAX_ENTRIES * 2) {
            handler.is_repeat(1, Path::new(&format!("/tmp/file-{i}")), now);
        }
        assert!(handler.recent.len() <= COALESCE_MAX_ENTRIES);
    }
}
