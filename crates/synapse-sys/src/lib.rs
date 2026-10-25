//! Minimal fanotify bindings, plus pidfd and `SO_PEERCRED` wrappers for the responder (`process`, M4).
//!
//! This is the only crate in the workspace that contains `unsafe` code, and it
//! is kept tiny on purpose. Everything else (event parsing, reading, path
//! lookup) is safe Rust. Each `unsafe` block carries a `SAFETY:` comment and the
//! `undocumented_unsafe_blocks` lint is denied.
//!
//! Only what Synapse M1 needs is exposed: a notification-class fanotify group,
//! filesystem-wide marks, and parsing of the fixed-size event records. Kernel
//! constants are copied from `<linux/fanotify.h>`; they are stable UAPI.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub mod process;

/// `fanotify_init` flag: close-on-exec for the group descriptor.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
/// `fanotify_init` flag: reads return `EAGAIN` instead of blocking.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;
/// `fanotify_init` class: notification only (no permission events).
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
/// `fanotify_mark` flag: add the mask to the mark.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;
/// `fanotify_mark` flag: mark the whole filesystem (superblock), across all
/// mounts and mount namespaces.
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
/// Event: a file opened for writing was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// Event: the kernel event queue overflowed (events were lost).
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

const FANOTIFY_METADATA_VERSION: u8 = 3;
/// `sizeof(struct fanotify_event_metadata)`.
const METADATA_LEN: usize = 24;

/// One decoded fanotify event record.
#[derive(Debug)]
pub struct FanEvent {
    pub mask: u64,
    /// PID of the process that caused the event (as seen from our PID namespace).
    pub pid: i32,
    /// Open descriptor for the file, absent for queue-overflow records.
    /// Owned: dropping it closes the descriptor.
    pub fd: Option<OwnedFd>,
}

/// A fanotify notification group.
#[derive(Debug)]
pub struct Fanotify {
    file: File,
}

impl Fanotify {
    /// Create a non-blocking, close-on-exec notification group.
    /// Needs `CAP_SYS_ADMIN`.
    #[allow(unsafe_code)]
    pub fn init() -> io::Result<Fanotify> {
        let flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK;
        // Descriptors the kernel opens for each event: read-only, close-on-exec.
        let event_f_flags = (libc::O_RDONLY | libc::O_CLOEXEC) as libc::c_uint;
        // SAFETY: `fanotify_init` takes two plain integers and returns a new
        // file descriptor or -1; it reads no caller memory.
        let fd = unsafe { libc::fanotify_init(flags, event_f_flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Fanotify {
            file: File::from(adopt(fd)),
        })
    }

    /// Watch every file on the filesystem that contains `path` for `mask`.
    #[allow(unsafe_code)]
    pub fn mark_filesystem(&self, path: &Path, mask: u64) -> io::Result<()> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        // SAFETY: `self.file` keeps the group descriptor open for the whole
        // call, and `c_path` is a valid NUL-terminated string that outlives it.
        // `path` is absolute in practice; `AT_FDCWD` only matters for relative
        // paths.
        let rc = unsafe {
            libc::fanotify_mark(
                self.file.as_raw_fd(),
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read and decode pending events into `buf`'s capacity.
    ///
    /// Returns `ErrorKind::WouldBlock` when nothing is pending.
    pub fn read_events(&self, buf: &mut [u8]) -> io::Result<Vec<FanEvent>> {
        let n = (&self.file).read(buf)?;
        parse_events(buf.get(..n).unwrap_or(&[]))
    }
}

/// Wait until `fd` has data to read, or `timeout_ms` milliseconds pass.
/// Returns `Ok(true)` when it is readable (or the peer hung up, so a following
/// read reports the end or the error), `Ok(false)` on timeout or interruption.
///
/// Used by the eBPF sensor to sleep on the ring buffer without busy-polling.
#[allow(unsafe_code)]
pub fn wait_readable<F: AsRawFd>(fd: &F, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is one valid, initialised `pollfd` that lives for the whole
    // call, and `nfds` is 1 to match. `fd` is borrowed, so it stays open.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(err)
        };
    }
    if pfd.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not open",
        ));
    }
    Ok(rc > 0)
}

/// Take ownership of a descriptor the kernel just handed to this process.
#[allow(unsafe_code)]
fn adopt(fd: RawFd) -> OwnedFd {
    // SAFETY: callers pass a descriptor that was freshly created for this
    // process (the result of `fanotify_init` or an event record) and that
    // nothing else owns or will close, so taking sole ownership is sound.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

/// Decode a buffer of back-to-back `fanotify_event_metadata` records.
///
/// A malformed record aborts parsing with `InvalidData`; descriptors already
/// decoded in the same call are closed when the partial result is dropped.
pub fn parse_events(buf: &[u8]) -> io::Result<Vec<FanEvent>> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let rest = buf.get(offset..).unwrap_or(&[]);
        let event_len = field::<4>(rest, 0)
            .map(u32::from_ne_bytes)
            .ok_or_else(|| bad("truncated fanotify record"))?;
        let version = *rest
            .get(4)
            .ok_or_else(|| bad("truncated fanotify record"))?;
        let metadata_len = field::<2>(rest, 6)
            .map(u16::from_ne_bytes)
            .ok_or_else(|| bad("truncated fanotify record"))?;
        let mask = field::<8>(rest, 8)
            .map(u64::from_ne_bytes)
            .ok_or_else(|| bad("truncated fanotify record"))?;
        let fd = field::<4>(rest, 16)
            .map(i32::from_ne_bytes)
            .ok_or_else(|| bad("truncated fanotify record"))?;
        let pid = field::<4>(rest, 20)
            .map(i32::from_ne_bytes)
            .ok_or_else(|| bad("truncated fanotify record"))?;

        if version != FANOTIFY_METADATA_VERSION {
            return Err(bad("unsupported fanotify metadata version"));
        }
        let event_len = usize::try_from(event_len).map_err(|_| bad("oversized fanotify record"))?;
        let metadata_len = usize::from(metadata_len);
        if metadata_len < METADATA_LEN || event_len < metadata_len || event_len > rest.len() {
            return Err(bad("inconsistent fanotify record length"));
        }

        // Take ownership of the descriptor last, after every check that could
        // reject the record, so a bad record never leaks it.
        let fd = if fd >= 0 { Some(adopt(fd)) } else { None };
        events.push(FanEvent { mask, pid, fd });
        offset += event_len;
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    fn record(mask: u64, fd: i32, pid: i32, extra: usize) -> Vec<u8> {
        let len = u32::try_from(METADATA_LEN + extra).unwrap();
        let mut v = Vec::new();
        v.extend(len.to_ne_bytes());
        v.push(FANOTIFY_METADATA_VERSION);
        v.push(0);
        v.extend(u16::try_from(METADATA_LEN).unwrap().to_ne_bytes());
        v.extend(mask.to_ne_bytes());
        v.extend(fd.to_ne_bytes());
        v.extend(pid.to_ne_bytes());
        v.extend(vec![0u8; extra]);
        v
    }

    #[test]
    fn parses_back_to_back_records_without_descriptors() {
        let mut buf = record(FAN_Q_OVERFLOW, -1, 0, 0);
        buf.extend(record(FAN_CLOSE_WRITE, -1, 4242, 0));
        let events = parse_events(&buf).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].mask, FAN_Q_OVERFLOW);
        assert!(events[0].fd.is_none());
        assert_eq!(events[1].mask, FAN_CLOSE_WRITE);
        assert_eq!(events[1].pid, 4242);
    }

    #[test]
    fn adopts_a_real_descriptor_and_closes_it_on_drop() {
        let raw = File::open("/dev/null").unwrap().into_raw_fd();
        let buf = record(FAN_CLOSE_WRITE, raw, 7, 0);
        let events = parse_events(&buf).unwrap();
        let owned = events[0].fd.as_ref().unwrap();
        assert_eq!(owned.as_raw_fd(), raw);
    }

    #[test]
    fn skips_trailing_info_records() {
        let mut buf = record(FAN_CLOSE_WRITE, -1, 1, 16);
        buf.extend(record(FAN_CLOSE_WRITE, -1, 2, 0));
        let events = parse_events(&buf).unwrap();
        assert_eq!(events.iter().map(|e| e.pid).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn rejects_truncated_buffers() {
        let buf = record(FAN_CLOSE_WRITE, -1, 1, 0);
        for cut in [1, 4, 10, METADATA_LEN - 1] {
            assert!(parse_events(&buf[..cut]).is_err(), "cut at {cut}");
        }
        // Declared length longer than the data we have.
        let mut long = record(FAN_CLOSE_WRITE, -1, 1, 8);
        long.truncate(METADATA_LEN + 2);
        assert!(parse_events(&long).is_err());
    }

    #[test]
    fn rejects_wrong_version_and_zero_length() {
        let mut buf = record(FAN_CLOSE_WRITE, -1, 1, 0);
        buf[4] = 2;
        assert!(parse_events(&buf).is_err());

        let mut zero = record(FAN_CLOSE_WRITE, -1, 1, 0);
        zero[..4].copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_events(&zero).is_err());
    }

    #[test]
    fn wait_readable_times_out_then_sees_data() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (a, mut b) = UnixStream::pair().unwrap();
        assert!(!wait_readable(&a, 10).unwrap());
        b.write_all(b"x").unwrap();
        assert!(wait_readable(&a, 1000).unwrap());
    }

    #[test]
    fn empty_buffer_is_no_events() {
        assert!(parse_events(&[]).unwrap().is_empty());
    }
}
