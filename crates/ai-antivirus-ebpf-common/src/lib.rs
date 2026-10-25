//! Wire format between the kernel-side eBPF programs and `ai-antivirus-sensord`.
//!
//! The kernel side fills these `#[repr(C)]` structs in a BPF ring buffer; the
//! sensor decodes the raw bytes with the safe functions in this crate. Decoding
//! uses `offset_of!` positions taken from the very same struct definitions, so
//! the two sides cannot drift apart, and the tests pin every size.
//!
//! Rules for this file:
//! * Only `u8`/`u16`/`u32`/`u64`/`i32` fields and byte arrays, with explicit
//!   padding fields, so the layout has no hidden padding.
//! * All multi-byte values are in the machine's native byte order (the kernel
//!   and the sensor run on the same machine).
//! * No `unsafe`, no allocation: the crate is `no_std` outside of tests.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::mem::offset_of;

/// Record kinds: the first `u32` of every ring-buffer record.
pub const KIND_FORK: u32 = 1;
pub const KIND_EXEC: u32 = 2;
pub const KIND_EXIT: u32 = 3;
pub const KIND_CONNECT: u32 = 4;

/// Bytes of the path given to `execve` that are kept (including the NUL).
pub const FILENAME_MAX: usize = 256;
/// Bytes of the NUL-separated argument block that are kept. Power of two.
pub const ARGV_MAX: usize = 4096;
/// Most bytes copied for one argument (including its NUL).
pub const ARG_CHUNK: usize = 512;
/// Most arguments read from one `execve` call.
pub const MAX_ARGS: u32 = 32;
/// Size of the scratch/stash buffer: `ARGV_MAX` plus room for one last chunk,
/// so a copy that starts below `ARGV_MAX` can never run off the end.
pub const ARGV_BLOB_LEN: usize = ARGV_MAX + ARG_CHUNK;

/// `ExecRecord::flags`: the argument block was captured at `execve` entry.
pub const EXEC_FLAG_ARGV: u32 = 1;
/// `ExecRecord::flags`: arguments were cut (too many, too long, or unreadable).
pub const EXEC_FLAG_ARGV_TRUNCATED: u32 = 2;
/// `ExecRecord::flags`: the file name did not fit in `FILENAME_MAX`.
pub const EXEC_FLAG_FILENAME_TRUNCATED: u32 = 4;

/// `ExitRecord::flags`: `code` holds the `exit_group` status.
pub const EXIT_FLAG_HAS_CODE: u32 = 1;

/// `ConnectRecord::proto`
pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

/// Linux address families that are reported.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// A process was forked (or a thread was created: the kernel does not say).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkRecord {
    pub kind: u32,
    /// Thread id of the forking thread.
    pub parent_tid: u32,
    /// Process (thread group) id of the forking process.
    pub parent_tgid: u32,
    /// Id of the new task. For a process this is also its process id.
    pub child_pid: u32,
    /// `CLOCK_BOOTTIME` at the event, in nanoseconds.
    pub ts_boot_ns: u64,
}

/// A process finished `execve`.
#[repr(C)]
pub struct ExecRecord {
    pub kind: u32,
    /// Process id after the exec.
    pub tgid: u32,
    /// Thread id of the calling thread before the exec (differs from `tgid`
    /// only when a non-leader thread called `execve`).
    pub old_tid: u32,
    /// Real user id.
    pub uid: u32,
    pub ts_boot_ns: u64,
    pub flags: u32,
    pub argc: u32,
    /// Valid bytes in `filename`, including the NUL if present.
    pub filename_len: u32,
    /// Valid bytes in `argv`.
    pub argv_len: u32,
    /// The path exactly as given to `execve` (may be relative).
    pub filename: [u8; FILENAME_MAX],
    /// NUL-separated arguments, like `/proc/<pid>/cmdline`.
    pub argv: [u8; ARGV_MAX],
}

/// A process (thread group leader) exited.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitRecord {
    pub kind: u32,
    pub tgid: u32,
    pub tid: u32,
    pub flags: u32,
    /// Low 8 bits of the `exit_group` argument; meaningful only with
    /// `EXIT_FLAG_HAS_CODE`.
    pub code: i32,
    pub _pad: u32,
    pub ts_boot_ns: u64,
}

/// A process called `connect` on an IPv4 or IPv6 socket.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRecord {
    pub kind: u32,
    pub tgid: u32,
    pub tid: u32,
    pub uid: u32,
    pub ts_boot_ns: u64,
    pub family: u16,
    pub proto: u8,
    pub _pad1: u8,
    /// Destination port in host byte order.
    pub port: u16,
    pub _pad2: u16,
    /// IPv4: the four address bytes then zeros. IPv6: all sixteen bytes.
    pub addr: [u8; 16],
}

/// Scratch and stash value for the `execve` argument block.
#[repr(C)]
pub struct ArgvBlob {
    /// Valid bytes in `data`, at most `ARGV_MAX`.
    pub len: u32,
    pub argc: u32,
    pub flags: u32,
    pub _pad: u32,
    pub data: [u8; ARGV_BLOB_LEN],
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the record kind needs.
    Truncated,
    /// The first word is not a known record kind.
    UnknownKind(u32),
}

/// A decoded exec record borrowing the filename and argument bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecView<'a> {
    pub tgid: u32,
    pub old_tid: u32,
    pub uid: u32,
    pub ts_boot_ns: u64,
    pub flags: u32,
    pub argc: u32,
    /// The file name up to (not including) the first NUL.
    pub filename: &'a [u8],
    /// The argument block, `argv_len` bytes, clamped to what the record holds.
    pub argv: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    Fork(ForkRecord),
    Exec(ExecView<'a>),
    Exit(ExitRecord),
    Connect(ConnectRecord),
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_ne_bytes(b.get(at..end)?.try_into().ok()?))
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_ne_bytes(b.get(at..end)?.try_into().ok()?))
}

fn read_i32(b: &[u8], at: usize) -> Option<i32> {
    read_u32(b, at).map(|v| i32::from_ne_bytes(v.to_ne_bytes()))
}

fn read_u64(b: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_ne_bytes(b.get(at..end)?.try_into().ok()?))
}

fn decode_fork(b: &[u8]) -> Option<ForkRecord> {
    Some(ForkRecord {
        kind: KIND_FORK,
        parent_tid: read_u32(b, offset_of!(ForkRecord, parent_tid))?,
        parent_tgid: read_u32(b, offset_of!(ForkRecord, parent_tgid))?,
        child_pid: read_u32(b, offset_of!(ForkRecord, child_pid))?,
        ts_boot_ns: read_u64(b, offset_of!(ForkRecord, ts_boot_ns))?,
    })
}

fn decode_exit(b: &[u8]) -> Option<ExitRecord> {
    Some(ExitRecord {
        kind: KIND_EXIT,
        tgid: read_u32(b, offset_of!(ExitRecord, tgid))?,
        tid: read_u32(b, offset_of!(ExitRecord, tid))?,
        flags: read_u32(b, offset_of!(ExitRecord, flags))?,
        code: read_i32(b, offset_of!(ExitRecord, code))?,
        _pad: 0,
        ts_boot_ns: read_u64(b, offset_of!(ExitRecord, ts_boot_ns))?,
    })
}

fn decode_connect(b: &[u8]) -> Option<ConnectRecord> {
    let at = offset_of!(ConnectRecord, addr);
    let addr: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(ConnectRecord {
        kind: KIND_CONNECT,
        tgid: read_u32(b, offset_of!(ConnectRecord, tgid))?,
        tid: read_u32(b, offset_of!(ConnectRecord, tid))?,
        uid: read_u32(b, offset_of!(ConnectRecord, uid))?,
        ts_boot_ns: read_u64(b, offset_of!(ConnectRecord, ts_boot_ns))?,
        family: read_u16(b, offset_of!(ConnectRecord, family))?,
        proto: *b.get(offset_of!(ConnectRecord, proto))?,
        _pad1: 0,
        port: read_u16(b, offset_of!(ConnectRecord, port))?,
        _pad2: 0,
        addr,
    })
}

fn decode_exec(b: &[u8]) -> Option<ExecView<'_>> {
    let name_at = offset_of!(ExecRecord, filename);
    let argv_at = offset_of!(ExecRecord, argv);
    let name_len = usize::try_from(read_u32(b, offset_of!(ExecRecord, filename_len))?).ok()?;
    let argv_len = usize::try_from(read_u32(b, offset_of!(ExecRecord, argv_len))?).ok()?;
    let name_len = name_len.min(FILENAME_MAX);
    let argv_len = argv_len.min(ARGV_MAX);
    let name_all = b.get(name_at..name_at + name_len)?;
    // `filename_len` includes the NUL; the name ends at the first NUL anyway.
    let name_end = name_all.iter().position(|c| *c == 0).unwrap_or(name_len);
    Some(ExecView {
        tgid: read_u32(b, offset_of!(ExecRecord, tgid))?,
        old_tid: read_u32(b, offset_of!(ExecRecord, old_tid))?,
        uid: read_u32(b, offset_of!(ExecRecord, uid))?,
        ts_boot_ns: read_u64(b, offset_of!(ExecRecord, ts_boot_ns))?,
        flags: read_u32(b, offset_of!(ExecRecord, flags))?,
        argc: read_u32(b, offset_of!(ExecRecord, argc))?,
        filename: name_all.get(..name_end)?,
        argv: b.get(argv_at..argv_at + argv_len)?,
    })
}

impl<'a> Record<'a> {
    /// Decode one ring-buffer record. Never panics, whatever the input.
    pub fn decode(bytes: &'a [u8]) -> Result<Record<'a>, DecodeError> {
        let kind = read_u32(bytes, 0).ok_or(DecodeError::Truncated)?;
        let decoded = match kind {
            KIND_FORK => decode_fork(bytes).map(Record::Fork),
            KIND_EXEC => decode_exec(bytes).map(Record::Exec),
            KIND_EXIT => decode_exit(bytes).map(Record::Exit),
            KIND_CONNECT => decode_connect(bytes).map(Record::Connect),
            other => return Err(DecodeError::UnknownKind(other)),
        };
        decoded.ok_or(DecodeError::Truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn sizes_are_pinned_and_have_no_hidden_padding() {
        assert_eq!(size_of::<ForkRecord>(), 24);
        assert_eq!(size_of::<ExitRecord>(), 32);
        assert_eq!(size_of::<ConnectRecord>(), 48);
        assert_eq!(size_of::<ExecRecord>(), 40 + FILENAME_MAX + ARGV_MAX);
        assert_eq!(size_of::<ArgvBlob>(), 16 + ARGV_BLOB_LEN);
        for align in [
            align_of::<ForkRecord>(),
            align_of::<ExitRecord>(),
            align_of::<ConnectRecord>(),
            align_of::<ExecRecord>(),
        ] {
            assert_eq!(align, 8);
        }
        assert!(ARGV_MAX.is_power_of_two());
    }

    #[test]
    fn exec_blob_fields_sit_where_the_kernel_expects() {
        assert_eq!(offset_of!(ExecRecord, filename), 40);
        assert_eq!(offset_of!(ExecRecord, argv), 40 + FILENAME_MAX);
        assert_eq!(offset_of!(ArgvBlob, data), 16);
    }

    fn put32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }

    fn put64(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_ne_bytes());
    }

    fn fork_bytes() -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ForkRecord>()];
        put32(&mut b, 0, KIND_FORK);
        put32(&mut b, offset_of!(ForkRecord, parent_tid), 11);
        put32(&mut b, offset_of!(ForkRecord, parent_tgid), 10);
        put32(&mut b, offset_of!(ForkRecord, child_pid), 12);
        put64(&mut b, offset_of!(ForkRecord, ts_boot_ns), 5_000_000_000);
        b
    }

    fn exec_bytes(name: &[u8], argv: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ExecRecord>()];
        put32(&mut b, 0, KIND_EXEC);
        put32(&mut b, offset_of!(ExecRecord, tgid), 100);
        put32(&mut b, offset_of!(ExecRecord, old_tid), 101);
        put32(&mut b, offset_of!(ExecRecord, uid), 1000);
        put64(&mut b, offset_of!(ExecRecord, ts_boot_ns), 7);
        put32(&mut b, offset_of!(ExecRecord, flags), EXEC_FLAG_ARGV);
        put32(&mut b, offset_of!(ExecRecord, argc), 2);
        put32(
            &mut b,
            offset_of!(ExecRecord, filename_len),
            u32::try_from(name.len() + 1).unwrap(),
        );
        put32(
            &mut b,
            offset_of!(ExecRecord, argv_len),
            u32::try_from(argv.len()).unwrap(),
        );
        let n = offset_of!(ExecRecord, filename);
        b[n..n + name.len()].copy_from_slice(name);
        let a = offset_of!(ExecRecord, argv);
        b[a..a + argv.len()].copy_from_slice(argv);
        b
    }

    #[test]
    fn fork_round_trips() {
        let bytes = fork_bytes();
        let rec = Record::decode(&bytes).unwrap();
        assert_eq!(
            rec,
            Record::Fork(ForkRecord {
                kind: KIND_FORK,
                parent_tid: 11,
                parent_tgid: 10,
                child_pid: 12,
                ts_boot_ns: 5_000_000_000
            })
        );
    }

    #[test]
    fn exec_borrows_name_and_argv() {
        let bytes = exec_bytes(b"/usr/bin/ls", b"ls\0-l\0");
        let Record::Exec(view) = Record::decode(&bytes).unwrap() else {
            panic!("not an exec record");
        };
        assert_eq!(view.tgid, 100);
        assert_eq!(view.old_tid, 101);
        assert_eq!(view.uid, 1000);
        assert_eq!(view.filename, b"/usr/bin/ls");
        assert_eq!(view.argv, b"ls\0-l\0");
        assert_eq!(view.argc, 2);
        assert_eq!(view.flags & EXEC_FLAG_ARGV, EXEC_FLAG_ARGV);
    }

    #[test]
    fn exec_lengths_are_clamped_not_trusted() {
        let mut bytes = exec_bytes(b"x", b"x\0");
        put32(&mut bytes, offset_of!(ExecRecord, filename_len), u32::MAX);
        put32(&mut bytes, offset_of!(ExecRecord, argv_len), u32::MAX);
        let Record::Exec(view) = Record::decode(&bytes).unwrap() else {
            panic!("not an exec record");
        };
        assert_eq!(view.filename, b"x");
        assert_eq!(view.argv.len(), ARGV_MAX);
    }

    #[test]
    fn exit_and_connect_round_trip() {
        let mut b = vec![0u8; size_of::<ExitRecord>()];
        put32(&mut b, 0, KIND_EXIT);
        put32(&mut b, offset_of!(ExitRecord, tgid), 5);
        put32(&mut b, offset_of!(ExitRecord, tid), 5);
        put32(&mut b, offset_of!(ExitRecord, flags), EXIT_FLAG_HAS_CODE);
        put32(&mut b, offset_of!(ExitRecord, code), 3);
        put64(&mut b, offset_of!(ExitRecord, ts_boot_ns), 9);
        let Record::Exit(e) = Record::decode(&b).unwrap() else {
            panic!("not an exit record");
        };
        assert_eq!((e.tgid, e.code, e.ts_boot_ns), (5, 3, 9));

        let mut c = vec![0u8; size_of::<ConnectRecord>()];
        put32(&mut c, 0, KIND_CONNECT);
        put32(&mut c, offset_of!(ConnectRecord, tgid), 8);
        c[offset_of!(ConnectRecord, family)..][..2].copy_from_slice(&AF_INET.to_ne_bytes());
        c[offset_of!(ConnectRecord, proto)] = PROTO_UDP;
        c[offset_of!(ConnectRecord, port)..][..2].copy_from_slice(&53u16.to_ne_bytes());
        c[offset_of!(ConnectRecord, addr)..][..4].copy_from_slice(&[1, 1, 1, 1]);
        let Record::Connect(r) = Record::decode(&c).unwrap() else {
            panic!("not a connect record");
        };
        assert_eq!(
            (r.tgid, r.family, r.proto, r.port),
            (8, AF_INET, PROTO_UDP, 53)
        );
        assert_eq!(&r.addr[..4], &[1, 1, 1, 1]);
    }

    #[test]
    fn short_and_unknown_records_are_errors_never_panics() {
        assert_eq!(Record::decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(Record::decode(&[1, 0]), Err(DecodeError::Truncated));
        let full = fork_bytes();
        for cut in 0..full.len() {
            assert!(Record::decode(&full[..cut]).is_err(), "cut at {cut}");
        }
        let mut unknown = vec![0u8; 64];
        put32(&mut unknown, 0, 99);
        assert_eq!(Record::decode(&unknown), Err(DecodeError::UnknownKind(99)));
        let exec = exec_bytes(b"a", b"a\0");
        for cut in [0, 4, 39, 40, 41, 295, 296, 297] {
            assert!(Record::decode(&exec[..cut]).is_err(), "exec cut at {cut}");
        }
    }
}
