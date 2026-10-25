//! AI Antivirus kernel-side eBPF programs (M2).
//!
//! Design rules (spec section 5.1: "keep the kernel side tiny: collect and
//! filter, no policy"):
//!
//! * **No `task_struct` access.** Rust cannot emit CO-RE relocations yet, so a
//!   hard-coded field offset would break on the next Arch kernel. Everything
//!   here comes from stable interfaces: tracepoint records, syscall arguments,
//!   the `inet_*_connect` socket-address argument and plain helper calls.
//!   Anything that would need `task_struct` (start time, parent, cwd, resolved
//!   executable path) is worked out by the sensor from the events and `/proc`.
//! * **Tracepoint field offsets are not compiled in.** The sensor reads them
//!   from `/sys/kernel/tracing/events/*/*/format` at start-up and passes them in
//!   through the `*_OFF` globals below.
//! * **No large copies by value.** BPF has no `memcpy`; big buffers are filled
//!   in place with helpers, and every helper call has a constant or masked size
//!   so the verifier can prove it in bounds.
//! * **Every reserved ring-buffer entry is submitted on every path.** The
//!   verifier rejects a program that can leak a reservation, so nothing that
//!   can fail with `?` runs between `reserve` and `submit`.
//! * Events from the sensor's own process (`SELF_TGID`) are never reported.
//!
//! Programs (all independent; the sensor attaches each one separately):
//!
//! | program | hook | purpose |
//! | --- | --- | --- |
//! | `sched_process_fork` | tracepoint | parent/child edge for the process tree |
//! | `sys_enter_execve`, `sys_enter_execveat` | tracepoint | capture argv before the exec |
//! | `sched_process_exec` | tracepoint | the exec itself, with the captured argv |
//! | `sys_enter_exit_group` | tracepoint | remember the exit status |
//! | `sched_process_exit` | tracepoint | the process is gone |
//! | `kp_inet_stream_connect`, `kp_inet_dgram_connect` | kprobe | TCP / UDP connect |

#![no_std]
#![no_main]
// Some helper wrappers are safe functions in some aya-ebpf versions and unsafe
// in others; keeping the `unsafe` blocks makes the code build on both.
#![allow(unused_unsafe)]

use core::ptr::{addr_of_mut, read_volatile};

use aya_ebpf::{
    cty::c_void,
    macros::{kprobe, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use ai_antivirus_ebpf_common::{
    ArgvBlob, ConnectRecord, ExecRecord, ExitRecord, ForkRecord, AF_INET, AF_INET6, ARGV_MAX,
    ARG_CHUNK, EXEC_FLAG_ARGV, EXEC_FLAG_ARGV_TRUNCATED, EXEC_FLAG_FILENAME_TRUNCATED,
    EXIT_FLAG_HAS_CODE, FILENAME_MAX, KIND_CONNECT, KIND_EXEC, KIND_EXIT, KIND_FORK, MAX_ARGS,
    PROTO_TCP, PROTO_UDP,
};

/// Raw BPF helpers. This is the single place that names them; if a future
/// aya-ebpf moves them, this is the one `use` to change.
mod raw {
    pub use aya_ebpf::helpers::gen::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str, bpf_probe_read_user,
        bpf_probe_read_user_str,
    };
}

// ---------------------------------------------------------------------------
// maps
// ---------------------------------------------------------------------------

/// All events for the sensor. 8 MiB holds roughly 1800 exec records or far more
/// of the small kinds; when it is full the event is dropped and counted.
const EVENTS_BYTES: u32 = 8 * 1024 * 1024;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_BYTES, 0);

/// Number of events dropped because `EVENTS` was full (one slot per CPU).
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Argument blocks captured at `execve` entry, keyed by thread id, waiting for
/// the exec to succeed. An LRU map, so failed execs never fill it up.
#[map]
static ARGV_STASH: LruHashMap<u32, ArgvBlob> = LruHashMap::with_max_entries(512, 0);

/// Per-CPU scratch space the argument block is assembled in (too big for the
/// 512-byte BPF stack).
#[map]
static ARGV_SCRATCH: PerCpuArray<ArgvBlob> = PerCpuArray::with_max_entries(1, 0);

/// `exit_group` status by process id, until the process actually exits.
#[map]
static EXIT_CODES: LruHashMap<u32, i32> = LruHashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// globals set by the sensor before the programs are loaded
// ---------------------------------------------------------------------------

#[no_mangle]
static SELF_TGID: u32 = 0;
#[no_mangle]
static FORK_CHILD_PID_OFF: u32 = 0;
#[no_mangle]
static EXEC_FILENAME_OFF: u32 = 0;
#[no_mangle]
static EXEC_OLD_PID_OFF: u32 = 0;
#[no_mangle]
static EXECVE_ARGV_OFF: u32 = 0;
#[no_mangle]
static EXECVEAT_ARGV_OFF: u32 = 0;
#[no_mangle]
static EXITGROUP_CODE_OFF: u32 = 0;

/// Read a global. Volatile, so the compiler cannot fold in the placeholder `0`
/// the sensor overwrites at load time.
#[inline(always)]
fn global(value: &'static u32) -> u32 {
    // SAFETY: `value` is a valid, aligned, initialised `u32` in read-only data.
    unsafe { read_volatile(value) }
}

// ---------------------------------------------------------------------------
// small wrappers around helpers
// ---------------------------------------------------------------------------

/// `(tgid, tid)` of the running task. `tgid` is the process id users see.
#[inline(always)]
fn pid_tgid() -> (u32, u32) {
    // SAFETY: the helper takes no arguments and only reads the current task's ids.
    let v = unsafe { raw::bpf_get_current_pid_tgid() };
    ((v >> 32) as u32, v as u32)
}

/// Real user id of the running task.
#[inline(always)]
fn real_uid() -> u32 {
    // SAFETY: the helper takes no arguments and only reads the current credentials.
    let v = unsafe { raw::bpf_get_current_uid_gid() };
    v as u32
}

/// `CLOCK_BOOTTIME` in nanoseconds: the same clock `/proc/<pid>/stat` start
/// times use, and it keeps counting across suspend.
#[inline(always)]
fn boot_ns() -> u64 {
    // SAFETY: the helper takes no arguments and has no side effects.
    unsafe { raw::bpf_ktime_get_boot_ns() }
}

#[inline(always)]
fn is_self(tgid: u32) -> bool {
    tgid == global(&SELF_TGID)
}

/// Read a `u32` from the tracepoint record at a byte offset.
#[inline(always)]
fn tp_u32(ctx: &TracePointContext, offset: u32) -> Result<u32, i64> {
    // SAFETY: `read_at` copies four bytes with `bpf_probe_read`; an offset that
    // is wrong for this kernel makes it return an error code, never fault.
    unsafe { ctx.read_at::<u32>(offset as usize) }
}

/// Read a `u64` from the tracepoint record at a byte offset.
#[inline(always)]
fn tp_u64(ctx: &TracePointContext, offset: u32) -> Result<u64, i64> {
    // SAFETY: as for `tp_u32`.
    unsafe { ctx.read_at::<u64>(offset as usize) }
}

#[inline(always)]
fn count_drop() {
    // SAFETY: `get_ptr_mut` returns a pointer into this CPU's slot of the map,
    // valid for the whole program run; nothing else touches that slot.
    unsafe {
        if let Some(counter) = DROPS.get_ptr_mut(0) {
            *counter += 1;
        }
    }
}

/// Send a small fixed-size record (a few dozen bytes, so building it on the
/// stack is fine).
#[inline(always)]
fn emit<T: 'static>(record: T) {
    match EVENTS.reserve::<T>(0) {
        Some(mut entry) => {
            entry.write(record);
            entry.submit(0);
        }
        None => count_drop(),
    }
}

/// Write one field of a ring-buffer record that is still uninitialised.
macro_rules! put {
    ($rec:expr, $field:ident, $value:expr) => {
        // SAFETY: `$rec` points to a live ring-buffer reservation of the
        // record's type, and `addr_of_mut!` creates no reference to the
        // uninitialised memory, only a raw pointer to the field.
        unsafe { addr_of_mut!((*$rec).$field).write($value) }
    };
}

// ---------------------------------------------------------------------------
// fork
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_fork(&ctx);
    0
}

#[inline(always)]
fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let (tgid, tid) = pid_tgid();
    if is_self(tgid) {
        return Ok(());
    }
    // The running task is the parent; only the child's id is in the record.
    let child_pid = tp_u32(ctx, global(&FORK_CHILD_PID_OFF))?;
    emit(ForkRecord {
        kind: KIND_FORK,
        parent_tid: tid,
        parent_tgid: tgid,
        child_pid,
        ts_boot_ns: boot_ns(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// execve: argument capture, then the exec itself
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = stash_argv(&ctx, global(&EXECVE_ARGV_OFF));
    0
}

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let _ = stash_argv(&ctx, global(&EXECVEAT_ARGV_OFF));
    0
}

/// Copy the caller's `argv` strings (user memory, only readable now, before the
/// old address space is replaced) into the scratch block and stash it by thread
/// id. Up to `MAX_ARGS` arguments, `ARG_CHUNK` bytes each, `ARGV_MAX` in total.
#[inline(always)]
fn stash_argv(ctx: &TracePointContext, argv_field_offset: u32) -> Result<(), i64> {
    let (tgid, tid) = pid_tgid();
    if is_self(tgid) {
        return Ok(());
    }
    let argv = tp_u64(ctx, argv_field_offset)? as *const u64;
    // SAFETY: the pointer is into this CPU's slot of the scratch map and stays
    // valid for the whole program run; programs do not migrate or nest here.
    let Some(blob) = (unsafe { ARGV_SCRATCH.get_ptr_mut(0) }) else {
        return Ok(());
    };

    let mut off: usize = 0;
    let mut argc: u32 = 0;
    let mut flags: u32 = 0;
    let mut i: u32 = 0;
    while i < MAX_ARGS {
        // argv[i]: a pointer into user memory, NULL after the last argument.
        let mut arg_ptr: u64 = 0;
        // SAFETY: the destination is a live 8-byte stack slot; the source is a
        // user address the helper validates (a bad one returns an error).
        let r = unsafe {
            raw::bpf_probe_read_user(
                addr_of_mut!(arg_ptr) as *mut c_void,
                8,
                argv.wrapping_add(i as usize) as *const c_void,
            )
        };
        if r != 0 {
            flags |= EXEC_FLAG_ARGV_TRUNCATED;
            break;
        }
        if arg_ptr == 0 {
            break;
        }
        if off >= ARGV_MAX {
            flags |= EXEC_FLAG_ARGV_TRUNCATED;
            break;
        }
        // `off < ARGV_MAX` holds here (checked above), and ARGV_MAX is a power
        // of two, so the mask never changes the value; it is kept so the
        // verifier sees the bound even if the compiler drops the comparison.
        // The block has ARG_CHUNK spare bytes after ARGV_MAX, so a copy of
        // ARG_CHUNK bytes from here always stays inside it.
        // SAFETY: `blob` is a live map value of type ArgvBlob; the offset is at
        // most ARGV_MAX - 1, and `data` is ARGV_MAX + ARG_CHUNK bytes long.
        let dst = unsafe { (addr_of_mut!((*blob).data) as *mut u8).add(off & (ARGV_MAX - 1)) };
        // SAFETY: `dst` has ARG_CHUNK writable bytes (see above); the source is
        // a user address the helper validates.
        let n = unsafe {
            raw::bpf_probe_read_user_str(dst as *mut c_void, ARG_CHUNK as u32, arg_ptr as *const c_void)
        };
        if n <= 0 || n > ARG_CHUNK as i64 {
            flags |= EXEC_FLAG_ARGV_TRUNCATED;
            break;
        }
        if n == ARG_CHUNK as i64 {
            // Filled the whole chunk: the argument may have been cut short.
            flags |= EXEC_FLAG_ARGV_TRUNCATED;
        }
        off += n as usize;
        argc += 1;
        i += 1;
    }
    if i >= MAX_ARGS {
        flags |= EXEC_FLAG_ARGV_TRUNCATED;
    }
    if off > ARGV_MAX {
        flags |= EXEC_FLAG_ARGV_TRUNCATED;
        off = ARGV_MAX;
    }

    // SAFETY: `blob` is the live per-CPU map value; these are plain integer stores.
    unsafe {
        (*blob).len = off as u32;
        (*blob).argc = argc;
        (*blob).flags = flags;
    }
    // SAFETY: `tid` is a live stack variable; `blob` is a live map value of the
    // map's value type.
    let _ = unsafe { ARGV_STASH.insert(&tid, &*blob, 0) };
    Ok(())
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

#[inline(always)]
fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let (tgid, _tid) = pid_tgid();
    if is_self(tgid) {
        return Ok(());
    }
    // Everything that can fail with `?` happens before the reservation.
    let old_tid = tp_u32(ctx, global(&EXEC_OLD_PID_OFF))?;
    // `__data_loc char[] filename`: low 16 bits = offset of the string in the
    // record, high 16 bits = its length.
    let data_loc = tp_u32(ctx, global(&EXEC_FILENAME_OFF))?;
    let name_off = (data_loc & 0xffff) as usize;
    let uid = real_uid();
    let ts = boot_ns();

    let Some(mut entry) = EVENTS.reserve::<ExecRecord>(0) else {
        count_drop();
        return Ok(());
    };
    let rec: *mut ExecRecord = entry.as_mut_ptr();

    put!(rec, kind, KIND_EXEC);
    put!(rec, tgid, tgid);
    put!(rec, old_tid, old_tid);
    put!(rec, uid, uid);
    put!(rec, ts_boot_ns, ts);

    let mut flags: u32 = 0;
    let mut argc: u32 = 0;
    let mut argv_len: u32 = 0;

    // The path as given to execve. `n` counts the NUL.
    // SAFETY: the destination is the `filename` field of the reservation
    // (FILENAME_MAX bytes); the source is inside the tracepoint record, and the
    // helper validates it either way.
    let n = unsafe {
        raw::bpf_probe_read_kernel_str(
            addr_of_mut!((*rec).filename) as *mut c_void,
            FILENAME_MAX as u32,
            (ctx.as_ptr() as *const u8).wrapping_add(name_off) as *const c_void,
        )
    };
    let name_len: u32 = if n > 0 { n as u32 } else { 0 };
    if n >= FILENAME_MAX as i64 {
        flags |= EXEC_FLAG_FILENAME_TRUNCATED;
    }

    // The argument block stashed by sys_enter_execve{,at}, if those loaded.
    // SAFETY: the returned reference points into a map value that stays valid
    // for this program run.
    if let Some(blob) = unsafe { ARGV_STASH.get(&old_tid) } {
        // Constant-size copy of the first ARGV_MAX bytes of the stash.
        // SAFETY: the destination is the `argv` field of the reservation
        // (ARGV_MAX bytes); the source is the stash's `data`, which is longer.
        let r = unsafe {
            raw::bpf_probe_read_kernel(
                addr_of_mut!((*rec).argv) as *mut c_void,
                ARGV_MAX as u32,
                blob.data.as_ptr() as *const c_void,
            )
        };
        if r == 0 {
            flags |= EXEC_FLAG_ARGV | (blob.flags & EXEC_FLAG_ARGV_TRUNCATED);
            argc = blob.argc;
            argv_len = blob.len;
        }
    }
    // SAFETY: `old_tid` is a live stack variable.
    let _ = unsafe { ARGV_STASH.remove(&old_tid) };

    put!(rec, flags, flags);
    put!(rec, argc, argc);
    put!(rec, filename_len, name_len);
    put!(rec, argv_len, argv_len);
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// exit
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    let _ = try_exit_group(&ctx);
    0
}

#[inline(always)]
fn try_exit_group(ctx: &TracePointContext) -> Result<(), i64> {
    let (tgid, _tid) = pid_tgid();
    if is_self(tgid) {
        return Ok(());
    }
    // The syscall argument is an `int`; the kernel keeps its low 8 bits.
    let status = (tp_u32(ctx, global(&EXITGROUP_CODE_OFF))? & 0xff) as i32;
    // SAFETY: both references point at live stack variables.
    let _ = unsafe { EXIT_CODES.insert(&tgid, &status, 0) };
    Ok(())
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    try_exit();
    0
}

/// This fires for every thread that exits. Only the thread-group leader's exit
/// is reported, which is the process's own exit in all but one rare case (the
/// main thread calling `pthread_exit` while other threads keep running).
#[inline(always)]
fn try_exit() {
    let (tgid, tid) = pid_tgid();
    if tid != tgid || is_self(tgid) {
        return;
    }
    // SAFETY: the returned reference points into a map value that stays valid
    // for this program run; it is copied out immediately.
    let status = unsafe { EXIT_CODES.get(&tgid) }.copied();
    if status.is_some() {
        // SAFETY: `tgid` is a live stack variable.
        let _ = unsafe { EXIT_CODES.remove(&tgid) };
    }
    emit(ExitRecord {
        kind: KIND_EXIT,
        tgid,
        tid,
        flags: if status.is_some() { EXIT_FLAG_HAS_CODE } else { 0 },
        code: status.unwrap_or(0),
        _pad: 0,
        ts_boot_ns: boot_ns(),
    });
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------

// `inet_stream_connect(struct socket *sock, struct sockaddr *uaddr, int len,
// int flags)` serves connect(2) on TCP sockets (IPv4 and IPv6), and
// `inet_dgram_connect` the same for UDP. By then the kernel has copied the
// address out of user space, so `uaddr` is a kernel pointer, and the function
// itself tells us the protocol, which the syscall tracepoint cannot.

#[kprobe]
pub fn kp_inet_stream_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, PROTO_TCP);
    0
}

#[kprobe]
pub fn kp_inet_dgram_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, PROTO_UDP);
    0
}

#[inline(always)]
fn try_connect(ctx: &ProbeContext, proto: u8) -> Result<(), i64> {
    let (tgid, tid) = pid_tgid();
    if is_self(tgid) {
        return Ok(());
    }
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;

    // 28 bytes covers sockaddr_in6, the largest address we report. The caller's
    // buffer is a sockaddr_storage (128 bytes), so reading that much from a
    // shorter sockaddr_in is safe.
    let mut sa = [0u8; 28];
    // SAFETY: the destination is a live 28-byte stack buffer; the source is a
    // kernel address the helper validates.
    let r = unsafe {
        raw::bpf_probe_read_kernel(sa.as_mut_ptr() as *mut c_void, 28, uaddr as *const c_void)
    };
    if r != 0 {
        return Err(r);
    }

    let family = u16::from_ne_bytes([sa[0], sa[1]]);
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    let mut addr = [0u8; 16];
    if family == AF_INET {
        addr[0] = sa[4];
        addr[1] = sa[5];
        addr[2] = sa[6];
        addr[3] = sa[7];
    } else if family == AF_INET6 {
        addr.copy_from_slice(&sa[8..24]);
    } else {
        // AF_UNIX and friends are not network connections.
        return Ok(());
    }

    emit(ConnectRecord {
        kind: KIND_CONNECT,
        tgid,
        tid,
        uid: real_uid(),
        ts_boot_ns: boot_ns(),
        family,
        proto,
        _pad1: 0,
        port,
        _pad2: 0,
        addr,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// boilerplate
// ---------------------------------------------------------------------------

/// The kernel only lets a program call GPL-only helpers (probe reads and the
/// ring buffer are GPL-only) if it declares a GPL-compatible license.
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the code above has no panicking paths (no unwrap, expect, or
    // unchecked indexing), so this is never reached.
    unsafe { core::hint::unreachable_unchecked() }
}
