//! The eBPF sensor (M2): loads the kernel programs, attaches each one on its
//! own, and turns the ring buffer into events.
//!
//! Failure model (the daemon must keep working on any kernel):
//! * The three **required** programs (fork, exec, exit) are what replace the
//!   `/proc` poller. If any of them cannot be loaded or attached, nothing stays
//!   attached, [`start`] returns an error, and the daemon falls back to the
//!   poller and reports `degraded`.
//! * The **optional** programs (argument capture, exit status, connect) can
//!   fail individually. The sensor keeps running, logs which one is missing,
//!   and reports `degraded`.

use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::{KProbe, ProgramError, TracePoint};
use aya::{Ebpf, EbpfLoader};
use synapse_common::config::Config;
use tracing::{debug, error, info, warn};

use crate::proctree::{lock, ProcTable, RealProcFs, SharedTable};
use crate::sink::Sink;
use crate::tracefs::Offsets;
use crate::translate::Translator;

/// Largest eBPF object file accepted.
const MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
/// How long the consumer sleeps on the ring buffer before checking shutdown.
const POLL_TIMEOUT_MS: i32 = 200;
/// How often the kernel drop counter is read.
const DROPS_INTERVAL: Duration = Duration::from_secs(1);
/// How often vanished processes are swept out of the process table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Longest piece of an error (a verifier log can be megabytes) that is logged.
const MAX_ERROR_CHARS: usize = 6000;

#[derive(Debug, Clone, Copy)]
enum Hook {
    Tracepoint(&'static str, &'static str),
    Kprobe(&'static str),
}

struct Spec {
    /// Function name in the eBPF object.
    name: &'static str,
    hook: Hook,
    required: bool,
    /// False when the running kernel lacks a field this program reads.
    available: fn(&Offsets) -> bool,
}

const SPECS: &[Spec] = &[
    Spec {
        name: "sched_process_fork",
        hook: Hook::Tracepoint("sched", "sched_process_fork"),
        required: true,
        available: |o: &Offsets| o.fork_child_pid.is_some(),
    },
    Spec {
        name: "sched_process_exec",
        hook: Hook::Tracepoint("sched", "sched_process_exec"),
        required: true,
        available: |o: &Offsets| o.exec_filename.is_some() && o.exec_old_pid.is_some(),
    },
    Spec {
        name: "sched_process_exit",
        hook: Hook::Tracepoint("sched", "sched_process_exit"),
        required: true,
        available: |_: &Offsets| true,
    },
    Spec {
        name: "sys_enter_execve",
        hook: Hook::Tracepoint("syscalls", "sys_enter_execve"),
        required: false,
        available: |o: &Offsets| o.execve_argv.is_some(),
    },
    Spec {
        name: "sys_enter_execveat",
        hook: Hook::Tracepoint("syscalls", "sys_enter_execveat"),
        required: false,
        available: |o: &Offsets| o.execveat_argv.is_some(),
    },
    Spec {
        name: "sys_enter_exit_group",
        hook: Hook::Tracepoint("syscalls", "sys_enter_exit_group"),
        required: false,
        available: |o: &Offsets| o.exit_group_code.is_some(),
    },
    Spec {
        name: "kp_inet_stream_connect",
        hook: Hook::Kprobe("inet_stream_connect"),
        required: false,
        available: |_: &Offsets| true,
    },
    Spec {
        name: "kp_inet_dgram_connect",
        hook: Hook::Kprobe("inet_dgram_connect"),
        required: false,
        available: |_: &Offsets| true,
    },
];

/// Names of required programs the kernel's tracepoint layout rules out.
fn missing_required(offsets: &Offsets) -> Vec<&'static str> {
    SPECS
        .iter()
        .filter(|spec| spec.required && !(spec.available)(offsets))
        .map(|spec| spec.name)
        .collect()
}

/// The last `max` characters of `text` (the interesting end of a verifier log).
fn tail_chars(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_owned();
    }
    let tail: String = text.chars().skip(count - max).collect();
    format!("...{tail}")
}

fn describe(err: impl Display) -> String {
    tail_chars(&err.to_string(), MAX_ERROR_CHARS)
}

/// The eBPF object is code that runs in the kernel, so it must be as
/// trustworthy as the sensor binary: owned by root, not writable by anyone else.
fn check_object_owner(uid: u32, mode: u32) -> Result<(), String> {
    if uid != 0 {
        return Err(format!("owned by uid {uid}, not root"));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "mode {:o} lets group or others write it",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// Read the object from an already-open descriptor, so the checks and the
/// bytes loaded cannot refer to different files.
fn read_object(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > MAX_OBJECT_BYTES {
        return Err(format!(
            "{} is larger than {MAX_OBJECT_BYTES} bytes",
            path.display()
        ));
    }
    check_object_owner(meta.uid(), meta.mode())
        .map_err(|why| format!("refusing {}: {why}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_OBJECT_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(bytes)
}

fn attach(ebpf: &mut Ebpf, spec: &Spec) -> Result<(), String> {
    let program = ebpf
        .program_mut(spec.name)
        .ok_or_else(|| "not found in the eBPF object".to_owned())?;
    match spec.hook {
        Hook::Tracepoint(category, event) => {
            let tp: &mut TracePoint = program.try_into().map_err(|e: ProgramError| describe(e))?;
            tp.load().map_err(describe)?;
            tp.attach(category, event).map_err(describe)?;
        }
        Hook::Kprobe(function) => {
            let kp: &mut KProbe = program.try_into().map_err(|e: ProgramError| describe(e))?;
            kp.load().map_err(describe)?;
            kp.attach(function, 0).map_err(describe)?;
        }
    }
    Ok(())
}

/// Load and attach the programs and start the consumer thread.
///
/// On `Err` nothing is left attached and no thread runs; the caller falls back
/// to the `/proc` poller. On `Ok` the process table has been baselined and the
/// thread owns the programs for as long as it runs.
pub fn start(
    cfg: &Config,
    sink: &Sink,
    table: &SharedTable,
    shutdown: &Arc<AtomicBool>,
) -> Result<JoinHandle<()>, String> {
    let bytes = read_object(&cfg.sensors.ebpf_object)?;

    let offsets = Offsets::from_system();
    if offsets.used_defaults {
        warn!("tracefs format files not readable; assuming the usual tracepoint layouts");
    }
    let missing = missing_required(&offsets);
    if !missing.is_empty() {
        return Err(format!(
            "this kernel's tracepoint layout does not match what {missing:?} reads"
        ));
    }

    // Globals the programs read. Every one must exist in the object, so a typo
    // here is an error and never a silent wrong offset.
    let self_tgid: u32 = std::process::id();
    let globals: [(&str, u32); 7] = [
        ("SELF_TGID", self_tgid),
        ("FORK_CHILD_PID_OFF", offsets.fork_child_pid.unwrap_or(0)),
        ("EXEC_FILENAME_OFF", offsets.exec_filename.unwrap_or(0)),
        ("EXEC_OLD_PID_OFF", offsets.exec_old_pid.unwrap_or(0)),
        ("EXECVE_ARGV_OFF", offsets.execve_argv.unwrap_or(0)),
        ("EXECVEAT_ARGV_OFF", offsets.execveat_argv.unwrap_or(0)),
        ("EXITGROUP_CODE_OFF", offsets.exit_group_code.unwrap_or(0)),
    ];
    let mut loader = EbpfLoader::new();
    for (name, value) in &globals {
        loader.set_global(name, value, true);
    }
    let mut ebpf = loader
        .load(&bytes)
        .map_err(|e| format!("cannot load the eBPF object: {}", describe(e)))?;

    let mut partial = false;
    for spec in SPECS {
        if !(spec.available)(&offsets) {
            warn!(
                program = spec.name,
                "skipped: the kernel lacks a field it reads"
            );
            partial = true;
            continue;
        }
        match attach(&mut ebpf, spec) {
            Ok(()) => debug!(program = spec.name, "attached"),
            Err(why) if spec.required => {
                return Err(format!("required program {} failed: {why}", spec.name));
            }
            Err(why) => {
                warn!(program = spec.name, error = %why, "optional program not attached");
                partial = true;
            }
        }
    }

    let ring_map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| "map EVENTS missing from the object".to_owned())?;
    let ring = RingBuf::try_from(ring_map).map_err(describe)?;
    let drops_map = ebpf
        .take_map("DROPS")
        .ok_or_else(|| "map DROPS missing from the object".to_owned())?;
    let drops: PerCpuArray<MapData, u64> = PerCpuArray::try_from(drops_map).map_err(describe)?;

    // Programs are attached, so events are already queueing in the ring buffer.
    // Record the processes that exist now; fork/exec records that raced with
    // this scan are consistent with it either way.
    let known = lock(table)
        .baseline()
        .map_err(|e| format!("cannot read /proc: {e}"))?;
    info!(processes = known, partial, "eBPF sensor attached");

    sink.stats.ebpf_alive.store(true, Ordering::Relaxed);
    sink.stats.ebpf_partial.store(partial, Ordering::Relaxed);

    let translator = Translator::new(Arc::clone(table), Box::new(RealProcFs::new("/proc")));
    let stats = Arc::clone(&sink.stats);
    let sink = sink.clone();
    let shutdown = Arc::clone(shutdown);
    let spawned = crate::spawn_named("ebpf", move || {
        consume(ebpf, ring, drops, &translator, &sink, &shutdown);
    });
    spawned.map_err(|e| {
        // The programs were dropped with the closure, so nothing is attached.
        stats.ebpf_alive.store(false, Ordering::Relaxed);
        e.to_string()
    })
}

/// Read records until shutdown. Owns `ebpf`, so dropping it on the way out
/// detaches every program.
fn consume(
    ebpf: Ebpf,
    mut ring: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    translator: &Translator,
    sink: &Sink,
    shutdown: &AtomicBool,
) {
    let _programs = ebpf;
    let mut last_drops = 0u64;
    let mut next_drops = Instant::now() + DROPS_INTERVAL;
    let mut next_sweep = Instant::now() + SWEEP_INTERVAL;

    let drain = |ring: &mut RingBuf<MapData>| {
        while let Some(item) = ring.next() {
            if let Err(e) = translator.handle(&item, sink) {
                // A record we cannot read is a lost event.
                debug!(error = ?e, "undecodable ring buffer record");
                sink.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    };

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = synapse_sys::wait_readable(&ring, POLL_TIMEOUT_MS) {
            error!(error = %e, "waiting on the eBPF ring buffer failed; process events stop");
            break;
        }
        drain(&mut ring);

        let now = Instant::now();
        if now >= next_drops {
            next_drops = now + DROPS_INTERVAL;
            if let Ok(per_cpu) = drops.get(&0, 0) {
                let total: u64 = per_cpu.iter().sum();
                if total > last_drops {
                    sink.stats
                        .dropped
                        .fetch_add(total - last_drops, Ordering::Relaxed);
                    last_drops = total;
                }
            }
        }
        if now >= next_sweep {
            next_sweep = now + SWEEP_INTERVAL;
            sweep(translator);
        }
    }
    drain(&mut ring);
    sink.stats.ebpf_alive.store(false, Ordering::Relaxed);
}

fn sweep(translator: &Translator) {
    let removed = translator.sweep();
    if removed > 0 {
        debug!(removed, "forgot vanished processes");
    }
}

/// A fresh, empty process table over the real `/proc`.
pub fn new_table() -> SharedTable {
    Arc::new(std::sync::Mutex::new(ProcTable::new(Box::new(
        RealProcFs::new("/proc"),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_must_be_root_owned_and_not_group_or_world_writable() {
        assert!(check_object_owner(0, 0o100644).is_ok());
        assert!(check_object_owner(0, 0o100755).is_ok());
        assert!(check_object_owner(1000, 0o100644).is_err());
        assert!(check_object_owner(0, 0o100664).is_err());
        assert!(check_object_owner(0, 0o100646).is_err());
    }

    #[test]
    fn reading_the_object_applies_the_checks_to_the_file_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.o");
        std::fs::write(&path, b"\x7fELF").unwrap();
        // Tests do not run as root, so the owner check must refuse it...
        if MetadataExt::uid(&std::fs::metadata(&path).unwrap()) != 0 {
            assert!(read_object(&path).unwrap_err().contains("not root"));
        }
        // ...and a missing file is an error with the path in it.
        let err = read_object(&dir.path().join("missing.o")).unwrap_err();
        assert!(err.contains("missing.o"));
        // A directory is not an object.
        assert!(read_object(dir.path()).is_err());
    }

    #[test]
    fn long_errors_keep_their_tail() {
        let long = format!("{}END", "x".repeat(10_000));
        let cut = tail_chars(&long, 100);
        assert!(cut.ends_with("END"));
        assert!(cut.starts_with("..."));
        assert_eq!(cut.chars().count(), 103);
        assert_eq!(tail_chars("short", 100), "short");
        assert_eq!(tail_chars("héllo wörld", 5), "...wörld");
    }

    fn all_offsets() -> Offsets {
        Offsets::resolve(|_, _| None)
    }

    #[test]
    fn every_program_is_planned_and_three_are_required() {
        let offsets = all_offsets();
        assert!(SPECS.iter().all(|s| (s.available)(&offsets)));
        let required: Vec<&str> = SPECS
            .iter()
            .filter(|s| s.required)
            .map(|s| s.name)
            .collect();
        assert_eq!(
            required,
            vec![
                "sched_process_fork",
                "sched_process_exec",
                "sched_process_exit"
            ]
        );
        let mut names: Vec<&str> = SPECS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), SPECS.len(), "duplicate program name");
        assert!(missing_required(&offsets).is_empty());
    }

    #[test]
    fn a_missing_field_rules_out_exactly_its_programs() {
        let mut offsets = all_offsets();
        offsets.fork_child_pid = None;
        assert_eq!(missing_required(&offsets), vec!["sched_process_fork"]);

        let mut offsets = all_offsets();
        offsets.execve_argv = None;
        assert!(
            missing_required(&offsets).is_empty(),
            "argv capture is optional"
        );
        let unavailable: Vec<&str> = SPECS
            .iter()
            .filter(|s| !(s.available)(&offsets))
            .map(|s| s.name)
            .collect();
        assert_eq!(unavailable, vec!["sys_enter_execve"]);
    }
}
