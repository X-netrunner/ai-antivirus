# Synapse

AI-assisted EDR and antivirus for Arch Linux. Design: see the Synapse master prompt and design specification (v1.0). This repository is built one milestone at a time.

**Status: M2 written, not yet compiled** (M0 is built and passes all 44 tests on Arch; M1 was written without a compiler and then fixed by you, see the archive name `m1-fix1`; M2 has never been compiled and no eBPF program has ever been loaded into a kernel). M2 adds the eBPF sensor (exec with arguments, exit with status, fork edges, TCP/UDP connect), the process tree and kernel drop counting. Default mode is `alert-only`; nothing here can act on the system: the sensor only observes and writes a log.

## Requirements

M0 needs no kernel features. The M1 sensor daemon needs fanotify (`CONFIG_FANOTIFY`, standard on Arch kernels) and runs as root; without `CAP_SYS_ADMIN` it still runs, with `/proc` polling only.

| Need | Arch package | Verify |
| --- | --- | --- |
| Rust 1.85+ | `rust` | `cargo --version` |
| SQLite | `sqlite` | `pkg-config --modversion sqlite3` |
| C toolchain | `base-devel` | `cc --version` |

No system SQLite? Build with `--features synapse-common/bundled-sqlite`.

**M2 (eBPF)** adds two build-time and several run-time needs. The stable workspace builds without any of the build-time ones; without the eBPF object the sensor simply runs on `/proc` polling.

| Need | Arch package / command | Verify |
| --- | --- | --- |
| rustup + nightly with `rust-src` (eBPF programs need `-Z build-std`) | `rustup`, then `rustup toolchain install nightly --component rust-src` | `rustup +nightly component list --installed` |
| `bpf-linker` | `cargo install bpf-linker` (check the AUR/extra for a package) | `bpf-linker --version` |
| Kernel with BPF, BTF, ring buffer (5.8+), tracefs | stock `linux`, `linux-lts`, `linux-zen` | `zcat /proc/config.gz \| grep -E 'BPF_SYSCALL\|BPF_JIT\|DEBUG_INFO_BTF\|KPROBES\|FANOTIFY'`, `ls /sys/kernel/btf/vmlinux`, `ls /sys/kernel/tracing/events/sched` |
| `CAP_BPF`, `CAP_PERFMON` | granted by the unit; or run as root | |

Kernel lockdown (Secure Boot) can forbid kprobes or BPF writes; if loading fails the sensor logs why and falls back to polling.

## Build and test

```sh
cargo build --workspace          # M1 and M2 added dependencies (aya), so the first build updates Cargo.lock
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Commit the refreshed `Cargo.lock`; after that `--locked` works again.

The kernel-side programs are a separate build (nightly, own `Cargo.lock`, not part of `cargo build --workspace`):

```sh
cargo xtask build-ebpf --release        # -> target/bpf/synapse-ebpf.o
sudo install -D -o root -g root -m 0644 target/bpf/synapse-ebpf.o /usr/lib/synapse/synapse-ebpf.o
```

The sensor refuses an object that is not owned by root or is writable by group/others; it is kernel code. For a quick try without installing, set `sensors.ebpf_object` to a path of your choosing and `sudo chown root:root` it.

Some tests start real processes (`sleep`) and read `/proc`; they run unprivileged. fanotify itself needs root and is only exercised by the manual check below.

## Use

```sh
synapsectl --config config/synapse.example.toml config-check [--print]
synapsectl db-init   --db ./synapse.db      # or omit --db to use <state_dir>/synapse.db
synapsectl db-stats  --db ./synapse.db
synapsectl --config /etc/synapse/synapse.toml db-cleanup

# M1: collect events and watch them
sudo synapse-sensord --config /etc/synapse/synapse.toml
synapsectl tail -n 50                       # last 50 events
synapsectl tail -f                          # follow, like tail -f
synapsectl tail -f --kind exec,file_write   # filter by event kind
synapsectl tail --json | jq .               # raw JSON, one event per line
synapsectl tail --file ./events.jsonl       # read a copy of a log
```

The default config path is `/etc/synapse/synapse.toml`. The state directory is mode 0750 owned by `synapse`, so run the db commands as that user or root. The event log is `<log_dir>/events.jsonl` (default `/var/log/synapse`), mode 0640, group `synapse`; add yourself to that group (or use `sudo`) to run `tail`.

### Trying M2 by hand

```sh
cargo xtask build-ebpf --release
sudo chown root:root target/bpf/synapse-ebpf.o
cat > /tmp/syn.toml <<'EOF2'
[paths]
log_dir = '/tmp/syn-logs'
[sensors]
ebpf_object = '/path/to/synapse/target/bpf/synapse-ebpf.o'
EOF2
mkdir -p /tmp/syn-logs
sudo RUST_LOG=debug ./target/debug/synapse-sensord --config /tmp/syn.toml &
sudo ./target/debug/synapsectl --config /tmp/syn.toml tail -f --kind exec,exit,connect
# elsewhere:  true; sh -c 'sleep 0.01'; curl -s https://example.com -o /dev/null; nc -u -w1 1.1.1.1 53 </dev/null
```

Expected: the log line `eBPF sensor attached` (and, if something is missing, one `optional program not attached` warning per program with the reason); an `exec` for every command, **including `true`**, which the poller misses, with full `argv`, the parent's key and the resolved `exe`; an `exit` with the real status for processes that call `exit_group`, `code=-1` for ones killed by a signal; `connect` lines with the destination. `sensor_health` shows `degraded=false` when everything attached. If the eBPF object fails to load you should instead see `eBPF sensor unavailable; falling back to /proc polling` with the verifier output tail; please send me that output.

### Trying M1 by hand

```sh
mkdir -p /tmp/syn-logs
cat > /tmp/syn.toml <<'EOF2'
[paths]
log_dir = '/tmp/syn-logs'
EOF2
sudo ./target/debug/synapse-sensord --config /tmp/syn.toml &
sudo ./target/debug/synapsectl --config /tmp/syn.toml tail -f   # log dir is root-only here
# in another terminal:
sleep 1; echo hi > /tmp/hello.txt      # shows exec (sleep) and file_write
```

Expected: a `sensor_health` line at start and every 10 s, an `exec` line for each new process (within one poll interval, 250 ms by default), an `exit` line when it ends, and a `file_write` line for `/tmp/hello.txt` with the writing process. Nothing in the log should come from `synapse-sensord` itself. Also run `./target/debug/synapse-sensord --config /tmp/syn.toml` once without `sudo`: it must start, log that fanotify is unavailable (and that `/proc` entries of other users may be partly unreadable), and report `degraded=true` in `sensor_health`.

## Layout

```
crates/synapse-common/   event schema, config, logging, store, JSONL event log
crates/synapse-sys/      unsafe code in userspace: fanotify and poll FFI (own lints)
crates/synapse-ebpf-common/  no_std record layouts shared by kernel and sensor
crates/synapse-ebpf/     kernel-side eBPF programs (nightly, excluded from the workspace)
crates/synapse-sensord/  sensor daemon: eBPF + process table, /proc poller fallback, fanotify
crates/synapsectl/       CLI
xtask/                   `cargo xtask build-ebpf`
config/                  synapse.example.toml (a test keeps it equal to the defaults)
packaging/arch/          sysusers.d and tmpfiles.d snippets
packaging/systemd/       synapse-sensord.service
```

M2 sensor design:

- `use_ebpf = true` (the default): the daemon loads `sensors.ebpf_object`, attaches the programs, and a consumer thread reads one ring buffer. The `/proc` poller is **not** started. If a required program (fork, exec, exit) cannot be loaded or attached, everything is detached, the daemon logs why, and the poller starts instead (`degraded=true`). Optional programs (argument capture, exit status, connect) fail one at a time; the daemon keeps running and reports `degraded=true`.
- The kernel side never touches `task_struct` (Rust cannot emit CO-RE relocations yet, so offsets would break on the next kernel). Start time, parent, working directory and resolved executable are derived in userspace from fork edges, exec records and `/proc`; see `proctree.rs` and `translate.rs`.
- Tracepoint field offsets are read from `/sys/kernel/tracing/events/*/*/format` at start-up and handed to the programs as globals. A kernel that renames or resizes a field disables only the program that reads it.
- `ProcKey` is created lazily on first use and never changes: `/proc/<pid>/stat` start time if it agrees with the fork timestamp, otherwise the fork timestamp rounded to a 10 ms tick. fanotify `file_write` uses the same table, so one process has one key across event kinds.
- Kernel-side ring-buffer drops are counted per CPU, summed once a second and added to `sensor_health.dropped`.

M1 sensor design (still how the fallback and fanotify work):

- Two sensor threads (`poller`, `fanotify`) push events into one bounded channel (8192). A full channel drops the event and counts it; the count is reported as `dropped` in `sensor_health` events every 10 s. The main thread stamps sequence numbers and appends to the log.
- The poller scans `/proc` every `sensors.poll_interval_ms` and reports `exec` for new processes and `exit` for vanished ones. Processes present at startup are recorded silently.
- fanotify watches `FAN_CLOSE_WRITE` on the whole filesystem of each path in `sensors.fanotify_marks` and reports `file_write` (path, size, writing process). Events from the sensor's own PID are never reported. Repeated writes to the same path by the same process within one second are merged (counted in memory, not logged).
- If fanotify is unavailable or no filesystem can be marked, the daemon keeps running on polling alone and reports `degraded=true`.

## Decisions and additions beyond the spec

- The store lives in `synapse-common` (the spec layout has no store crate).
- Config gains `[paths]`, `[storage] max_db_mb` and `[logging]`. All keys are optional and default to the spec values.
- Alert-only mode allows levels 0 to 1 (log, notify). `effective_max_auto_level()` is the lower of the mode cap and `response.auto_levels_max`.
- `ai.endpoint` must be `http://` to a loopback IP literal. Host names, including `localhost`, are rejected so DNS or `/etc/hosts` cannot redirect data off the machine.
- `Envelope::ts_ns` is Unix-epoch wall clock. `ProcKey::start_ns` is boot-relative, so a `ProcKey` is only unique within one `boot_id`.
- `boot_id` and SHA-256 serialize as hex strings (JSON cannot hold a u128).
- Paths and argv are plain JSON strings when UTF-8 and `{"hex": "..."}` otherwise; the round trip is lossless.
- `(boot_id, seq)` is indexed but not unique, because `seq` restarts when the sensor restarts.
- `TamperKind` variants are my choice; the spec names the type but not its contents.
- fanotify uses `FAN_MARK_FILESYSTEM`, not `FAN_MARK_MOUNT` as spec 5.2 says. Mount marks attach to one mount object, so a service with `ProtectSystem=` (a private mount namespace) would silently stop seeing writes from the rest of the system. Filesystem marks do not have that problem.
- The sensor unit adds `CAP_SYS_PTRACE` to the spec's capability list: reading `/proc/<pid>/exe` and `cwd` of other users' processes requires it. (M1 said M2 would remove the need. It does not: the kernel programs cannot report the resolved executable or the working directory without `task_struct`.) M2 also adds `CAP_BPF` and `CAP_PERFMON`.
- **M2 scope.** The spec's tracepoint list is longer than the M2 milestone line. Only exec, exit, fork and connect are built; `bind`/`listen`, `ptrace`, `memfd_create`, module loading and `setuid` come with the rules that need them (M3 and later). There is no `Fork` event in the schema: forks only feed the process table.
- **Connect via kprobe, not tracepoint.** `sys_enter_connect` cannot tell TCP from UDP. `inet_stream_connect` / `inet_dgram_connect` can, and receive the address already copied into kernel memory. Kprobes are not a stable ABI; if a kernel inlines or renames them the connect programs fail to attach and the sensor reports `degraded` (the rest keeps working). `sendto` on an unconnected UDP socket is not seen.
- **Arguments are captured at `execve` entry** (before the old address space disappears), up to 32 arguments, 512 bytes each, 4096 bytes in total. Longer arguments are cut (the NUL is always kept). Failed `execve` calls leave no event.
- **`uid` in `exec` and `connect` is the real uid** (`bpf_get_current_uid_gid`). M1's poller reported the owner of `/proc/<pid>`, which is the effective uid, so they differ for set-uid programs.
- **Exit status** is known only when the process called `exit_group` (normal exit). A process killed by a signal reports `code = -1`, the same value the poller uses for "unknown". Only the thread-group leader's exit is reported.
- **The eBPF object declares the license `Dual MIT/GPL`.** The kernel only lets a program call the probe-read and ring-buffer helpers if its license is GPL-compatible. This does not force the userspace code to be GPL, but you still need to pick a project license (none is chosen yet).
- **Pinned to aya 0.13 / aya-ebpf 0.1.** aya 0.14 and aya-ebpf 0.2 exist (June 2026); I wrote against the API I know. Moving up means changing both sides at once.
- M1 uses std threads and `std::sync::mpsc::sync_channel`, not tokio. The bounded, never-blocking, drop-and-count behaviour of hard rule 6 is kept. tokio arrives with the engine (M3), where async IPC needs it.
- `unsafe` lives only in `synapse-sys` (three small functions, each with a `SAFETY:` comment, `undocumented_unsafe_blocks = deny`). The rest of the workspace still has `unsafe_code = forbid`. Event parsing is safe code.
- `/proc/<pid>/stat` times use `USER_HZ = 100` as a constant (true on all Linux architectures) to avoid an `unsafe` `sysconf` call.
- Retention prunes `events` only. Alerts, verdicts and actions are kept; an alert's event link becomes NULL when its event is pruned.

## Not done yet

M3 to M8 in full. In particular: no daemons besides the sensor, no IPC, no rules, no responder, no AI analyzer.

M2 specifics:

- Not done: `synapsectl status`; reloading detached programs (M6); embedding the eBPF object in the binary (M7, PKGBUILD); `FAN_OPEN_EXEC_PERM`; the other tracepoints listed above; running the poller as a live fallback if the eBPF consumer dies after start-up (it reports `degraded` and stops delivering process events until the daemon restarts).
- The event schema has no field for "argument list was truncated"; the kernel flag is decoded but not yet surfaced.
- `exe` is resolved from `/proc/<pid>/exe` after the exec was reported, so a process that already exec'd again or exited gets the path as given to `execve` (possibly relative) instead.

M1 specifics:

- Only `exec`, `exit` and `file_write` are produced. `connect`, `listen`, `module_load`, `ptrace` need eBPF (M2). `file_create`, `file_unlink` and `file_rename` need fanotify FID mode (not started). `file_write.sha256` is always null (hashing belongs to the engine).
- No `FAN_OPEN_EXEC_PERM` pre-exec scan: it needs the scanner from M3.
- `synapsectl status` is not implemented, so degraded mode is only visible in `sensor_health` events.
- The sensor does not write to SQLite; the engine will read the log in M3.
- `tail` shows only the live `events.jsonl`, not rotated files.
- No license chosen. No CI.

## Known risks

- **M2 has never been compiled, and no eBPF program has been loaded by a verifier.** The userspace half (record decoding, process table, translator, tracefs parser) is ordinary Rust with tests that need no kernel; the kernel half is where I expect trouble. Most likely, in order: (1) the verifier rejecting the argument-capture loop in `sys_enter_execve` (it is a separate, optional program on purpose, so exec events still flow without it); (2) the import path `aya_ebpf::helpers::gen::{...}` in `crates/synapse-ebpf/src/main.rs` (one `mod raw`, one line to change); (3) `RingBufEntry` / map method names or `unsafe`-ness in aya-ebpf 0.1; (4) `RingBuf: AsRawFd` and `PerCpuValues::iter` in aya 0.13 (`ebpf.rs`); (5) the kprobe targets on your kernel. Send me the compiler or verifier output and I will fix it.
- Thread creation also produces fork records (the kernel gives no way to tell without `task_struct`). They are cheap, but a thread-heavy workload raises the ring-buffer rate; watch `dropped`.
- A main thread that calls `pthread_exit` while other threads continue is reported as exited early.

- **M1 has never been compiled.** It was written in an environment without a Rust toolchain. Expect a few compile errors, most likely in `synapse-sys` (libc signatures for `fanotify_init`/`fanotify_mark`) and in trait or borrow details elsewhere. M0 is verified (44 tests on Arch).
- Polling misses processes that start and exit between two scans, and cannot see exit codes (`exit` events carry `code = -1`). `exec` describes the process as found at scan time. M2 fixes all three.
- A process that wrote a file and exited before the sensor looked it up is reported with `start_ns = 0`.
- Two rotations between two `tail -f` polls (200 ms) could skip the lines in the middle file. With the default 64 MiB rotation this is not realistic.
- fanotify on a busy system is chatty (journald is excluded by default). Expect large logs on a build or package upgrade; rotation caps them (64 MiB x 6 files by default).
- If `fanotify_read` reports a queue overflow, the number of lost events is unknown; it is counted as one drop.
- M0 was developed on Ubuntu 24.04 with Rust 1.91 and confirmed on Arch. Dependency pins (`rusqlite` 0.37, `toml` 0.9, `signal-hook` 0.3) may need bumps on your toolchain.
- `synchronous = NORMAL` in WAL can lose the last few transactions on power loss. Fine for telemetry; M4 should reconsider it for action and undo records.
- The `O_NOFOLLOW` symlink check and SQLite's own open are separate steps. The real protection is that the state directory is not writable by untrusted users.
- Size-cap accounting counts database pages, not the `-wal` file, and prunes events only.
- The config permission check rejects world-writable files but does not check ownership.
