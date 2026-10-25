# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow milestones until 1.0.

## [0.3.0] - M2: eBPF sensor, process tree (unreleased, not yet compiled or loaded on a kernel)

### Added
- `crates/synapse-ebpf` (kernel side, nightly, `bpfel-unknown-none`): programs for `sched_process_fork`, `sched_process_exec`, `sched_process_exit`, `sys_enter_execve{,at}` (argument capture), `sys_enter_exit_group` (exit status) and kprobes on `inet_stream_connect` / `inet_dgram_connect` (TCP/UDP connect). 8 MiB ring buffer, per-CPU drop counter.
- `crates/synapse-ebpf-common`: `no_std` record layouts shared with the sensor, with safe decoding and layout tests.
- `synapse-sensord`: eBPF loader (each program attached on its own; fork/exec/exit required, the rest optional), ring-buffer consumer, `tracefs` format parser that passes tracepoint field offsets to the kernel side, process table (`ProcKey` identity, parent links, exit tombstones, ancestry), record translator. Kernel drops are added to `sensor_health.dropped`.
- `Connect` events (the schema had them since M0), `Exit` events with real exit status when the process called `exit_group`.
- `synapse-sys::wait_readable` (safe `poll` wrapper).
- `xtask`: `cargo xtask build-ebpf [--release]` -> `target/bpf/synapse-ebpf.o`.
- Config key `sensors.ebpf_object`.

### Changed
- With eBPF loaded the `/proc` poller is not started; without it (or with `use_ebpf = false`) M1 behaviour is unchanged. `sensor_health.degraded` is true when eBPF was wanted but is missing or partial.
- fanotify `file_write` events take their `ProcKey` from the process table when eBPF runs.
- Sensor unit: adds `CAP_BPF` and `CAP_PERFMON`.
- Workspace version 0.3.0.

## [0.2.0] - M1: /proc and fanotify sensor, event log, tail (unreleased, not yet compiled)

### Added
- `synapse-sensord`: `/proc` process poller (`exec`, `exit`) and fanotify file-write sensor (`file_write`), bounded drop-and-count channel, periodic `sensor_health`, graceful degraded mode without `CAP_SYS_ADMIN`.
- `synapse-sys`: the only `unsafe` code in the workspace (fanotify init, mark, descriptor adoption), with `SAFETY:` comments and `undocumented_unsafe_blocks = deny`.
- `synapse_common::eventlog`: rotating JSONL writer (mode 0640, `O_NOFOLLOW`) and a rotation-aware follower.
- `synapsectl tail` (`-n`, `-f`, `--json`, `--kind`, `--file`) with terminal-escape sanitizing.
- Config keys `sensors.use_fanotify`, `fanotify_exclude`, `poll_interval_ms`, `event_log_max_mb`, `event_log_keep`.
- `packaging/systemd/synapse-sensord.service`.

### Changed
- `tmpfiles.d`: `/var/log/synapse` is now `2750 root:synapse` (the sensor runs as root and the engine only reads).
- fanotify marks whole filesystems (`FAN_MARK_FILESYSTEM`) instead of mounts.

## [0.1.0] - M0: workspace, schema, config, logging, store

### Added
- Cargo workspace with `synapse-common` and `synapsectl`.
- Event schema (`ProcKey`, `Envelope`, `Event`, `TamperKind`) with lossless serde for non-UTF-8 paths and arguments.
- Strict TOML config: unknown keys rejected, all problems reported at once, loopback-only AI endpoint, mode-capped response level, world-writable config refused.
- tracing-based logging (text or JSON on stderr, `RUST_LOG` override).
- SQLite store: WAL, mode 0600, symlink refused, versioned migration, batched event inserts, alert inserts, statistics, retention cleanup by age and size.
- `synapsectl`: `config-check`, `db-init`, `db-stats`, `db-cleanup`.
- `sysusers.d` and `tmpfiles.d` snippets, example config.
- Workspace lints: `unsafe_code = forbid`, `clippy::unwrap_used` and `clippy::expect_used` = deny.
