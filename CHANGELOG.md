# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow milestones until 1.0.

## [0.7.0] - M6 self-protection and M7 packaging (unreleased)

### Added
- M6: systemd readiness and watchdog heartbeats (`synapse-common::notify`) in the sensor, engine and responder; their units are `Type=notify` with `WatchdogSec=30`.
- M6: signed rule bundles (ed25519): `synapsectl keygen`, `rules-sign`, `rules-verify`; `engine.require_signed_rules`, `engine.rules_pubkey`. Verified at start and on every reload; a failed reload keeps the running rules and raises `SYN-T-0004`. `approve-rule --key` signs again.
- M6: engine self-checks: own binaries against pacman's records (`SYN-T-0001`, offers `restore`), debugger on the engine (`SYN-T-0002`), silent sensor (`SYN-T-0003`), `Tamper` events from the sensor become alerts (`SYN-T-0010`..`0013`). Shipped rule `SYN-B-0020` (writes to Synapse's own files outside pacman). Config `engine.self_check_files`.
- M6: sensor self-watch: a canary exec every 60 s checks that the eBPF stream still reports, and a restart (through systemd) re-attaches the probes when it does not; debugger check on the sensor.
- M6: the `restore` action in the responder (level 6, always needs approval): pacman-owned files from the pacman cache, verified against the package's `mtree`, evidence kept, undo.
- M7: `packaging/arch/PKGBUILD`, `synapse-edr.install`, pacman hooks `00-synapse-pre` and `zz-synapse-post` (+ `/usr/lib/synapse/pacman-post`), `synapsectl pacman-begin`, `pacman-end`, `scan-pkgbuild`.
- Config: `paths.private_dir`.
- M8: `SystemCallFilter=` in the sensor, engine and responder units (traced under `strace`; the sensor adds `bpf perf_event_open fanotify_init fanotify_mark` to `@system-service`), `SystemCallErrorNumber=EPERM` in all four.
- M8: `lineage` on `exec` events (the sensor's chain of ancestors, including processes that only forked); the engine's `exclude_ancestor_exe` follows it.
- M8: seeded mutation tests for the rule parser, the `mtree` reader, the analyzer's answer validator and extractors, the control-socket request parser and event-log lines; pipeline regression tests for both soak findings.

### Changed
- Rules now live in `/etc/synapse/rules` (was `/var/lib/synapse/rules`), the benign-activity recording in `/etc/synapse/corpus/`, quarantine and restore evidence in `/var/lib/synapse-private` (was inside `/var/lib/synapse`). Root-owned folders no longer sit inside a folder owned by an unprivileged user (found by installing the package in a VM: `systemd-tmpfiles` refused the layout, rightly).
- The responder unit no longer sets `ProtectSystem=` (restore writes under `/usr` and `/etc`).
- `Event::Tamper` is turned into an alert by the engine. Duplicate suppression for file findings includes the file's hash.
- Workspace version 0.7.0.

### Fixed
- The sensor hung instead of exiting when it asked for a restart (its threads were never told to stop).
- Restore did not set the modification time, so `pacman -Qkk` still complained.
- The AI hand-off files were created with the services' umask and were unreadable for the other service; they now get explicit modes.
- Soak: `SYN-B-0001` fired on `ldd` run by pacman hooks through subshells (the ancestor trail was broken; fixed by `lineage`); `SYN-B-0010` fired on `gzip` over hundreds of files (compressors are now excluded, `gpg` and `openssl` are not).

## [0.6.0] - M5: AI analyzer (unreleased)

### Added
- `synapse-ai`: bundle builder (credential files never read), prompt with random data markers, Ollama client (temperature 0, JSON-schema output, timeout), strict output validator, spool daemon with an hourly budget. `packaging/systemd/synapse-ai.service` (no capabilities, localhost only).
- Engine: queues alerts for analysis, validates and imports answers, checks proposed rules against a recording of ordinary activity, reloads changed rules without a restart.
- `synapsectl ai-notes`, `proposals`, `proposal-show`, `approve-rule`, `reject-rule`.
- Store: schema v3 (`ai_notes`). Config: `ai.max_per_hour`, `ai.min_severity`, `ai.corpus`, `paths.ai_dir`. tmpfiles and sysusers entries for the analyzer's folder.

## [0.5.0] - M4: responder with dry-run, approval and undo (unreleased)

### Added
- `synapse-responderd`: follows the alerts table (cursor in `state`; the history before the first start is skipped) and turns each alert's action into an `actions` row. Decides by mode ladder, `response.dry_run`, circuit breaker, approval above `response.auto_levels_max` (levels 4 to 6 always), and the per-minute budget `engine.max_actions_per_minute` (automatic level 2+ actions; tripping it falls back to dry runs and notifies). Checks the allowlist against the live system: PID 1, kernel threads, session leaders, Synapse, systemd, `engine.allow_exe`, pacman (lock or ancestry), PID reuse; for files: system and Synapse folders, devices, pacman-owned files; for addresses: loopback, link-local, multicast, unspecified.
- Actions: `notify` (spool for `synapse-notify`), `freeze` (process tree into `synapse.slice/suspect-<id>`, `cgroup.freeze`), `kill` (freeze then `cgroup.kill`; pidfd SIGKILL without cgroup v2), `quarantine` (mode-000 copy plus sidecar, inode re-check, unlink), `block` (nftables `inet synapse` sets with per-element timeout, JSON via `nft -j -f -`). Undo for freeze, quarantine and block.
- Control socket `/run/synapse/responder.sock` (0600, root peers only via `SO_PEERCRED`): approve, reject, undo, breaker reset, status.
- `synapse-notify`: user-session notifier (spool follower, escaped text, burst limit, `notify-send`). `packaging/systemd/user/synapse-notify.service`.
- `synapsectl actions [--pending]`, `approve`, `reject`, `undo`, `breaker-reset`, `responder-status`.
- `synapse-sys::process`: `pidfd_open`, `pidfd_send_signal`, `peer_cred`.
- Store: `get_alert`, `max_alert_id`, `pending_actions`; `executed_since` takes a minimum level and counts only automatic actions.
- Config: `response.dry_run`, `response.cgroup_root`, `response.notify_dir`.
- `packaging/systemd/synapse-responderd.service` (root, 8 capabilities). sysusers: group `synapse-notify`. tmpfiles: `/var/lib/synapse/quarantine` (0700 root), `/run/synapse-notify` (2750 root:synapse-notify).

### Changed
- The engine enforces `engine.allow_exe`: alerts about those programs ask for `notify` at most (`detail.allowlisted`, `detail.rule_action`).
- Workspace version 0.5.0.

### Fixed
- `Store::alerts_after` skipped older alerts when more than `limit` arrived at once; it now pages by id.

## [0.4.0] - M3: rule engine, YARA-X, hash table, pacman trust (unreleased)

### Added
- `synapse-engined`: follows `events.jsonl`, keeps a process table (warmed up from the log at start, pipe ends paired), runs L0 pacman trust, L1 hash table, L2 YARA-X and L3 behavior rules, stores alerts; `--replay FILE` prints alerts for a recorded log. `packaging/systemd/synapse-engined.service` (user `synapse`, no capabilities, no network).
- `synapse-rules`: strict TOML behavior-rule schema (all problems reported at once), matcher, sliding threshold windows per process or process tree, YARA-X loading and scanning with a timeout, SHA-256, pacman `desc`/`files`/`mtree` reader.
- Shipped rules: 11 behavior rules (`rules/behavior/00-shipped.toml`) and YARA rules (EICAR, reverse-shell one-liners, XMRig, ld.so.preload rootkits).
- `synapsectl alerts`, `scan`, `rules`, `trust-baseline`, `integrity`, `hash-add`.
- Store: alert reads, hash table and trust-cache operations.
- Events: `exec.stdio` and `file_write.head_entropy` (optional fields; older logs still parse). `entropy` module.
- Config: `engine.rules_dir`, `scan_max_mb`, `yara_timeout_ms`, `scan_on_write`, `max_scans_per_sec`.
- `tmpfiles.d`: root-owned `/var/lib/synapse/rules`.

### Fixed
- M2: a test did not compile (temporary dropped while borrowed). M2 is now built and verified on kernel 7.2 (all programs attach).
- Found in the test VM: pacman hooks run with a socket on stdin and matched the reverse-shell rule; rules gain `exclude_ancestor_exe`.

## [0.3.0] - M2: eBPF sensor, process tree (unreleased)

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
