# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow milestones until 1.0.

## [Unreleased]

### Renamed
- **Synapse is now AI Antivirus** (`ai-antivirus`). Package `ai-antivirus` (replaces and conflicts with `synapse-edr`), CLI
  `ai-antivirus` (was `synapsectl`), daemons `ai-antivirus-{sensord,engined,responderd,analyzer,notify}` (`synapse-ai` is
  now `ai-antivirus-analyzer`), crates `ai-antivirus-*`, paths `/etc/ai-antivirus`, `/var/lib/ai-antivirus`,
  `/var/log/ai-antivirus`, `/run/ai-antivirus`, system users `ai-antivirus` / `ai-antivirus-analyzer`, cgroup slice
  `ai_antivirus.slice`, nft table `ai_antivirus`, environment `AI_ANTIVIRUS_*`, rule ids `AV-*` (were `SYN-*`).
- Upgrading from `synapse-edr`: the install script carries `/etc/synapse/synapse.toml` (or its `.pacsave`) over once, with the
  paths renamed; the package default is kept as `ai-antivirus.toml.from-synapse`. Old data stays in `/var/lib/synapse`.
- Version 0.8.0.

### Exceptions
- **Programs and folders left alone**, in `/etc/ai-antivirus/exceptions.toml` (new key `engine.exceptions_file`); without
  the file a built-in list of AI coding tools applies (Claude Code, Antigravity / agy, Gemini CLI, Codex, Cursor and its CLI,
  Windsurf, Aider, OpenCode, GitHub Copilot CLI, Goose). A program exception drops behavior alerts about the program and
  everything it starts; malware found in a file it touches is still reported, capped at a notification. A folder exception
  skips scanning there and drops alerts about its files. `ai-antivirus exceptions [list|add|remove|reset] [--json]`
  (changes need root); the engine reloads the file within a few seconds. Never dropped: AV-B-0004, AV-B-0020, self-protection.
  Broad entries (shells, interpreters, sudo, terminals, /usr/bin, a whole home, ~/Downloads, /tmp ...) are refused.
  Processes started before the engine are matched through /proc. See README, "Exceptions".

### Fixed
- The engine unit's `ProtectProc=invisible` hid every other user's `/proc/<pid>` from the engine, so the CPU check of
  AV-B-0015 (mining-pool port + busy CPU) could never read a user process. Now `ProtectProc=default`.
- Alerts finished by the CPU check were not capped at `notify` for `engine.allow_exe` programs.

### Faster
- **On-demand scans are about 7x faster** (15k files / 2.5 GB, warm cache: 4.4 s -> 0.6 s). Files are scanned on several
  threads (`-j N`, default one per core up to 8), each with one YARA-X scanner it keeps (making a scanner cost about as much
  as scanning a small file), and a file up to 16 MiB is read once for both the hash and YARA (it was read twice).
  The engine's automatic checks use the same path. Output stays in file order.
- `ai-antivirus scan --json`: one JSON object per file with findings, then a summary (files, found, seconds, threads);
  the Halcyon Security center runs scans with it. The summary line now includes the time taken.

### Detection
- New shipped YARA file `rules/yara/linux-threats.yar`: PHP web shells that run request data, encoded payloads piped into
  a shell, the Diamorphine and Reptile kernel rootkits, scripts that collect SSH private keys and upload them. Each rule
  needs a specific string; checked against 410k files on an Arch desktop (`/usr`, home): no hits outside the rule files
  themselves. Tests: `crates/ai-antivirus-rules/tests/shipped_yara.rs` (samples fire, ordinary files and the machine's own
  binaries stay quiet).

### Fixed (found by installing the package on an Arch desktop, 2026-10-25)
- **The engine could not read home directories** (it ran with no capabilities and homes are 0700), so nothing written
  to `~/Downloads` was ever scanned: EICAR there raised no alert. The unit now has `CAP_DAC_READ_SEARCH` (read any file,
  nothing else; still no network, no writes outside its state folders). Live: EICAR in ~/Downloads alerts at once.
- **Desktop notifications never arrived:** the responder creates the spool with `mode(0o640)`, but its `UMask=0077` made
  it 0600, so the notify group could not read it. The mode is now set explicitly. The notifier no longer restarts every
  5 s forever without access (exit 3 + `RestartPreventExitStatus=3`; group membership needs a new login anyway).
  Live: a real notification reached the desktop.
- `cargo xtask build-ebpf` (and so `makepkg`) failed on every rustup machine: rustup passes `RUSTUP_TOOLCHAIN` to the
  inner cargo, which overrode the eBPF crate's nightly pin. Cleared now.
- `status` checked a service named `ai` (`ai-antivirus-ai`, which does not exist since the rename); it is `analyzer`.
  `ask` is told what each service is and that unreadable figures are unknown, not zero (it had reported the antivirus as
  down while it ran).
- AV-B-0001: a socket that is in neither /proc/net/unix nor the TCP/UDP tables is already closed and not a reverse
  shell (editor and agent hooks are often gone before the engine looks; they raised a high alert every second).
  A real local reverse shell (`bash -i < /dev/tcp/127.0.0.1/PORT`) still alerts.
- `ai-antivirus alerts | head` no longer prints "error: Broken pipe".

### Fewer false alarms
- **AV-B-0001 (reverse shell) only fires on a network socket.** New rule condition `stdin_socket_network`: stdin is a
  socket the engine cannot find in `/proc/net/unix`. Editors' terminals and coding agents hand a shell a Unix-domain
  socket as stdin; in a live run on an Arch desktop every command a coding agent ran raised a high alert. A socket that
  cannot be looked up still counts as network. Tests: `a_shell_fed_by_a_unix_socket_is_not_a_reverse_shell` and the
  /proc/net/unix parser.
- Live check (root, /proc fallback, 2026-10-25): EICAR written to ~/Downloads alerted within a second; a program run from
  /tmp raised AV-B-0013.

### Local model
- `ask` prefers **qwen3.5:4b** (3.3 GB at q4: fits a 6 GB GPU with room for the context), then the qwen2.5 / llama 3.2
  models as before. Requests send `"think": false`, and a `<think>` block a model adds anyway is dropped (`ask` and the
  analyzer's JSON validation).

### Added (0.8.0 work)
- `ai-antivirus status [--json]`: services, sensor `degraded`, last event, alerts per severity in 24 h, unacknowledged,
  pending actions, circuit breaker. Read-only, works without root (what it cannot read is null); the Halcyon Security
  center reads the JSON.
- Alert acknowledgement: `ai-antivirus ack <ID>... | --all`, `ai-antivirus alerts --unacked` (the `acknowledged` column
  already existed in schema v1; no migration needed). Store: `ack_alerts`, `ack_all_alerts`, `unacked_alerts`, `alert_counts`.
- `ai-antivirus ask "..." [--json]`: the local model from `[ai]` (loopback only, enforced by the config) answers from the
  status figures and the newest alerts; advice only, with a fixed list of commands it may name.
- Rule updates: `ai-antivirus rules-update DIR [--dry-run] [--target]` validates behavior + YARA rules, verifies the
  signature when `engine.require_signed_rules` is on, prints added / removed / changed ids, installs with a rename and
  keeps `<rules_dir>.prev`; `ai-antivirus rules-rollback` swaps it back. Only regular files are copied (no symlinks).
- Rule condition `min_cpu_percent` + `cpu_window_secs` (connect / listen): the engine samples the process's CPU time at
  the event and again after the window (at most 256 checks waiting). New shipped rule **AV-B-0015**: mining-pool port
  plus 60 % CPU over 60 s (GAPS item 6). AV-B-0012 (port only) stays as the early, weak signal.

### Fixed
- The responder's guard refused loopback / link-local / multicast addresses but not the machine's **default gateways and
  DNS resolvers**: a `block` on one of them cut the whole network. They are refused now (read from `/proc/net/route`,
  `/proc/net/ipv6_route`, `/etc/resolv.conf`, `/run/systemd/resolve/resolv.conf`; injectable for tests).
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) went into the IPv6 nft set, where they never match IPv4 traffic; they are
  converted to IPv4 before the guard check and the set choice.

### Performance
- A quiet event (no rule matches) went from ~2.3 µs to ~0.14 µs in the engine (`per_event_cost`, an ignored timing test):
  `Rule::matches` compared the exclusion lists (path comparisons, 47 of them with the shipped rules) before checking the
  event kind; now the kind is checked first. Also: event details are built only when a rule matched, the ancestor walk
  runs only for event kinds whose rules use `exclude_ancestor_exe`, and the pacman lock probe (a stat per event,
  ~600 ns) is cached for 100 ms. With the real probe: ~760 ns -> ~160 ns per event.

### Added
- `docs/SOAK.md`: step-by-step guide for the spec's two-week alert-only soak (record, review, label, tune, exit criteria).
- `scripts/soak-report.py`: read-only summary of `ai-antivirus alerts --json` (by severity, rule, day; repeat offenders), a
  CSV to label alerts by hand (`--csv`) and the false-positive rate from the labeled CSV (`--rate`).
- `docs/GAPS.md`: what is still open, in priority order, with task text for each item.
- `.github/workflows/ci.yml`: fmt, clippy and tests in an Arch container (written without being run).

### Fixed
- `ai-antivirus.install`: the post-install hint ran `ai-antivirus alerts` as the invoking user, which cannot read the
  database (it is readable by `ai-antivirus` and root); it now says `sudo -u ai-antivirus ai-antivirus alerts`. The post-remove
  message did not mention `/var/lib/ai-antivirus-private`, where quarantined files and restore evidence now live.
- CHANGELOG: the 0.2.0 heading still said "not yet compiled".

## [0.7.0] - M6 self-protection and M7 packaging (unreleased)

### Added
- M6: systemd readiness and watchdog heartbeats (`ai-antivirus-common::notify`) in the sensor, engine and responder; their units are `Type=notify` with `WatchdogSec=30`.
- M6: signed rule bundles (ed25519): `ai-antivirus keygen`, `rules-sign`, `rules-verify`; `engine.require_signed_rules`, `engine.rules_pubkey`. Verified at start and on every reload; a failed reload keeps the running rules and raises `AV-T-0004`. `approve-rule --key` signs again.
- M6: engine self-checks: own binaries against pacman's records (`AV-T-0001`, offers `restore`), debugger on the engine (`AV-T-0002`), silent sensor (`AV-T-0003`), `Tamper` events from the sensor become alerts (`AV-T-0010`..`0013`). Shipped rule `AV-B-0020` (writes to AI Antivirus's own files outside pacman). Config `engine.self_check_files`.
- M6: sensor self-watch: a canary exec every 60 s checks that the eBPF stream still reports, and a restart (through systemd) re-attaches the probes when it does not; debugger check on the sensor.
- M6: the `restore` action in the responder (level 6, always needs approval): pacman-owned files from the pacman cache, verified against the package's `mtree`, evidence kept, undo.
- M7: `packaging/arch/PKGBUILD`, `ai-antivirus.install`, pacman hooks `00-ai-antivirus-pre` and `zz-ai-antivirus-post` (+ `/usr/lib/ai-antivirus/pacman-post`), `ai-antivirus pacman-begin`, `pacman-end`, `scan-pkgbuild`.
- Config: `paths.private_dir`.
- M8: `SystemCallFilter=` in the sensor, engine and responder units (traced under `strace`; the sensor adds `bpf perf_event_open fanotify_init fanotify_mark` to `@system-service`), `SystemCallErrorNumber=EPERM` in all four.
- M8: `lineage` on `exec` events (the sensor's chain of ancestors, including processes that only forked); the engine's `exclude_ancestor_exe` follows it.
- M8: seeded mutation tests for the rule parser, the `mtree` reader, the analyzer's answer validator and extractors, the control-socket request parser and event-log lines; pipeline regression tests for both soak findings.

### Changed
- Rules now live in `/etc/ai-antivirus/rules` (was `/var/lib/ai-antivirus/rules`), the benign-activity recording in `/etc/ai-antivirus/corpus/`, quarantine and restore evidence in `/var/lib/ai-antivirus-private` (was inside `/var/lib/ai-antivirus`). Root-owned folders no longer sit inside a folder owned by an unprivileged user (found by installing the package in a VM: `systemd-tmpfiles` refused the layout, rightly).
- The responder unit no longer sets `ProtectSystem=` (restore writes under `/usr` and `/etc`).
- `Event::Tamper` is turned into an alert by the engine. Duplicate suppression for file findings includes the file's hash.
- Workspace version 0.7.0.

### Fixed
- The sensor hung instead of exiting when it asked for a restart (its threads were never told to stop).
- Restore did not set the modification time, so `pacman -Qkk` still complained.
- The AI hand-off files were created with the services' umask and were unreadable for the other service; they now get explicit modes.
- Soak: `AV-B-0001` fired on `ldd` run by pacman hooks through subshells (the ancestor trail was broken; fixed by `lineage`); `AV-B-0010` fired on `gzip` over hundreds of files (compressors are now excluded, `gpg` and `openssl` are not).

## [0.6.0] - M5: AI analyzer (unreleased)

### Added
- `ai-antivirus-analyzer`: bundle builder (credential files never read), prompt with random data markers, Ollama client (temperature 0, JSON-schema output, timeout), strict output validator, spool daemon with an hourly budget. `packaging/systemd/ai-antivirus-analyzer.service` (no capabilities, localhost only).
- Engine: queues alerts for analysis, validates and imports answers, checks proposed rules against a recording of ordinary activity, reloads changed rules without a restart.
- `ai-antivirus ai-notes`, `proposals`, `proposal-show`, `approve-rule`, `reject-rule`.
- Store: schema v3 (`ai_notes`). Config: `ai.max_per_hour`, `ai.min_severity`, `ai.corpus`, `paths.ai_dir`. tmpfiles and sysusers entries for the analyzer's folder.

## [0.5.0] - M4: responder with dry-run, approval and undo (unreleased)

### Added
- `ai-antivirus-responderd`: follows the alerts table (cursor in `state`; the history before the first start is skipped) and turns each alert's action into an `actions` row. Decides by mode ladder, `response.dry_run`, circuit breaker, approval above `response.auto_levels_max` (levels 4 to 6 always), and the per-minute budget `engine.max_actions_per_minute` (automatic level 2+ actions; tripping it falls back to dry runs and notifies). Checks the allowlist against the live system: PID 1, kernel threads, session leaders, AI Antivirus, systemd, `engine.allow_exe`, pacman (lock or ancestry), PID reuse; for files: system and AI Antivirus folders, devices, pacman-owned files; for addresses: loopback, link-local, multicast, unspecified.
- Actions: `notify` (spool for `ai-antivirus-notify`), `freeze` (process tree into `ai_antivirus.slice/suspect-<id>`, `cgroup.freeze`), `kill` (freeze then `cgroup.kill`; pidfd SIGKILL without cgroup v2), `quarantine` (mode-000 copy plus sidecar, inode re-check, unlink), `block` (nftables `inet ai-antivirus` sets with per-element timeout, JSON via `nft -j -f -`). Undo for freeze, quarantine and block.
- Control socket `/run/ai-antivirus/responder.sock` (0600, root peers only via `SO_PEERCRED`): approve, reject, undo, breaker reset, status.
- `ai-antivirus-notify`: user-session notifier (spool follower, escaped text, burst limit, `notify-send`). `packaging/systemd/user/ai-antivirus-notify.service`.
- `ai-antivirus actions [--pending]`, `approve`, `reject`, `undo`, `breaker-reset`, `responder-status`.
- `ai-antivirus-sys::process`: `pidfd_open`, `pidfd_send_signal`, `peer_cred`.
- Store: `get_alert`, `max_alert_id`, `pending_actions`; `executed_since` takes a minimum level and counts only automatic actions.
- Config: `response.dry_run`, `response.cgroup_root`, `response.notify_dir`.
- `packaging/systemd/ai-antivirus-responderd.service` (root, 8 capabilities). sysusers: group `ai-antivirus-notify`. tmpfiles: `/var/lib/ai-antivirus/quarantine` (0700 root), `/run/ai-antivirus-notify` (2750 root:ai-antivirus-notify).

### Changed
- The engine enforces `engine.allow_exe`: alerts about those programs ask for `notify` at most (`detail.allowlisted`, `detail.rule_action`).
- Workspace version 0.5.0.

### Fixed
- `Store::alerts_after` skipped older alerts when more than `limit` arrived at once; it now pages by id.

## [0.4.0] - M3: rule engine, YARA-X, hash table, pacman trust (unreleased)

### Added
- `ai-antivirus-engined`: follows `events.jsonl`, keeps a process table (warmed up from the log at start, pipe ends paired), runs L0 pacman trust, L1 hash table, L2 YARA-X and L3 behavior rules, stores alerts; `--replay FILE` prints alerts for a recorded log. `packaging/systemd/ai-antivirus-engined.service` (user `ai-antivirus`, no capabilities, no network).
- `ai-antivirus-rules`: strict TOML behavior-rule schema (all problems reported at once), matcher, sliding threshold windows per process or process tree, YARA-X loading and scanning with a timeout, SHA-256, pacman `desc`/`files`/`mtree` reader.
- Shipped rules: 11 behavior rules (`rules/behavior/00-shipped.toml`) and YARA rules (EICAR, reverse-shell one-liners, XMRig, ld.so.preload rootkits).
- `ai-antivirus alerts`, `scan`, `rules`, `trust-baseline`, `integrity`, `hash-add`.
- Store: alert reads, hash table and trust-cache operations.
- Events: `exec.stdio` and `file_write.head_entropy` (optional fields; older logs still parse). `entropy` module.
- Config: `engine.rules_dir`, `scan_max_mb`, `yara_timeout_ms`, `scan_on_write`, `max_scans_per_sec`.
- `tmpfiles.d`: root-owned `/var/lib/ai-antivirus/rules`.

### Fixed
- M2: a test did not compile (temporary dropped while borrowed). M2 is now built and verified on kernel 7.2 (all programs attach).
- Found in the test VM: pacman hooks run with a socket on stdin and matched the reverse-shell rule; rules gain `exclude_ancestor_exe`.

## [0.3.0] - M2: eBPF sensor, process tree (unreleased)

### Added
- `crates/ai-antivirus-ebpf` (kernel side, nightly, `bpfel-unknown-none`): programs for `sched_process_fork`, `sched_process_exec`, `sched_process_exit`, `sys_enter_execve{,at}` (argument capture), `sys_enter_exit_group` (exit status) and kprobes on `inet_stream_connect` / `inet_dgram_connect` (TCP/UDP connect). 8 MiB ring buffer, per-CPU drop counter.
- `crates/ai-antivirus-ebpf-common`: `no_std` record layouts shared with the sensor, with safe decoding and layout tests.
- `ai-antivirus-sensord`: eBPF loader (each program attached on its own; fork/exec/exit required, the rest optional), ring-buffer consumer, `tracefs` format parser that passes tracepoint field offsets to the kernel side, process table (`ProcKey` identity, parent links, exit tombstones, ancestry), record translator. Kernel drops are added to `sensor_health.dropped`.
- `Connect` events (the schema had them since M0), `Exit` events with real exit status when the process called `exit_group`.
- `ai-antivirus-sys::wait_readable` (safe `poll` wrapper).
- `xtask`: `cargo xtask build-ebpf [--release]` -> `target/bpf/ai-antivirus-ebpf.o`.
- Config key `sensors.ebpf_object`.

### Changed
- With eBPF loaded the `/proc` poller is not started; without it (or with `use_ebpf = false`) M1 behaviour is unchanged. `sensor_health.degraded` is true when eBPF was wanted but is missing or partial.
- fanotify `file_write` events take their `ProcKey` from the process table when eBPF runs.
- Sensor unit: adds `CAP_BPF` and `CAP_PERFMON`.
- Workspace version 0.3.0.

## [0.2.0] - M1: /proc and fanotify sensor, event log, tail (unreleased)

### Added
- `ai-antivirus-sensord`: `/proc` process poller (`exec`, `exit`) and fanotify file-write sensor (`file_write`), bounded drop-and-count channel, periodic `sensor_health`, graceful degraded mode without `CAP_SYS_ADMIN`.
- `ai-antivirus-sys`: the only `unsafe` code in the workspace (fanotify init, mark, descriptor adoption), with `SAFETY:` comments and `undocumented_unsafe_blocks = deny`.
- `ai_antivirus_common::eventlog`: rotating JSONL writer (mode 0640, `O_NOFOLLOW`) and a rotation-aware follower.
- `ai-antivirus tail` (`-n`, `-f`, `--json`, `--kind`, `--file`) with terminal-escape sanitizing.
- Config keys `sensors.use_fanotify`, `fanotify_exclude`, `poll_interval_ms`, `event_log_max_mb`, `event_log_keep`.
- `packaging/systemd/ai-antivirus-sensord.service`.

### Changed
- `tmpfiles.d`: `/var/log/ai-antivirus` is now `2750 root:ai-antivirus` (the sensor runs as root and the engine only reads).
- fanotify marks whole filesystems (`FAN_MARK_FILESYSTEM`) instead of mounts.

## [0.1.0] - M0: workspace, schema, config, logging, store

### Added
- Cargo workspace with `ai-antivirus-common` and `ai-antivirus`.
- Event schema (`ProcKey`, `Envelope`, `Event`, `TamperKind`) with lossless serde for non-UTF-8 paths and arguments.
- Strict TOML config: unknown keys rejected, all problems reported at once, loopback-only AI endpoint, mode-capped response level, world-writable config refused.
- tracing-based logging (text or JSON on stderr, `RUST_LOG` override).
- SQLite store: WAL, mode 0600, symlink refused, versioned migration, batched event inserts, alert inserts, statistics, retention cleanup by age and size.
- `ai-antivirus`: `config-check`, `db-init`, `db-stats`, `db-cleanup`.
- `sysusers.d` and `tmpfiles.d` snippets, example config.
- Workspace lints: `unsafe_code = forbid`, `clippy::unwrap_used` and `clippy::expect_used` = deny.
