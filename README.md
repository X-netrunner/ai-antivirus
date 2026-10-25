# Synapse

AI-assisted EDR and antivirus for Arch Linux. Design: see the Synapse master prompt and design specification (v1.0). This repository is built one milestone at a time.

**Status: M4 built and unit-tested; not yet run as root on a real system.** M3 (engine: pacman trust, hash table, YARA-X, behavior rules) is built and tested on Arch, kernel 7.2, and M2's eBPF programs load and attach there. M4 adds `synapse-responderd`, which acts on alerts: notify, cgroup freeze, kill, quarantine and nftables block. Every action has a dry run, an undo record (`synapsectl undo`), approval for anything above `response.auto_levels_max`, a per-minute budget and a circuit breaker. The default mode is still `alert-only`: the responder records what it *would* do and sends a desktop notification, nothing more. Before you switch modes, read [M4: the responder](#m4-the-responder), including what has not been tried as root yet.

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
crates/synapse-rules/    behavior-rule schema and matcher, threshold windows, YARA-X glue, pacman mtree reader (M3)
crates/synapse-engined/  engine daemon: process table, L0-L3 pipeline, alerts, --replay (M3)
crates/synapse-responderd/  responder daemon: guard, policy, cgroup freeze/kill, quarantine, nft block, undo, control socket (M4)
crates/synapse-notify/   desktop notifier (user service): shows the responder's notifications with notify-send (M4)
crates/synapsectl/       CLI
rules/behavior/          shipped behavior rules (TOML)
rules/yara/              shipped YARA rules
xtask/                   `cargo xtask build-ebpf`
config/                  synapse.example.toml (a test keeps it equal to the defaults)
packaging/arch/          sysusers.d and tmpfiles.d snippets
packaging/systemd/       synapse-sensord.service, synapse-engined.service, synapse-responderd.service, user/synapse-notify.service
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

## M3: the engine

```sh
sudo install -d /var/lib/synapse/rules && sudo cp -r rules/behavior rules/yara /var/lib/synapse/rules/   # root-owned
sudo -u synapse synapsectl trust-baseline       # what pacman installed -> trust cache (~1 s for 250k files)
sudo -u synapse synapse-engined                  # or: systemctl enable --now synapse-engined
synapsectl alerts [-n 50] [--json]               # newest alerts
synapsectl rules [--dir rules]                   # validate and list the rules
sudo synapsectl scan [-q] PATH...                # on demand: trust, hashes, YARA; exit 1 = something found
sudo synapsectl integrity [--package NAME]       # every pacman file vs. its recorded SHA-256; exit 1 = differences
synapsectl hash-add FILE|SHA256 [--good] [--label TEXT]
synapse-engined --replay events.jsonl --rules rules   # run a recorded log through the engine, alerts as JSON lines
```

How an event is handled, cheapest first (spec 7):

- **Process table** from `exec`/`exit` (warmed up from the existing log at start, so running processes are known). It also pairs pipe ends, so `curl ... | sh` is recognized whichever process the kernel reports first.
- **L0 trust.** A file pacman installed whose SHA-256 matches the package's `mtree` is trusted and not YARA-scanned. A mismatch is re-checked against the package's *current* mtree first (an upgrade the cache has not caught up with is not an alert), then reported as `SYN-I-0001`. Files a package marks as editable configuration (`%BACKUP%`, e.g. `/etc/pacman.conf`) are not trust material.
- **L1 hash table** (`hashes`): known bad = `SYN-H-0001`, known good ends the check.
- **L2 YARA-X** on every program that runs and on written files that are executable or in `/tmp`, `/dev/shm`, `/var/tmp`, `~/Downloads`. Results are cached per (inode, size, mtime, ctime); automatic scans are capped at `engine.max_scans_per_sec`.
- **L3 behavior rules** (`rules/behavior/*.toml`). Threshold rules count in a sliding window per process or per process tree (up to the nearest shell, terminal or session program).
- Alerts go to SQLite (`alerts`); the same rule for the same process and path alerts at most once in 5 minutes.

### Behavior rules

```toml
[[rule]]
id = 'SYN-B-0001'                 # SYN-B-NNNN shipped, LOCAL-<name> yours
title = 'Shell with a socket as stdin (reverse shell)'
severity = 'high'                 # low | medium | high | critical
confidence = 0.9                  # 0..1
exclude_exe = []                  # acting programs this rule ignores
exclude_ancestor_exe = ['/usr/bin/pacman']   # ... or anything running under them
match = { event = 'exec', exe_in = ['/usr/bin/bash'], stdin_is_socket = true }
action = 'freeze'                 # log | notify | freeze | kill | quarantine | block | restore (see M4: what runs depends on the mode)
```

`match` keys: `event` (required: `exec`, `exit`, `connect`, `listen`, `file_write`, ...), `exe_in`, `exe_prefix`, `exe_suffix`, `parent_exe_in`; exec only: `argv_contains`, `stdin_is_socket`, `stdout_is_socket`, `stdin_from_exe_in`; file events: `path_in`, `path_prefix`, `path_not_prefix`, `path_suffix` (`~/x` = in every home), `setuid_file`; network: `port_in`; any: `outside_pacman`. Threshold rules add `scope` (`process` | `process_tree`), `window_secs` and `threshold = { events, distinct_files_written, high_entropy_ratio }`. Unknown keys, keys that do not fit the event kind, relative paths and duplicate ids are errors, all reported at once; the engine refuses to start with broken rules.

Shipped: SYN-B-0001 reverse shell, 0002 download piped into a shell, 0003 exec from memfd, 0004 `/etc/ld.so.preload`, 0005 services/timers/autostart/cron written outside pacman, 0006 `authorized_keys` by a non-editor, 0008 new setuid-root file, 0010 ransomware-like burst, 0012 mining-pool port, 0013 exec from a temp folder, 0014 exec of a deleted file. YARA: EICAR, reverse-shell one-liners, XMRig, ld.so.preload rootkits.

### M3 verification

- `cargo test --workspace` (unit tests plus `crates/synapse-engined/tests/pipeline.rs`: each rule fires on its pattern and stays quiet on look-alikes such as `ssh host cmd`, `cat x | sh`, npm installs, Steam, editors, `systemctl edit`, pacman hooks), `cargo clippy --workspace --all-targets -- -D warnings`.
- Test VM (Arch, kernel 7.2.11, sensor + engine running): `pacman -S`/`-R` of several packages including ones with hooks, `makepkg`, `git clone`, `curl`, tar round trips -> **no alerts**; EICAR written to `/tmp` -> one `YARA:eicar.eicar_test_file` alert. The first run found a false positive (pacman runs hooks with a socket on stdin, which matched SYN-B-0001); `exclude_ancestor_exe` fixes it and a test keeps it fixed.
- This machine (read-only): `trust-baseline` 1257 packages / 249k files in ~1 s; `integrity` over all of them in 39 s: everything matches except `/usr/lib/vlc/plugins/plugins.dat`, a cache a pacman hook rebuilds.

## M4: the responder

```sh
sudo systemd-sysusers && sudo systemd-tmpfiles --create    # group synapse-notify, /var/lib/synapse/quarantine, /run/synapse-notify
sudo systemctl enable --now synapse-responderd             # after synapse-engined has created the database
sudo usermod -aG synapse-notify "$USER"                    # once; log out and in
systemctl --user enable --now synapse-notify               # desktop notifications (needs notify-send / libnotify)

synapsectl actions [-n 50] [--pending] [--json]           # what was done, would be done, or waits for you
sudo synapsectl approve ID | reject ID                    # pending actions
sudo synapsectl undo ID                                   # thaw, restore a quarantined file, lift a block
sudo synapsectl responder-status                          # mode, dry_run, breaker, pending count
sudo synapsectl breaker-reset
```

How an alert is handled. The engine stores the rule's `action` on the alert (capped at `notify` when the acting program is in `engine.allow_exe`). The responder follows the alerts table. On its very first start it skips the existing history. Then, in this order:

1. **Plan.** It works out what the action is aimed at: the alert's process (`freeze`, `kill`), its `path` (`quarantine`) or its `dst` address (`block`). `log` makes no action row. An alert the action cannot apply to (say a freeze with no process) is recorded as `skipped`.
2. **Decide.**
   - `notify` always runs.
   - `restore` is `skipped` (M6).
   - A level above what `general.mode` allows (alert-only 1, contain 3, enforce 6), or `response.dry_run = true`, or an open circuit breaker: recorded as `dry_run`, with what it would have run into.
   - A level above `response.auto_levels_max` waits as `pending`. So does anything at level 4 or more, whatever `auto_levels_max` says: quarantine and block always need `synapsectl approve` in M4.
   - Otherwise it runs, unless the budget is used up. `engine.max_actions_per_minute` counts automatic actions at level 2 and up. Going over trips the breaker, which falls back to dry runs and sends a notification until `breaker-reset`.
3. **Guard**, checked against the live system at that moment (not the alert). These are never touched:
   - PID 1, kernel threads, login session leaders, Synapse itself, systemd components, `engine.allow_exe`, and anything running under pacman.
   - Anything at all while `/var/lib/pacman/db.lck` exists.
   - A process whose start time no longer matches the alert's `ProcKey`, i.e. its PID was reused.
   - Files under `/boot`, `/usr/lib/systemd`, `/usr/lib/modules`, `/var/lib/pacman` and Synapse's folders, device files, and any file pacman owns (the reply says which package to reinstall).
   - Loopback, link-local, multicast and unspecified addresses.
4. **Act and record the undo:**
   - `freeze` moves the process and its descendants (up to 512) into `/sys/fs/cgroup/synapse.slice/suspect-<id>` and writes `cgroup.freeze`. Undo thaws it and moves every process back to the cgroup it came from.
   - `kill` freezes first, then writes `cgroup.kill`. Without cgroup v2 it sends SIGKILL to the process through a pidfd. A kill cannot be undone.
   - `quarantine` copies the file into `/var/lib/synapse/quarantine/<id>.bin` (mode 000, plus an `<id>.json` sidecar). It checks the path still names the same inode, then removes the original. Undo checks the copy's SHA-256 and links the file back with its owner, mode and mtime. It refuses if something exists at the path by then.
   - `block` adds the address, with `response.nft_block_ttl_secs` as its timeout, to a set in nftables table `inet synapse`. That table drops input from and output to the set. Commands are JSON on `nft -j -f -` stdin, built from parsed `IpAddr` values. Undo deletes the element.

Every outcome (`executed`, `failed`, `skipped`, `dry_run`, `pending`, `rejected`, `undone`) is a row in `actions` with its reason and who decided it. A notification says what happened and which `synapsectl` command undoes or approves it.

Requirements: cgroup v2 (the Arch default; `cgroup.kill` needs kernel 5.14+), `nftables` for blocks (`nft --version`), and `libnotify` (`notify-send`) in the desktop session. `pidfd_open` needs kernel 5.3+.

### M4 verification

- `cargo test --workspace`. The responder runs against a fake `/proc`, an emulated cgroup tree, a temporary quarantine folder and a recording nft (`crates/synapse-responderd/tests/responder.rs`). That covers every action kind through decide, guard, execute and undo, the circuit breaker, approval and rejection, PID reuse, pacman lock, session leaders, `allow_exe`, pacman-owned files, the loopback block, the alert cursor, and a real `sleep` process killed through a pidfd. The control socket test checks that a non-root peer is refused. Also `cargo clippy --workspace --all-targets -- -D warnings`.
- Live, unprivileged, with every path in a temporary folder, the real `synapse-responderd` was run in contain mode against alerts written into the database:
  - a kill alert killed its process (pidfd path; no cgroup root configured);
  - a freeze of a session leader was refused;
  - a quarantine was recorded as a dry run (contain allows up to level 3);
  - the alert that existed before the first start was left alone;
  - `synapsectl responder-status` from uid 1000 was refused by `SO_PEERCRED`;
  - `synapse-notify --print` showed the spooled notification with its markup escaped.
- **Root run in the test VM** (Arch, kernel 7.2.11, real cgroup v2 and nftables; alerts written into the database, harmless targets):
  - `contain`: a `sleep` process was frozen into `synapse.slice/suspect-1` (`frozen 1`), and `undo` thawed it and moved it back to its session scope. Another `sleep` was killed through `cgroup.kill`. A kill alert with a wrong start time (PID reuse) was refused. Quarantine and block were recorded as dry runs (above level 3).
  - `enforce`: quarantine of a root-owned EICAR file waited as `pending`; after `approve` the file was gone and `quarantine/1.bin` was mode 000, and `undo` brought it back with mode 640, owner root and the original mtime. A block of 192.0.2.10 waited, was added to `inet synapse` with a 1 h timeout, and `undo` removed it. A loopback block was refused even when approved. `reject` works. No errors in the log.

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

- **M3: the engine reads the JSONL event log** instead of a socket from the sensor (spec 4 sketches Unix-socket IPC). The log is already the sensor's durable output, either daemon can restart alone, and replay comes for free. A socket can replace it once the responder needs low latency (M4).
- **M3: pacman's database is read directly** (`desc`, `files`, `mtree`), not through libalpm: the `alpm` crate must match the installed libalpm exactly, so a rolling pacman upgrade could break Synapse at the worst moment.
- **M3: the sensor enriches two events** (backward compatible, older logs still parse): `exec.stdio` (where fds 0-2 point) and `file_write.head_entropy` (entropy of the first 4 KiB, read through fanotify's own descriptor). The engine is unprivileged and could not get either itself.
- **M3: rule ids SYN-B-0013 and 0014 are new**; the spec folds exec-from-tmp into 0002 and deleted binaries into 0003. Splitting them keeps each `match` table a single AND.
- **M3: std threads, no tokio.** The engine is one loop over the log; there is no async IPC yet.

- **M4: the responder runs as root** (with a bounding set of 8 capabilities), like the sensor. It must act on any user's processes and files and open the `synapse`-owned database. SQLite, when running as root, gives the WAL/SHM files it creates the database's owner, so the engine keeps working. The responder refuses to start when the database does not exist yet, so it never creates a root-owned one.
- **M4: the responder follows the `alerts` table** (a cursor in the new `state` table), not a socket from the engine. Same reasoning as the engine and the event log: either daemon restarts alone, and nothing is lost in between. Latency is one poll (300 ms).
- **M4: human decisions go over a Unix socket** (`/run/synapse/responder.sock`, 0600, peer uid 0 checked with `SO_PEERCRED`), so only the responder process ever changes the system. `synapsectl actions` reads the database directly.
- **M4: levels 4 to 6 always need approval**, even when `response.auto_levels_max` is higher (spec 8: "until the false-positive rate on your machine is understood"). The config still accepts 0..=6 so a later milestone can lift this without a config change.
- **M4: notifications go through a spool file**, not D-Bus from the responder. The responder is root and outside any desktop session. `synapse-notify` runs in the session, reads `/run/synapse-notify/notify.jsonl` (group `synapse-notify`) and calls `notify-send` with escaped text after `--`. The spec's stack names zbus; this avoids a D-Bus client in a root daemon and a large dependency.
- **M4: `kill` freezes first**, then uses `cgroup.kill`, so the whole tree dies at once and no PID can be reused in between. Without cgroup v2: SIGKILL through a pidfd, opened first and then checked against the start time, so the signal cannot reach a process that reused the PID.
- **M4: quarantine copies and then unlinks** (instead of renaming), so it works across filesystems (`/tmp` is tmpfs) and the original stays put until the copy is synced. Other hard links to the same inode remain (the record keeps `nlink`).
- **M4: `restore` (level 6) is not built**: it is not in the M4 milestone line. Such actions are recorded as `skipped`; it comes with self-protection (M6).
- **M4: the engine now enforces `engine.allow_exe`** (it was in the config since M0 but unused): the alert still appears, with `allowlisted` and the rule's original action in its detail, and asks for `notify` only.
- **M4: config additions** `response.dry_run`, `response.cgroup_root`, `response.notify_dir`.
- **M4 fix: `Store::alerts_after`** (M4 groundwork) read the newest N alerts and filtered them, so a burst larger than N skipped the older ones. It now pages by id.

## Not done yet

M5 to M8 in full: no AI analyzer, no self-protection, no PKGBUILD or pacman hooks.

M4 specifics:

- **Not run as root on a real system yet** (see M4 verification). Real cgroupfs, nft and capability behaviour are covered only by emulation and by reading the kernel interfaces.
- `restore` (level 6) is not built; restoring pacman files from the package cache comes in M6.
- No snapshot before risky actions (spec 8 mentions snapper); no pacman hooks that pause enforcement (M7). The responder checks `db.lck` itself instead.
- Pending actions never expire. An approved freeze or kill still checks the process's identity first, so a stale approval can only fail, never hit another process.
- Quarantine cannot touch files under `/usr`, `/etc`, `/boot` (the unit's `ProtectSystem=full`, and the guard refuses pacman-owned files anyway). An unpackaged file in `/usr/local/bin` cannot be quarantined.
- There is no per-cgroup egress block (spec 8, optional): `block` is per address.
- The responder has no `Type=notify` watchdog yet (M6).

M3 specifics:

- **Simulators (spec 14) are not in the repo.** The rules are covered by the pipeline tests with recorded-style events and by the live VM run above, but there is no script that triggers each rule on a real system yet.
- Rules not built because the sensor does not report what they need: SYN-B-0007 (file reads: fanotify open events), SYN-B-0009 (module loads), SYN-B-0011 (ptrace). SYN-B-0012 has only its port half (no CPU statistics).
- No `FAN_OPEN_EXEC_PERM`: scanning is after the fact (detect, not block).
- The engine (user `synapse`, no capabilities) cannot read files in `0700` home directories, so YARA on `~/Downloads` only works for readable files. Run `sudo synapsectl scan` for those.
- The trust cache is only refreshed per package when a file looks changed; the pacman hooks that refresh it after every transaction come in M7. `synapsectl trust-baseline` does it by hand.
- No rule-bundle signing (M6); the rules directory is protected by being root-owned.
- `synapsectl status`, rule reload without restart, alert acknowledgement: not done.

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

- **M4 acts on the system once you leave alert-only.** A false positive in `contain` freezes or kills a process you wanted. Freeze is undoable; kill is not. Stay in alert-only and read `synapsectl actions` (every would-be action is recorded) through the soak, then try `contain` with `response.dry_run = true` first.
- Moving processes between cgroups writes PIDs by number. The responder checks the start time right before and after each move, and moves a newcomer back if the PID was reused in between. The window is microseconds, but it is not zero.
- Moving a process out of its systemd scope or service is invisible to systemd until undo; `systemctl status` shows it under `synapse.slice`. If systemd stops a unit whose processes were moved away, they stay frozen in the suspect cgroup until undo or a kill.
- A frozen process holds its locks and open files. Freezing something that holds a lock a desktop component needs can stall that component until undo.
- `nft` blocks drop traffic in both directions for every process, not only the suspect.

- **False positives are the main M3 risk.** Only a short benign run in a VM and this machine's package files have been checked; the spec's two-week soak (M8) has not happened. Known: SYN-B-0003 fires on runc/Docker (memfd re-exec), SYN-B-0013 on installers and AppImages that run from `/tmp`, SYN-B-0010 could fire on a program not in its exclusion list that writes many compressed files quickly into a home directory, `integrity` reports caches that pacman hooks rebuild (`plugins.dat`).
- YARA-X needs writable-then-executable memory, so the engine unit cannot use `MemoryDenyWriteExecute=`.
- A malicious process that starts before the engine and never execs again is known only through the warm-up (the last 200k log lines).
- Thread creation also produces fork records (the kernel gives no way to tell without `task_struct`). They are cheap, but a thread-heavy workload raises the ring-buffer rate; watch `dropped`.
- A main thread that calls `pthread_exit` while other threads continue is reported as exited early.

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
