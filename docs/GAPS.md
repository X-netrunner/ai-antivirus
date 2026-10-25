# What is still open

Version 0.7.0 plus the unreleased 0.8.0 work (status, ack, ask, rule updates, CPU rule, network guard). Everything in the plan is built except the items below. Each item says why it matters and gives a small,
self-contained task description you can hand to a coding assistant on its own. Do them one at a time, run
`cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` after each, and keep alert-only as
the default.

## Before you leave alert-only (do these first)

1. **The soak.** `docs/SOAK.md`. Nothing else tells you the false-positive rate on your machine.
2. **Choose a license.** None is set (the PKGBUILD says `custom` and ships no license file) and the eBPF object is
   declared `Dual MIT/GPL`, which the kernel requires for its helpers. This is your decision, not something code can
   settle; put the text in `LICENSE` and change `license=` in the PKGBUILD.
3. ~~**Do not let `block` cut your own network.**~~ Done in 0.8.0: the guard also refuses the default gateway(s) and the
   resolvers, and IPv4-mapped IPv6 addresses are treated as IPv4.

## Open work, in the order I would do it

| # | Item | Why | Notes |
| --- | --- | --- | --- |
| 2 | fanotify open events and FID mode (`FileCreate`, `FileRename`, `FileUnlink`) | unlocks AV-B-0007 (non-allowlisted reads of browser profiles and SSH keys) and the three unused schema events | needs `FAN_REPORT_DFID_NAME`; watch the event volume |
| 3 | eBPF probes for `ptrace`, module load, `memfd_create`, `bind`/`listen`, signals sent to AI Antivirus | unlocks AV-B-0009 and AV-B-0011 and the "signals aimed at AI Antivirus" self-protection check | add each probe as an optional program like the connect ones, so a missing one only sets `degraded` |
| 4 | `FAN_OPEN_EXEC_PERM` scanning before a program runs | today AI Antivirus detects after the fact | must fail open after `exec_scan_timeout_ms`; measure p99 latency; start with scan-only, never deny |
| 5 | Baseline layer (spec 7, L4) | first-seen executable for a parent, first-seen destination per program, new autostart entries | keep it explainable, store in SQLite, alert at low severity only |
| 7 | Snapshot before `restore` (snapper) | spec 8 | optional; never roll back automatically |
| 8 | ClamAV (`clamd` socket) as an optional extra scanner | classic signatures | optional |
| 9 | tree-sitter bash parsing for `scan-pkgbuild` and the analyzer | spec names it; today structure checks and strings stand in | adds a build dependency, so weigh it |
| 10 | Per-cgroup egress block | spec 8, optional | `block` is per address today |

Example task text for item 3 of the table: "This is a defensive host-monitoring daemon for my own Arch
machine. Add an optional eBPF tracepoint program to crates/ai-antivirus-ebpf for `sched`/`syscalls` events that report a
ptrace attach (tracer pid, target pid), following the existing optional connect programs: shared record layout in
ai-antivirus-ebpf-common with layout tests, loader in ai-antivirus-sensord that attaches it on its own and only sets `degraded`
when missing, translation to the existing `Event::Ptrace`, and tests. Then add detection rule AV-B-0011 to
rules/behavior/00-shipped.toml with an exclusion for debuggers I use."

## Test and project hygiene

- **Simulators (spec 14).** Small benign programs that imitate each behavior on a throwaway VM (write many files, run a
  shell on a localhost socket, edit a dummy watched file) so every rule has a repeatable trigger. Not included; write
  them yourself against the rule conditions in `rules/behavior/00-shipped.toml` and run them only in a VM.
- **Coverage-guided fuzzing.** The seeded mutation tests stand in for `cargo-fuzz`. Add targets for the rule parser,
  the `mtree` reader, the analyzer's answer validator and the control-socket request parser.
- **Btrfs/snapper test VM.** The test VM was ext4.
- **CI.** `.github/workflows/ci.yml` runs fmt, clippy and the tests in an Arch container. It was written without being
  run (no repository to push to yet); expect to adjust it on first use.
- **A `ai-antivirus-git` PKGBUILD** only makes sense once there is a repository URL; the current PKGBUILD already builds
  from the working tree.
- **AUR helper integration.** `scan-pkgbuild DIR` is a command you run by hand; wiring it into your helper's pre-build
  step depends on which helper you use.
- **Desktop notifications.** `ai-antivirus-notify` was exercised in a headless VM; check one real notification in your
  desktop session. Its user unit sets `PrivateNetwork=yes`, which needs unprivileged user namespaces; on kernels that
  disable them (for example `linux-hardened`) remove that line.
- **Shipped rules after upgrades.** If you sign your rules, sign again after every package upgrade.

## Things to watch (known, not bugs)

- Retention prunes events after `retention_days = 14`; alerts, verdicts and actions are kept. Save your own event log
  copies during the soak (docs/SOAK.md, step 1).
- `SystemCallFilter=` lists came from one traced session. After a kernel or libc upgrade, read the journal for `EPERM`.
- aya is pinned to 0.13; newer releases exist and need both the loader and the eBPF side changed together.
