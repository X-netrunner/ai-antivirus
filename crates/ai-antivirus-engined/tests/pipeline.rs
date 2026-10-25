//! The engine with the shipped rules (`rules/`), fed hand-made events: each detection fires, and look-alike benign activity
//! stays quiet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::PathBuf;

use ai_antivirus_common::config::Config;
use ai_antivirus_common::event::{BootId, Envelope, Event, ProcKey, Proto};
use ai_antivirus_common::exceptions::{self, Exception, Matcher};
use ai_antivirus_common::store::Store;
use ai_antivirus_engined::engine::{Alert, Engine, LiveProc};

const S: u64 = 1_000_000_000;

struct Rig {
    engine: Engine,
    store: Store,
    seq: u64,
}

fn k(pid: u32) -> ProcKey {
    ProcKey {
        pid,
        start_ns: u64::from(pid) * 1000,
    }
}

impl Rig {
    fn new() -> Rig {
        let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let mut engine = ai_antivirus_engined::build(&Config::default(), &rules).unwrap();
        engine.set_pacman_probe(|| false);
        // the made-up sockets in these tests are network sockets unless a test says otherwise
        engine.set_unix_socket_probe(|_| Some(false));
        // hermetic: the built-in exceptions (not the host's file) and no look at the host's /proc
        engine.set_exceptions(Matcher::new(exceptions::defaults()));
        engine.set_live_probe(|_| None);
        Rig {
            engine,
            store: Store::open_in_memory().unwrap(),
            seq: 0,
        }
    }

    fn feed(&mut self, ts: u64, event: Event) -> Vec<Alert> {
        self.seq += 1;
        let env = Envelope {
            seq: self.seq,
            ts_ns: ts,
            boot_id: BootId(1),
            event,
        };
        self.engine.handle(&mut self.store, &env)
    }

    fn exec(
        &mut self,
        ts: u64,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv: &[&str],
        stdio: &[&str],
    ) -> Vec<Alert> {
        self.feed(
            ts,
            Event::Exec {
                proc: k(pid),
                parent: k(ppid),
                uid: 1000,
                exe: PathBuf::from(exe),
                argv: argv.iter().map(OsString::from).collect(),
                cwd: PathBuf::from("/home/u"),
                cgroup: String::new(),
                stdio: stdio.iter().map(OsString::from).collect(),
                lineage: Vec::new(),
            },
        )
    }

    fn write(&mut self, ts: u64, pid: u32, path: &str, entropy: Option<u16>) -> Vec<Alert> {
        self.feed(
            ts,
            Event::FileWrite {
                proc: k(pid),
                path: PathBuf::from(path),
                size: 4096,
                sha256: None,
                head_entropy: entropy,
            },
        )
    }
}

fn ids(a: &[Alert]) -> Vec<&str> {
    a.iter().map(|a| a.rule_id.as_str()).collect()
}

#[test]
fn a_shell_fed_by_a_unix_socket_is_not_a_reverse_shell() {
    // editors' terminals and coding agents give the shell a Unix-domain socket as stdin
    let mut r = Rig::new();
    r.engine.set_unix_socket_probe(|inode| Some(inode == 777));
    let quiet = r.exec(
        S,
        200,
        1,
        "/usr/bin/zsh",
        &["zsh", "-c", "ls"],
        &["socket:[777]", "socket:[777]", "socket:[777]"],
    );
    assert!(ids(&quiet).is_empty(), "{:?}", ids(&quiet));
    // a TCP socket still fires, and so does one that cannot be looked up
    let a = r.exec(
        2 * S,
        201,
        1,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[888]", "socket:[888]"],
    );
    assert_eq!(ids(&a), ["AV-B-0001"]);
    r.engine.set_unix_socket_probe(|_| None);
    let a = r.exec(
        3 * S,
        202,
        1,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[999]", "socket:[999]"],
    );
    assert_eq!(ids(&a), ["AV-B-0001"]);
}

#[test]
fn reverse_shell_fires_and_an_ssh_command_does_not() {
    let mut r = Rig::new();
    r.exec(
        S,
        100,
        1,
        "/usr/bin/fish",
        &["fish"],
        &["/dev/pts/1", "/dev/pts/1"],
    );
    let a = r.exec(
        2 * S,
        101,
        100,
        "/usr/bin/bash",
        &["bash", "-i"],
        &["socket:[555]", "socket:[555]", "socket:[555]"],
    );
    assert_eq!(ids(&a), ["AV-B-0001"]);
    assert_eq!(a[0].detail["stdin"], "socket:[555]");
    // `ssh host cmd` gives the remote shell pipes, not sockets
    let a = r.exec(
        3 * S,
        102,
        1,
        "/usr/bin/bash",
        &["bash", "-c", "ls"],
        &["pipe:[1]", "pipe:[2]", "pipe:[3]"],
    );
    assert!(a.is_empty(), "{a:?}");
}

#[test]
fn pacman_hooks_with_a_socket_stdin_are_not_reverse_shells() {
    // pacman runs hooks and scriptlets with stdin on a socket; seen in the test VM during `pacman -S`
    let mut r = Rig::new();
    r.exec(
        S,
        800,
        1,
        "/usr/bin/pacman",
        &["pacman", "-S", "htop"],
        &["/dev/pts/0"],
    );
    let a = r.exec(
        2 * S,
        801,
        800,
        "/usr/bin/bash",
        &["/usr/share/libalpm/scripts/gtk-update-icon-cache"],
        &["socket:[9]"],
    );
    assert!(a.is_empty(), "{a:?}");
    // and a subshell of the hook (grandchild of pacman)
    assert!(r
        .exec(
            3 * S,
            802,
            801,
            "/usr/bin/bash",
            &["bash", "-c", "x"],
            &["socket:[9]"]
        )
        .is_empty());
}

#[test]
fn a_hook_script_that_runs_ldd_through_subshells_is_still_under_pacman() {
    // seen in the VM soak: mkinitcpio, run by a pacman hook, runs `ldd` (a bash script) from forked subshells with a
    // socket as stdin; the subshells never exec, so only the sensor's lineage connects `ldd` to pacman
    let mut r = Rig::new();
    r.exec(
        S,
        820,
        1,
        "/usr/bin/pacman",
        &["pacman", "-Syu"],
        &["/dev/pts/0"],
    );
    r.exec(
        2 * S,
        821,
        820,
        "/usr/bin/bash",
        &["/usr/share/libalpm/scripts/mkinitcpio-install"],
        &["socket:[9]"],
    );
    let with_lineage = |pid: u32, ppid: u32, lineage: Vec<u32>| Event::Exec {
        proc: k(pid),
        parent: k(ppid),
        uid: 0,
        exe: PathBuf::from("/usr/bin/bash"),
        argv: vec![OsString::from("ldd"), OsString::from("/usr/bin/mount")],
        cwd: PathBuf::from("/"),
        cgroup: String::new(),
        stdio: vec![OsString::from("socket:[9]")],
        lineage: lineage.into_iter().map(k).collect(),
    };
    let a = r.feed(3 * S, with_lineage(822, 830, vec![830, 829, 821, 820]));
    assert!(a.is_empty(), "{a:?}");
    // the same exec with no lineage (an old log) is what the soak flagged
    let a = r.feed(4 * S, with_lineage(823, 830, Vec::new()));
    assert_eq!(ids(&a), ["AV-B-0001"]);
}

#[test]
fn curl_into_sh_fires_whichever_starts_first_and_cat_into_sh_does_not() {
    let mut r = Rig::new();
    r.exec(S, 200, 1, "/usr/bin/fish", &["fish"], &[]);
    // the shell first, then curl
    assert!(r
        .exec(
            2 * S,
            201,
            200,
            "/usr/bin/sh",
            &["sh"],
            &["pipe:[900]", "/dev/pts/0"]
        )
        .is_empty());
    let a = r.exec(
        2 * S + 1,
        202,
        200,
        "/usr/bin/curl",
        &["curl", "-fsSL", "https://x.invalid/i.sh"],
        &["/dev/pts/0", "pipe:[900]"],
    );
    assert_eq!(ids(&a), ["AV-B-0002"]);
    assert_eq!(a[0].detail["stdin_from"], "/usr/bin/curl");
    // curl first
    r.exec(
        3 * S,
        210,
        200,
        "/usr/bin/wget",
        &["wget", "-qO-", "x"],
        &["", "pipe:[901]"],
    );
    assert_eq!(
        ids(&r.exec(
            3 * S + 1,
            211,
            200,
            "/usr/bin/bash",
            &["bash"],
            &["pipe:[901]"]
        )),
        ["AV-B-0002"]
    );
    // cat into sh is fine
    r.exec(
        4 * S,
        220,
        200,
        "/usr/bin/cat",
        &["cat", "x.sh"],
        &["", "pipe:[902]"],
    );
    assert!(r
        .exec(4 * S + 1, 221, 200, "/usr/bin/sh", &["sh"], &["pipe:[902]"])
        .is_empty());
}

#[test]
fn memfd_deleted_and_tmp_execution() {
    let mut r = Rig::new();
    assert_eq!(
        ids(&r.exec(S, 300, 1, "/memfd:payload (deleted)", &["x"], &[])),
        ["AV-B-0003", "AV-B-0014"]
    );
    assert_eq!(
        ids(&r.exec(S, 301, 1, "/dev/shm/.x/run", &["run"], &[])),
        ["AV-B-0013"]
    );
    assert!(r
        .exec(S, 302, 1, "/usr/bin/ls", &["ls"], &["/dev/pts/0"])
        .is_empty());
}

#[test]
fn persistence_writes() {
    let mut r = Rig::new();
    r.exec(S, 400, 1, "/usr/bin/python3", &["python3", "x.py"], &[]);
    assert_eq!(
        ids(&r.write(2 * S, 400, "/etc/ld.so.preload", None)),
        ["AV-B-0004"]
    );
    assert_eq!(
        ids(&r.write(
            2 * S,
            400,
            "/home/u/.config/systemd/user/updater.service",
            None
        )),
        ["AV-B-0005"]
    );
    assert_eq!(
        ids(&r.write(2 * S, 400, "/home/u/.ssh/authorized_keys", None)),
        ["AV-B-0006"]
    );
    assert!(r.write(2 * S, 400, "/home/u/notes.txt", None).is_empty());
    // the same write by an editor, and units written by systemctl, are expected
    r.exec(S, 401, 1, "/usr/bin/nvim", &["nvim"], &[]);
    assert!(r
        .write(3 * S, 401, "/home/u/.ssh/authorized_keys", None)
        .is_empty());
    r.exec(
        S,
        402,
        1,
        "/usr/bin/systemctl",
        &["systemctl", "edit", "x"],
        &[],
    );
    assert!(r
        .write(
            3 * S,
            402,
            "/etc/systemd/system/x.service.d/override.conf",
            None
        )
        .is_empty());
}

#[test]
fn pacman_transactions_silence_the_rules_that_ask_for_it() {
    let mut r = Rig::new();
    r.engine.set_pacman_probe(|| true);
    r.exec(S, 450, 1, "/usr/bin/bash", &["bash", ".INSTALL"], &[]);
    assert!(r
        .write(2 * S, 450, "/usr/lib/systemd/system/foo.service", None)
        .is_empty());
}

#[test]
fn ransomware_burst_fires_once_and_a_node_modules_install_does_not() {
    let mut r = Rig::new();
    r.exec(S, 500, 1, "/usr/bin/fish", &["fish"], &[]);
    r.exec(S, 501, 500, "/home/u/.local/bin/locker", &["locker"], &[]);
    r.exec(
        S,
        502,
        501,
        "/home/u/.local/bin/locker",
        &["locker", "--worker"],
        &[],
    );
    let mut fired = Vec::new();
    for i in 0..300u64 {
        // two workers of one tree share the window
        let pid = if i % 2 == 0 { 501 } else { 502 };
        fired.extend(r.write(
            2 * S + i * S / 100,
            pid,
            &format!("/home/u/Documents/f{i}.odt"),
            Some(7990),
        ));
    }
    assert_eq!(ids(&fired), ["AV-B-0010"]);
    assert_eq!(
        fired[0].proc_key,
        Some(k(501)),
        "counted per tree, reported on its root"
    );
    assert!(
        fired[0].detail["window"]["distinct_files"]
            .as_u64()
            .unwrap()
            >= 200
    );

    // npm writing many text files
    r.exec(
        S,
        510,
        500,
        "/usr/bin/node",
        &["node", "npm", "install"],
        &[],
    );
    for i in 0..1000u64 {
        let a = r.write(
            10 * S + i * S / 200,
            510,
            &format!("/home/u/proj/node_modules/p{i}/index.js"),
            Some(4700),
        );
        assert!(a.is_empty());
    }
    // Steam unpacking a game (random-looking data) is left alone
    r.exec(
        S,
        520,
        500,
        "/home/u/.local/share/Steam/ubuntu12_32/steam",
        &["steam"],
        &[],
    );
    for i in 0..400u64 {
        assert!(r
            .write(
                20 * S + i * S / 100,
                520,
                &format!("/home/u/.local/share/Steam/steamapps/common/G/d{i}.pak"),
                Some(7999)
            )
            .is_empty());
    }
}

#[test]
fn writes_to_ai_antivirus_own_files_are_alerts_unless_pacman_or_the_cli_wrote_them() {
    let mut r = Rig::new();
    r.exec(S, 900, 1, "/usr/bin/python3", &["python3", "x.py"], &[]);
    r.exec(
        S,
        901,
        1,
        "/usr/bin/ai-antivirus",
        &["ai-antivirus", "approve-rule", "3"],
        &[],
    );
    for p in [
        "/usr/lib/ai-antivirus/ai-antivirus-ebpf.o",
        "/etc/ai-antivirus/ai-antivirus.toml",
        "/etc/ai-antivirus/rules/behavior/00-shipped.toml",
        "/usr/bin/ai-antivirus-sensord",
    ] {
        assert_eq!(ids(&r.write(2 * S, 900, p, None)), ["AV-B-0020"], "{p}");
    }
    assert!(
        r.write(
            3 * S,
            901,
            "/etc/ai-antivirus/rules/behavior/local/ai-3.toml",
            None
        )
        .is_empty(),
        "the CLI"
    );
    assert!(
        r.write(3 * S, 900, "/var/lib/ai-antivirus/ai-antivirus.db", None)
            .is_empty(),
        "state files are not rules"
    );
    r.engine.set_pacman_probe(|| true);
    assert!(
        r.write(
            4 * S,
            900,
            "/usr/lib/ai-antivirus/ai-antivirus-ebpf.o",
            None
        )
        .is_empty(),
        "during an upgrade"
    );
}

#[test]
fn tamper_events_from_the_sensor_become_alerts() {
    use ai_antivirus_common::event::TamperKind;
    let mut r = Rig::new();
    let a = r.feed(
        S,
        Event::Tamper {
            what: TamperKind::ProbeDetached,
        },
    );
    assert_eq!(ids(&a), ["AV-T-0010"]);
    assert_eq!(a[0].layer, "self-protection");
    let a = r.feed(
        2 * S,
        Event::Tamper {
            what: TamperKind::PtraceAttach { from: k(77) },
        },
    );
    assert_eq!(
        (ids(&a), a[0].detail["tracer_pid"].as_u64()),
        (vec!["AV-T-0011"], Some(77))
    );
    // health lines are not tamper
    assert!(r
        .feed(
            3 * S,
            Event::SensorHealth {
                dropped: 0,
                degraded: false
            }
        )
        .is_empty());
}

#[test]
fn bulk_compression_is_quiet_but_bulk_encryption_is_not() {
    // found by the VM soak: gzip over 320 files looked like ransomware
    let mut r = Rig::new();
    r.exec(S, 950, 1, "/usr/bin/fish", &["fish"], &[]);
    r.exec(S, 951, 950, "/usr/bin/gzip", &["gzip", "logs/a.txt"], &[]);
    for i in 0..320u64 {
        let a = r.write(
            2 * S + i * S / 100,
            951,
            &format!("/home/u/logs/log{i}.txt.gz"),
            Some(7900),
        );
        assert!(a.is_empty(), "gzip: {a:?}");
    }
    r.exec(S, 960, 950, "/usr/bin/gpg", &["gpg", "-c"], &[]);
    let mut fired = Vec::new();
    for i in 0..320u64 {
        fired.extend(r.write(
            20 * S + i * S / 100,
            960,
            &format!("/home/u/Documents/d{i}.gpg"),
            Some(7990),
        ));
    }
    assert_eq!(
        ids(&fired),
        ["AV-B-0010"],
        "encrypting hundreds of files is still caught"
    );
}

#[test]
fn mining_pool_port() {
    let mut r = Rig::new();
    r.exec(S, 600, 1, "/home/u/.x/xm", &["xm"], &[]);
    let c = |port: u16| Event::Connect {
        proc: k(600),
        dst: format!("198.51.100.7:{port}").parse().unwrap(),
        proto: Proto::Tcp,
    };
    assert_eq!(ids(&r.feed(2 * S, c(14444))), ["AV-B-0012"]);
    assert!(r.feed(3 * S, c(443)).is_empty());
}

#[test]
fn miner_with_sustained_cpu_is_reported_after_the_window() {
    use std::sync::{Arc, Mutex};
    let mut r = Rig::new();
    // fake CPU clock per pid: pid 600 burns 90% of a core, pid 601 stays idle
    let cpu: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let c2 = cpu.clone();
    r.engine.set_cpu_probe(move |key| {
        let busy = *c2.lock().unwrap();
        match key.pid {
            600 => Some(busy),
            601 => Some(1_000),
            _ => None,
        }
    });
    r.exec(S, 600, 1, "/home/u/.x/xm", &["xm"], &[]);
    r.exec(S, 601, 1, "/usr/bin/somegame", &["somegame"], &[]);
    let c = |pid: u32| Event::Connect {
        proc: k(pid),
        dst: "198.51.100.7:3333".parse().unwrap(),
        proto: Proto::Tcp,
    };
    // the port-only rule fires at once, the CPU rule waits
    assert_eq!(ids(&r.feed(2 * S, c(600))), ["AV-B-0012"]);
    assert_eq!(ids(&r.feed(2 * S, c(601))), ["AV-B-0012"]);
    assert_eq!(r.engine.cpu_checks_waiting(), 2);
    // a repeated connect does not queue a second check
    r.feed(3 * S, c(600));
    assert_eq!(r.engine.cpu_checks_waiting(), 2);
    assert!(r.engine.tick(30 * S).is_empty(), "not due yet");
    *cpu.lock().unwrap() = 54 * S; // 54 s of CPU in 60 s = 90 %
    let fired = r.engine.tick(62 * S);
    assert_eq!(ids(&fired), ["AV-B-0015"]);
    assert_eq!(fired[0].proc_key, Some(k(600)));
    assert_eq!(fired[0].detail["cpu_percent"], 90);
    assert_eq!(r.engine.cpu_checks_waiting(), 0);
}

#[test]
fn eicar_written_to_tmp_is_found_by_yara_and_alerts_once() {
    let dir = tempfile::Builder::new()
        .prefix("ai-antivirus-test")
        .tempdir_in("/tmp")
        .unwrap();
    let p = dir.path().join("eicar.com");
    std::fs::write(&p, ai_antivirus_rules::scan::EICAR).unwrap();
    let mut r = Rig::new();
    r.exec(S, 700, 1, "/usr/bin/curl", &["curl"], &[]);
    let path = p.to_str().unwrap();
    let a = r.write(2 * S, 700, path, None);
    assert_eq!(ids(&a), ["YARA:eicar.eicar_test_file"]);
    assert_eq!(a[0].layer, "L2 yara");
    assert!(r.write(3 * S, 700, path, None).is_empty(), "deduplicated");
}

#[test]
fn replay_prints_one_json_line_per_alert() {
    let mut r = Rig::new();
    let lines = [
        r#"{"seq":1,"ts_ns":1000000000,"boot_id":"00000000000000000000000000000001","event":{"type":"exec","proc":{"pid":9,"start_ns":9},"parent":{"pid":1,"start_ns":1},"uid":0,"exe":"/usr/bin/bash","argv":["bash"],"cwd":"/","cgroup":"","stdio":["socket:[1]","socket:[1]",""]}}"#,
        "not json",
        r#"{"seq":2,"ts_ns":2000000000,"boot_id":"00000000000000000000000000000001","event":{"type":"exit","proc":{"pid":9,"start_ns":9},"code":0}}"#,
    ]
    .join("\n");
    let mut out = Vec::new();
    let alerts =
        ai_antivirus_engined::replay(&mut r.engine, &mut r.store, lines.as_bytes(), &mut out)
            .unwrap();
    assert_eq!(alerts.len(), 1);
    let printed: serde_json::Value =
        serde_json::from_slice(out.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(printed["rule_id"], "AV-B-0001");
    assert_eq!(printed["action"], "freeze");
}

#[test]
fn allowlisted_programs_are_capped_at_notify() {
    use ai_antivirus_rules::rule::Action;
    let mut r = Rig::new();
    // makepkg is in the default engine.allow_exe; python3 is not
    r.exec(S, 410, 1, "/usr/bin/makepkg", &["makepkg"], &[]);
    r.exec(S, 411, 1, "/usr/bin/python3", &["python3"], &[]);
    let a = r.write(2 * S, 410, "/etc/ld.so.preload", None);
    assert_eq!(ids(&a), ["AV-B-0004"]);
    assert_eq!(a[0].action, Action::Notify);
    assert_eq!(a[0].detail["allowlisted"], "/usr/bin/makepkg");
    assert_eq!(a[0].detail["rule_action"], "freeze");
    let b = r.write(2 * S, 411, "/etc/ld.so.preload", None);
    assert_eq!(b[0].action, Action::Freeze);
}

#[test]
fn what_an_excepted_coding_agent_starts_raises_no_behavior_alerts() {
    let mut r = Rig::new();
    // Claude Code (native install) runs `curl ... | sh` and a shell on a socket
    r.exec(
        S,
        800,
        1,
        "/home/u/.local/share/claude/versions/2.1.310",
        &["claude"],
        &[],
    );
    r.exec(S, 801, 800, "/usr/bin/zsh", &["zsh", "-c", "x"], &[]);
    r.exec(2 * S, 802, 801, "/usr/bin/sh", &["sh"], &["pipe:[950]"]);
    let a = r.exec(
        2 * S + 1,
        803,
        801,
        "/usr/bin/curl",
        &["curl", "x"],
        &["", "pipe:[950]"],
    );
    assert!(a.is_empty(), "{:?}", ids(&a));
    let a = r.exec(
        3 * S,
        804,
        801,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[951]", "socket:[951]"],
    );
    assert!(a.is_empty(), "{:?}", ids(&a));
    assert_eq!(r.engine.stats.excepted, 2);
    // the same from an ordinary terminal still fires
    r.exec(S, 810, 1, "/usr/bin/fish", &["fish"], &[]);
    r.exec(4 * S, 811, 810, "/usr/bin/sh", &["sh"], &["pipe:[952]"]);
    let a = r.exec(
        4 * S + 1,
        812,
        810,
        "/usr/bin/curl",
        &["curl", "x"],
        &["", "pipe:[952]"],
    );
    assert_eq!(ids(&a), ["AV-B-0002"]);
    // a copy named claude in /tmp is not Claude Code
    r.exec(S, 820, 1, "/tmp/claude", &["claude"], &[]);
    let a = r.exec(
        5 * S,
        821,
        820,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[953]", "socket:[953]"],
    );
    assert_eq!(ids(&a), ["AV-B-0001"]);
}

#[test]
fn rules_that_guard_the_system_ignore_exceptions() {
    let mut r = Rig::new();
    r.exec(S, 830, 1, "/usr/bin/agy", &["agy"], &[]);
    let a = r.write(2 * S, 830, "/etc/ld.so.preload", None);
    assert_eq!(ids(&a), ["AV-B-0004"]);
    assert!(a[0].detail.get("exception").is_none());
}

#[test]
fn malware_written_by_an_excepted_program_is_still_reported_as_a_notification() {
    use ai_antivirus_rules::rule::Action;
    let dir = tempfile::Builder::new()
        .prefix("ai-antivirus-test")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let p = dir.path().join("payload");
    std::fs::write(&p, ai_antivirus_rules::scan::EICAR).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut r = Rig::new();
    r.exec(
        S,
        840,
        1,
        "/usr/bin/node",
        &["node", "/usr/bin/gemini"],
        &[],
    );
    let a = r.write(2 * S, 840, p.to_str().unwrap(), None);
    assert_eq!(ids(&a), ["YARA:eicar.eicar_test_file"]);
    assert_eq!(a[0].action, Action::Notify);
    assert_eq!(a[0].detail["exception"], "Gemini CLI");
    assert_eq!(a[0].detail["rule_action"], "quarantine");

    // a folder exception: not scanned at all, nothing reported
    let folder = dir.path().to_str().unwrap().to_owned();
    r.engine
        .set_exceptions(Matcher::new(vec![Exception::folder(&folder, "samples")]));
    r.exec(S, 841, 1, "/usr/bin/cp", &["cp"], &[]);
    let checked = r.engine.files.stats.checked;
    let a = r.write(3 * S, 841, p.to_str().unwrap(), None);
    assert!(a.is_empty(), "{:?}", ids(&a));
    assert_eq!(
        r.engine.files.stats.checked, checked,
        "the file was scanned"
    );
}

#[test]
fn an_agent_started_before_the_engine_is_found_in_proc() {
    let mut r = Rig::new();
    // pid 850's parent (849) is not in the table: the engine looks it up live, and its parent (848) is Claude Code
    r.engine.set_live_probe(|pid| match pid {
        849 => Some(LiveProc {
            ppid: 848,
            exe: PathBuf::from("/usr/bin/zsh"),
            argv: vec![OsString::from("zsh")],
        }),
        848 => Some(LiveProc {
            ppid: 1,
            exe: PathBuf::from("claude"),
            argv: vec![OsString::from("claude")],
        }),
        _ => None,
    });
    let a = r.exec(
        S,
        850,
        849,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[960]", "socket:[960]"],
    );
    assert!(a.is_empty(), "{:?}", ids(&a));
    // a parent that is not an agent: the alert stays
    let a = r.exec(
        S,
        851,
        700,
        "/usr/bin/sh",
        &["sh", "-i"],
        &["socket:[961]", "socket:[961]"],
    );
    assert_eq!(ids(&a), ["AV-B-0001"]);
}

/// Timing, not a correctness test: `cargo test --release -p ai-antivirus-engined --test pipeline -- --ignored --nocapture per_event`
#[test]
#[ignore]
fn per_event_cost() {
    let mut r = Rig::new();
    // a process five levels deep, like a program started from a terminal in a session
    for (pid, parent) in [(10, 1), (11, 10), (12, 11), (13, 12), (14, 13)] {
        r.exec(S, pid, parent, "/usr/bin/bash", &["bash"], &[]);
    }
    r.exec(S, 600, 14, "/usr/bin/firefox", &["firefox"], &[]);
    let n = 200_000u64;
    let started = std::time::Instant::now();
    for i in 0..n {
        let alerts = r.feed(
            2 * S + i,
            Event::Connect {
                proc: k(600),
                dst: "198.51.100.7:443".parse().unwrap(),
                proto: Proto::Tcp,
            },
        );
        assert!(alerts.is_empty());
    }
    let per = started.elapsed().as_nanos() / u128::from(n);
    // what building the events alone costs, so the figure above can be read as engine time
    let started = std::time::Instant::now();
    let mut keep = 0u64;
    for i in 0..n {
        let ev = Event::Connect {
            proc: k(600),
            dst: "198.51.100.7:443".parse().unwrap(),
            proto: Proto::Tcp,
        };
        keep += i + u64::from(matches!(ev, Event::Connect { .. }));
    }
    let harness = started.elapsed().as_nanos() / u128::from(n);
    println!(
        "per_event_cost: {per} ns per connect event (of which {harness} ns building it, {keep})"
    );
    // with the real pacman probe (a stat of /var/lib/pacman/db.lck), as in production
    r.engine
        .set_pacman_probe(ai_antivirus_rules::mtree::pacman_active);
    let started = std::time::Instant::now();
    for i in 0..n {
        r.feed(
            3 * S + i,
            Event::Connect {
                proc: k(600),
                dst: "198.51.100.7:443".parse().unwrap(),
                proto: Proto::Tcp,
            },
        );
    }
    let real = started.elapsed().as_nanos() / u128::from(n);
    println!("per_event_cost: {real} ns per connect event with the real pacman probe");
}
