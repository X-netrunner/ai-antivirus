//! The engine with the shipped rules (`rules/`), fed hand-made events: each detection fires, and look-alike benign activity
//! stays quiet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::PathBuf;

use synapse_common::config::Config;
use synapse_common::event::{BootId, Envelope, Event, ProcKey, Proto};
use synapse_common::store::Store;
use synapse_engined::engine::{Alert, Engine};

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
        let mut engine = synapse_engined::build(&Config::default(), &rules).unwrap();
        engine.set_pacman_probe(|| false);
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
    assert_eq!(ids(&a), ["SYN-B-0001"]);
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
    assert_eq!(ids(&a), ["SYN-B-0002"]);
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
        ["SYN-B-0002"]
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
        ["SYN-B-0003", "SYN-B-0014"]
    );
    assert_eq!(
        ids(&r.exec(S, 301, 1, "/dev/shm/.x/run", &["run"], &[])),
        ["SYN-B-0013"]
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
        ["SYN-B-0004"]
    );
    assert_eq!(
        ids(&r.write(
            2 * S,
            400,
            "/home/u/.config/systemd/user/updater.service",
            None
        )),
        ["SYN-B-0005"]
    );
    assert_eq!(
        ids(&r.write(2 * S, 400, "/home/u/.ssh/authorized_keys", None)),
        ["SYN-B-0006"]
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
    assert_eq!(ids(&fired), ["SYN-B-0010"]);
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
fn mining_pool_port() {
    let mut r = Rig::new();
    r.exec(S, 600, 1, "/home/u/.x/xm", &["xm"], &[]);
    let c = |port: u16| Event::Connect {
        proc: k(600),
        dst: format!("198.51.100.7:{port}").parse().unwrap(),
        proto: Proto::Tcp,
    };
    assert_eq!(ids(&r.feed(2 * S, c(14444))), ["SYN-B-0012"]);
    assert!(r.feed(3 * S, c(443)).is_empty());
}

#[test]
fn eicar_written_to_tmp_is_found_by_yara_and_alerts_once() {
    let dir = tempfile::Builder::new()
        .prefix("synapse-test")
        .tempdir_in("/tmp")
        .unwrap();
    let p = dir.path().join("eicar.com");
    std::fs::write(&p, synapse_rules::scan::EICAR).unwrap();
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
        synapse_engined::replay(&mut r.engine, &mut r.store, lines.as_bytes(), &mut out).unwrap();
    assert_eq!(alerts.len(), 1);
    let printed: serde_json::Value =
        serde_json::from_slice(out.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(printed["rule_id"], "SYN-B-0001");
    assert_eq!(printed["action"], "freeze");
}

#[test]
fn allowlisted_programs_are_capped_at_notify() {
    use synapse_rules::rule::Action;
    let mut r = Rig::new();
    // makepkg is in the default engine.allow_exe; python3 is not
    r.exec(S, 410, 1, "/usr/bin/makepkg", &["makepkg"], &[]);
    r.exec(S, 411, 1, "/usr/bin/python3", &["python3"], &[]);
    let a = r.write(2 * S, 410, "/etc/ld.so.preload", None);
    assert_eq!(ids(&a), ["SYN-B-0004"]);
    assert_eq!(a[0].action, Action::Notify);
    assert_eq!(a[0].detail["allowlisted"], "/usr/bin/makepkg");
    assert_eq!(a[0].detail["rule_action"], "freeze");
    let b = r.write(2 * S, 411, "/etc/ld.so.preload", None);
    assert_eq!(b[0].action, Action::Freeze);
}
