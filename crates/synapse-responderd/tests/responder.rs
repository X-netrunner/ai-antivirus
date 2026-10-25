//! The responder against a fake system: a fake `/proc`, an emulated cgroup tree, a temporary quarantine folder, a
//! recording nft. Every action kind runs through decide, guard, execute and undo.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use synapse_common::config::{Config, Mode};
use synapse_common::event::{ProcKey, Sha256};
use synapse_common::model::{ActionStatus, Severity};
use synapse_common::store::{ActionRow, NewAlert, Store, TrustEntry};
use synapse_responderd::ipc::{self, Request};
use synapse_responderd::responder::{Responder, System};
use synapse_responderd::{
    cgroup::Cgroups, nft, notify::Notifier, procfs::ProcFs, quarantine::Quarantine,
};

const S: u64 = 1_000_000_000;
const T0: u64 = 1_800_000_000 * S;

/// Records nft documents; the table exists after the first create.
#[derive(Clone, Default)]
struct Nft(Arc<std::sync::Mutex<Vec<Value>>>);

impl nft::Nft for Nft {
    fn apply(&self, doc: &Value) -> Result<(), String> {
        self.0.lock().unwrap().push(doc.clone());
        Ok(())
    }
    fn table_exists(&self) -> bool {
        !self.0.lock().unwrap().is_empty()
    }
}

struct Rig {
    dir: tempfile::TempDir,
    r: Responder,
    pacman: Arc<AtomicBool>,
    nft: Nft,
}

fn stat_line(pid: u32, ppid: u32, sid: u32, ticks: u64) -> String {
    format!("{pid} (x) S {ppid} {pid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n")
}

impl Rig {
    fn new(mode: Mode, tweak: impl FnOnce(&mut Config, &mut Store)) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.general.mode = mode;
        let mut store = Store::open_in_memory().unwrap();
        tweak(&mut cfg, &mut store);
        for d in ["proc", "cg/user.slice/s.scope", "q", "notify"] {
            fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        let pacman = Arc::new(AtomicBool::new(false));
        let p2 = Arc::clone(&pacman);
        let nft = Nft::default();
        let sys = System {
            procfs: ProcFs::new(dir.path().join("proc")),
            cgroups: Cgroups::emulated(dir.path().join("cg")),
            quarantine: Quarantine::new(dir.path().join("q")),
            nft: Box::new(nft.clone()),
            notifier: Notifier::new(dir.path().join("notify")),
            pacman_active: Box::new(move || p2.load(Ordering::Relaxed)),
            self_pid: 999_999,
        };
        let rig = Rig {
            r: Responder::new(cfg, store, sys),
            dir,
            pacman,
            nft,
        };
        // a session (sid 100) with a shell, a suspect python and its child
        rig.proc(100, 1, 100, 100, "/usr/bin/bash");
        rig.proc(200, 100, 100, 200, "/tmp/evil");
        rig.proc(201, 200, 100, 201, "/usr/bin/sh");
        rig.proc(300, 100, 100, 300, "/usr/bin/makepkg");
        rig
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    fn proc(&self, pid: u32, ppid: u32, sid: u32, ticks: u64, exe: &str) {
        let d = self.path(&format!("proc/{pid}"));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("stat"), stat_line(pid, ppid, sid, ticks)).unwrap();
        let _ = fs::remove_file(d.join("exe"));
        std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
        fs::write(d.join("cgroup"), "0::/user.slice/s.scope\n").unwrap();
    }

    fn alert(&mut self, rule: &str, action: &str, pid: Option<u32>, extra: Value) -> i64 {
        let mut detail = json!({"action": action, "exe": "/tmp/evil"});
        for (k, v) in extra.as_object().unwrap() {
            detail[k] = v.clone();
        }
        let id = self
            .r
            .store()
            .insert_alert(&NewAlert {
                ts_ns: T0,
                rule_id: rule.into(),
                severity: Severity::High,
                confidence: 0.9,
                title: format!("{rule} title"),
                // start ticks equal the pid in this rig (10 ms each)
                proc_key: pid.map(|p| ProcKey {
                    pid: p,
                    start_ns: u64::from(p) * 10_000_000,
                }),
                event_id: None,
                detail,
            })
            .unwrap();
        let a = self.r.store().get_alert(id).unwrap().unwrap();
        self.r.handle_alert(&a, T0).unwrap().unwrap()
    }

    fn action(&self, id: i64) -> ActionRow {
        self.r.store().get_action(id).unwrap().unwrap()
    }

    fn notes(&self) -> Vec<Value> {
        fs::read_to_string(self.path("notify/notify.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn cg_procs(&self, rel: &str) -> Vec<u32> {
        fs::read_to_string(self.path(&format!("cg/{rel}/cgroup.procs")))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.parse().ok())
            .collect()
    }
}

/// The emulated cgroupfs: control files are plain files. The responder's real `Cgroups` writes to them; the rig
/// prepares what the kernel would provide.
fn emulate(rig: &Rig) {
    fs::write(rig.path("cg/cgroup.controllers"), "").unwrap();
    fs::write(rig.path("cg/user.slice/s.scope/cgroup.procs"), "").unwrap();
}

#[test]
fn alert_only_records_what_it_would_do_and_notifies() {
    let mut rig = Rig::new(Mode::AlertOnly, |_, _| {});
    emulate(&rig);
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    let a = rig.action(id);
    assert_eq!(a.status, ActionStatus::DryRun);
    let why = a.error.unwrap();
    assert!(
        why.contains("mode alert-only allows up to level 1"),
        "{why}"
    );
    assert!(why.contains("2 process(es) would be affected"), "{why}");
    assert!(
        !rig.path("cg/synapse.slice").exists(),
        "nothing was touched"
    );
    let n = rig.notes();
    assert_eq!(n.len(), 1);
    assert!(n[0]["summary"]
        .as_str()
        .unwrap()
        .starts_with("Would freeze process 200"));

    let id = rig.alert("SYN-B-0005", "notify", Some(200), json!({}));
    assert_eq!(rig.action(id).status, ActionStatus::Executed);
    assert_eq!(rig.notes().len(), 2);
    // log-only alerts make no action
    let a = rig
        .r
        .store()
        .insert_alert(&NewAlert {
            ts_ns: T0,
            rule_id: "x".into(),
            severity: Severity::Low,
            confidence: 0.1,
            title: "t".into(),
            proc_key: None,
            event_id: None,
            detail: json!({"action": "log"}),
        })
        .unwrap();
    let a = rig.r.store().get_alert(a).unwrap().unwrap();
    assert_eq!(rig.r.handle_alert(&a, T0).unwrap(), None);
}

#[test]
fn contain_freezes_the_tree_and_undo_puts_it_back() {
    let mut rig = Rig::new(Mode::Contain, |_, _| {});
    emulate(&rig);
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    let a = rig.action(id);
    assert_eq!(a.status, ActionStatus::Executed, "{:?}", a.error);
    let suspect = format!("synapse.slice/suspect-{id}");
    assert_eq!(rig.cg_procs(&suspect), [200, 201]);
    assert_eq!(
        fs::read_to_string(rig.path(&format!("cg/{suspect}/cgroup.freeze"))).unwrap(),
        "1"
    );
    let undo = a.undo.unwrap();
    assert_eq!(undo["cgroup"], format!("/{suspect}"));
    assert_eq!(undo["members"][0]["from"], "/user.slice/s.scope");
    assert!(rig.notes()[0]["summary"]
        .as_str()
        .unwrap()
        .contains(&format!("synapsectl undo {id}")));

    // the emulated kernel does not move processes, so cgroup.procs of the suspect still lists them: undo reads that
    let a = rig.r.undo(id, "uid 0", T0 + S).unwrap();
    assert_eq!(a.status, ActionStatus::Undone, "{:?}", a.error);
    assert_eq!(a.decided_by.as_deref(), Some("uid 0"));
    assert_eq!(rig.cg_procs("user.slice/s.scope"), [200, 201]);
    assert!(!rig.path(&format!("cg/{suspect}")).exists());
    assert!(rig.r.undo(id, "uid 0", T0 + S).is_err(), "undone once");
}

#[test]
fn kill_is_freeze_plus_cgroup_kill_and_cannot_be_undone() {
    let mut rig = Rig::new(Mode::Contain, |_, _| {});
    emulate(&rig);
    let id = rig.alert("SYN-B-0010", "kill", Some(200), json!({}));
    let a = rig.action(id);
    assert_eq!(a.status, ActionStatus::Executed, "{:?}", a.error);
    assert_eq!(a.undo.as_ref().unwrap()["killed"], true);
    assert_eq!(
        fs::read_to_string(rig.path(&format!("cg/synapse.slice/suspect-{id}/cgroup.kill")))
            .unwrap(),
        "1"
    );
    assert!(rig
        .r
        .undo(id, "uid 0", T0)
        .unwrap_err()
        .contains("cannot be brought back"));
    assert!(!rig.notes()[0]["summary"].as_str().unwrap().contains("undo"));
}

#[test]
fn the_allowlist_is_checked_on_the_live_system() {
    let mut rig = Rig::new(Mode::Contain, |_, _| {});
    emulate(&rig);
    let skipped = |rig: &Rig, id: i64, why: &str| {
        let a = rig.action(id);
        assert_eq!(a.status, ActionStatus::Skipped, "{:?}", a.error);
        assert!(
            a.error.as_deref().unwrap().contains(why),
            "{:?} lacks {why}",
            a.error
        );
    };
    let id = rig.alert("SYN-B-0001", "freeze", Some(100), json!({}));
    skipped(&rig, id, "session leaders");
    let id = rig.alert("SYN-B-0001", "freeze", Some(300), json!({}));
    skipped(&rig, id, "engine.allow_exe");
    // pid 200 was replaced by a newer process with the same pid
    rig.proc(200, 100, 100, 9000, "/usr/bin/vim");
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    skipped(&rig, id, "PID now belongs to another process");
    rig.proc(200, 100, 100, 200, "/tmp/evil");
    rig.pacman.store(true, Ordering::Relaxed);
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    skipped(&rig, id, "pacman transaction");
    rig.pacman.store(false, Ordering::Relaxed);
    let id = rig.alert("SYN-B-0001", "freeze", None, json!({}));
    skipped(&rig, id, "names no process");
    assert!(
        !rig.path("cg/synapse.slice").exists()
            || fs::read_dir(rig.path("cg/synapse.slice")).unwrap().count() == 0
    );
}

#[test]
fn the_budget_trips_the_circuit_breaker() {
    let mut rig = Rig::new(Mode::Contain, |c, _| c.engine.max_actions_per_minute = 2);
    emulate(&rig);
    for pid in [400, 401, 402, 403] {
        rig.proc(pid, 100, 100, u64::from(pid), "/tmp/evil");
    }
    let ids: Vec<i64> = [400, 401, 402, 403]
        .iter()
        .map(|p| rig.alert("SYN-B-0003", "freeze", Some(*p), json!({})))
        .collect();
    let st: Vec<ActionStatus> = ids.iter().map(|i| rig.action(*i).status).collect();
    assert_eq!(
        st,
        [
            ActionStatus::Executed,
            ActionStatus::Executed,
            ActionStatus::DryRun,
            ActionStatus::DryRun
        ]
    );
    assert!(rig
        .action(ids[2])
        .error
        .unwrap()
        .contains("circuit breaker tripped"));
    assert!(rig
        .action(ids[3])
        .error
        .unwrap()
        .contains("circuit breaker is open"));
    assert!(rig.r.breaker().is_some());
    assert!(rig.notes().iter().any(|n| n["rule_id"] == "SYN-R-0001"));
    // notifications never use up the budget
    let n = rig.alert("SYN-B-0005", "notify", Some(400), json!({}));
    assert_eq!(rig.action(n).status, ActionStatus::Executed);

    let reply = ipc::dispatch(&mut rig.r, &Request::BreakerReset, "uid 0");
    assert!(reply.ok && reply.message.contains("reset"), "{reply:?}");
    assert!(rig.r.breaker().is_none());
    // still two executed in the last minute: the next one trips it again
    rig.proc(404, 100, 100, 404, "/tmp/evil");
    let id = rig.alert("SYN-B-0003", "freeze", Some(404), json!({}));
    assert_eq!(rig.action(id).status, ActionStatus::DryRun);
}

#[test]
fn quarantine_waits_for_approval_then_undo_restores() {
    let mut rig = Rig::new(Mode::Enforce, |_, _| {});
    let victim = rig.path("Downloads-x.bin");
    fs::write(&victim, b"MZ evil").unwrap();
    let id = rig.alert(
        "YARA:x",
        "quarantine",
        Some(200),
        json!({"path": victim.to_str().unwrap()}),
    );
    assert_eq!(rig.action(id).status, ActionStatus::Pending);
    assert!(rig.notes()[0]["summary"]
        .as_str()
        .unwrap()
        .contains(&format!("synapsectl approve {id}")));
    assert!(victim.exists());
    assert_eq!(rig.r.store().pending_actions().unwrap().len(), 1);

    let reply = ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0 (pid 7)");
    assert!(reply.ok, "{reply:?}");
    assert_eq!(reply.data["status"], "executed", "{reply:?}");
    assert!(!victim.exists());
    let stored = rig.path(&format!("q/{id}.bin"));
    assert!(stored.exists());
    assert!(ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0")
        .message
        .contains("not pending"));

    // unprivileged test: the mode-000 copy must be readable to restore it
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&stored, fs::Permissions::from_mode(0o400)).unwrap();
    let reply = ipc::dispatch(&mut rig.r, &Request::Undo { id }, "uid 0");
    assert!(reply.ok, "{reply:?}");
    assert_eq!(fs::read(&victim).unwrap(), b"MZ evil");
}

#[test]
fn rejected_and_refused_files() {
    let mut rig = Rig::new(Mode::Enforce, |_, store| {
        store
            .trust_replace_package(
                "coreutils",
                &[TrustEntry {
                    path: b"/usr/bin/ls".to_vec(),
                    sha256: Sha256([0; 32]),
                    package: "coreutils".into(),
                    size: 1,
                    mtime_ns: 0,
                    verified_ns: 0,
                }],
            )
            .unwrap();
    });
    let id = rig.alert(
        "SYN-H-0001",
        "quarantine",
        Some(200),
        json!({"path": "/usr/bin/ls"}),
    );
    let reply = ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0");
    assert_eq!(reply.data["status"], "skipped");
    assert!(reply.data["error"]
        .as_str()
        .unwrap()
        .contains("pacman -S coreutils"));

    let victim = rig.path("y.bin");
    fs::write(&victim, b"y").unwrap();
    let id = rig.alert(
        "YARA:y",
        "quarantine",
        Some(200),
        json!({"path": victim.to_str().unwrap()}),
    );
    let reply = ipc::dispatch(&mut rig.r, &Request::Reject { id }, "uid 0");
    assert_eq!(reply.data["status"], "rejected");
    assert!(victim.exists());
    assert!(rig.r.undo(id, "uid 0", T0).is_err(), "nothing was done");
}

#[test]
fn block_and_unblock_through_nft() {
    let mut rig = Rig::new(Mode::Enforce, |_, _| {});
    let id = rig.alert(
        "SYN-B-0012",
        "block",
        Some(200),
        json!({"dst": "203.0.113.5:3333"}),
    );
    assert_eq!(rig.action(id).status, ActionStatus::Pending);
    let reply = ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0");
    assert_eq!(reply.data["status"], "executed", "{reply:?}");
    assert_eq!(reply.data["undo"]["addr"], "203.0.113.5");
    let docs = rig.nft.0.lock().unwrap().clone();
    assert_eq!(docs.len(), 2, "create table, add element");
    assert_eq!(
        docs[1]["nftables"][0]["add"]["element"]["elem"][0]["elem"]["timeout"],
        3600
    );
    rig.r.undo(id, "uid 0", T0).unwrap();
    assert!(rig.nft.0.lock().unwrap()[2]["nftables"][0]
        .get("delete")
        .is_some());

    let id = rig.alert(
        "SYN-B-0012",
        "block",
        Some(200),
        json!({"dst": "127.0.0.1:53"}),
    );
    let reply = ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0");
    assert_eq!(reply.data["status"], "skipped");
    let id = rig.alert("SYN-B-0012", "block", Some(200), json!({"dst": "nonsense"}));
    assert_eq!(rig.action(id).status, ActionStatus::Skipped);
}

#[test]
fn dry_run_restore_and_approval_limits() {
    let mut rig = Rig::new(Mode::Contain, |c, _| c.response.dry_run = true);
    emulate(&rig);
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    let a = rig.action(id);
    assert_eq!(a.status, ActionStatus::DryRun);
    assert!(a.error.unwrap().contains("response.dry_run"));

    let id = rig.alert(
        "SYN-I-0001",
        "restore",
        Some(200),
        json!({"path": "/usr/bin/ls"}),
    );
    assert_eq!(rig.action(id).status, ActionStatus::Skipped);

    // contain mode caps at level 3: quarantine is only recorded
    let id = rig.alert("YARA:x", "quarantine", Some(200), json!({"path": "/tmp/x"}));
    assert_eq!(rig.action(id).status, ActionStatus::DryRun);

    let mut rig = Rig::new(Mode::Contain, |c, _| c.response.auto_levels_max = 1);
    emulate(&rig);
    let id = rig.alert("SYN-B-0001", "freeze", Some(200), json!({}));
    assert_eq!(
        rig.action(id).status,
        ActionStatus::Pending,
        "above auto_levels_max"
    );
    let reply = ipc::dispatch(&mut rig.r, &Request::Approve { id }, "uid 0");
    assert_eq!(reply.data["status"], "executed", "{reply:?}");
    assert_eq!(
        rig.cg_procs(&format!("synapse.slice/suspect-{id}")),
        [200, 201]
    );

    let status = ipc::dispatch(&mut rig.r, &Request::Status, "uid 0");
    assert_eq!(status.data["mode"], "contain");
    assert_eq!(status.data["auto_level_max"], 1);
}

#[test]
fn the_cursor_starts_after_history_and_moves_on() {
    let mut rig = Rig::new(Mode::AlertOnly, |_, _| {});
    rig.alert("SYN-B-0005", "notify", Some(200), json!({}));
    let first = synapse_responderd::start_cursor(rig.r.store()).unwrap();
    assert_eq!(first, 1, "existing alerts are history");
    assert_eq!(
        synapse_responderd::start_cursor(rig.r.store()).unwrap(),
        1,
        "stored"
    );
    for _ in 0..3 {
        rig.r
            .store()
            .insert_alert(&NewAlert {
                ts_ns: T0,
                rule_id: "SYN-B-0005".into(),
                severity: Severity::Medium,
                confidence: 0.5,
                title: "t".into(),
                proc_key: None,
                event_id: None,
                detail: json!({"action": "notify"}),
            })
            .unwrap();
    }
    let c = synapse_responderd::step(&mut rig.r, first).unwrap();
    assert_eq!(c, 4);
    assert_eq!(
        rig.r
            .store()
            .state_get(synapse_responderd::CURSOR_KEY)
            .unwrap()
            .as_deref(),
        Some("4")
    );
    assert_eq!(synapse_responderd::step(&mut rig.r, c).unwrap(), 4);
}

#[test]
fn without_cgroups_kill_uses_a_pidfd_on_the_real_process() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.general.mode = Mode::Contain;
    let sys = System {
        procfs: ProcFs::system(),
        cgroups: Cgroups::new(dir.path().join("no-cgroup-here")),
        quarantine: Quarantine::new(dir.path().join("q")),
        nft: Box::new(Nft::default()),
        notifier: Notifier::new(dir.path()),
        pacman_active: Box::new(|| false),
        self_pid: std::process::id(),
    };
    let mut r = Responder::new(cfg, Store::open_in_memory().unwrap(), sys);
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let live = ProcFs::system().get(child.id()).unwrap();
    let key = ProcKey {
        pid: child.id(),
        start_ns: live.start_ns,
    };
    let mut alert = |action: &str| {
        let id = r
            .store()
            .insert_alert(&NewAlert {
                ts_ns: T0,
                rule_id: "SYN-B-0001".into(),
                severity: Severity::High,
                confidence: 0.9,
                title: "t".into(),
                proc_key: Some(key),
                event_id: None,
                detail: json!({"action": action}),
            })
            .unwrap();
        let a = r.store().get_alert(id).unwrap().unwrap();
        let act = r.handle_alert(&a, T0).unwrap().unwrap();
        r.store().get_action(act).unwrap().unwrap()
    };
    let frozen = alert("freeze");
    assert_eq!(frozen.status, ActionStatus::Failed);
    assert!(frozen.error.unwrap().contains("cgroup v2 is not mounted"));
    let killed = alert("kill");
    assert_eq!(killed.status, ActionStatus::Executed, "{:?}", killed.error);
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9), "SIGKILL");
}
