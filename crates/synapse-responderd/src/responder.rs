//! What happens to one alert: plan (which action, on what), decide (mode ladder, dry-run, circuit breaker, approval,
//! budget), check the allowlist against the live system, act, and record an undo. Also the human side: approve, reject,
//! undo, breaker reset.
//!
//! Every outcome is one row in `actions`, including the ones that did nothing (`dry_run`, `skipped`, `pending`,
//! `rejected`), so `synapsectl actions` always explains why something was or was not done.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use synapse_common::config::Config;
use synapse_common::event::ProcKey;
use synapse_common::model::ActionStatus;
use synapse_common::store::{ActionRow, AlertRow, Store};
use synapse_rules::rule::Action;
use tracing::{info, warn};

use crate::cgroup::{Cgroups, Member};
use crate::guard::{self, Context, Refusal};
use crate::nft::{self, Nft};
use crate::notify::{Notification, Notifier};
use crate::procfs::{LiveProc, ProcFs};
use crate::quarantine::{Quarantine, Record};

/// Levels above this always wait for a human in M4, whatever `response.auto_levels_max` says (spec 8: quarantine,
/// block and restore need approval until the false-positive rate on the machine is known).
pub const HARD_AUTO_MAX: u8 = 3;
/// Most processes one freeze moves (a fork bomb must not stall the responder).
const MAX_TREE: usize = 512;
const FREEZE_WAIT: Duration = Duration::from_secs(1);
const MINUTE_NS: u64 = 60 * 1_000_000_000;
pub const BREAKER_KEY: &str = "responder.breaker";

/// What an action is aimed at. Stored as the action's `target` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// Notifications: the alert itself.
    Alert,
    Process {
        pid: u32,
        start_ns: u64,
        exe: Option<String>,
    },
    File {
        path: String,
    },
    Ip {
        addr: IpAddr,
    },
}

/// Undo data of a freeze or kill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contained {
    pub cgroup: String,
    pub members: Vec<Member>,
    pub killed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocked {
    pub addr: IpAddr,
    pub ttl_secs: u32,
    pub expires_ns: u64,
}

/// The circuit breaker's stored state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breaker {
    pub tripped_ns: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Execute,
    DryRun(String),
    Pending,
    Skipped(String),
}

/// Everything the responder touches on the system. Swapped for fakes in tests.
pub struct System {
    pub procfs: ProcFs,
    pub cgroups: Cgroups,
    pub quarantine: Quarantine,
    pub nft: Box<dyn Nft>,
    pub notifier: Notifier,
    pub pacman_active: Box<dyn Fn() -> bool + Send>,
    pub self_pid: u32,
}

impl System {
    pub fn real(cfg: &Config) -> System {
        System {
            procfs: ProcFs::system(),
            cgroups: Cgroups::new(&cfg.response.cgroup_root),
            quarantine: Quarantine::new(cfg.quarantine_dir()),
            nft: Box::new(nft::NftCmd),
            notifier: Notifier::new(&cfg.response.notify_dir),
            pacman_active: Box::new(synapse_rules::mtree::pacman_active),
            self_pid: std::process::id(),
        }
    }
}

pub struct Responder {
    cfg: Config,
    store: Store,
    sys: System,
}

/// Which action an alert asks for, and its target. The engine stores the action in `detail.action`.
pub fn plan(alert: &AlertRow) -> Result<(Action, Target), String> {
    let action = match alert.detail.get("action") {
        None => Action::Log,
        Some(v) => serde_json::from_value::<Action>(v.clone())
            .map_err(|_| format!("unknown action {v} in the alert"))?,
    };
    let process = || {
        let k = alert.proc_key.ok_or("the alert names no process")?;
        Ok::<_, String>(Target::Process {
            pid: k.pid,
            start_ns: k.start_ns,
            exe: alert
                .detail
                .get("exe")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    };
    let target = match action {
        Action::Log | Action::Notify => Target::Alert,
        Action::Freeze | Action::Kill => process()?,
        Action::Quarantine | Action::Restore => {
            let path = alert
                .detail
                .get("path")
                .and_then(Value::as_str)
                .ok_or("the alert names no file")?;
            Target::File {
                path: path.to_owned(),
            }
        }
        Action::Block => {
            let dst = alert
                .detail
                .get("dst")
                .and_then(Value::as_str)
                .ok_or("the alert names no address")?;
            let addr = dst
                .parse::<SocketAddr>()
                .map(|s| s.ip())
                .or_else(|_| dst.parse::<IpAddr>())
                .map_err(|_| format!("{dst:?} is not an address"))?;
            Target::Ip { addr }
        }
    };
    Ok((action, target))
}

fn action_of(row: &ActionRow) -> Result<Action, String> {
    serde_json::from_value(Value::String(row.action.clone()))
        .map_err(|_| format!("unknown action {}", row.action))
}

fn target_of(row: &ActionRow) -> Result<Target, String> {
    serde_json::from_value(row.target.clone())
        .map_err(|e| format!("bad target in action {}: {e}", row.id))
}

fn describe(action: Action, t: &Target) -> String {
    match t {
        Target::Alert => action.as_str().to_owned(),
        Target::Process { pid, exe, .. } => format!(
            "{} process {pid}{} and its children",
            action.as_str(),
            exe.as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        ),
        Target::File { path } => format!("{} {path}", action.as_str()),
        Target::Ip { addr } => format!("{} {addr}", action.as_str()),
    }
}

impl Responder {
    pub fn new(cfg: Config, store: Store, sys: System) -> Responder {
        Responder { cfg, store, sys }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn cx(&self) -> (Vec<PathBuf>, bool, u32) {
        (
            self.cfg.engine.allow_exe.clone(),
            (self.sys.pacman_active)(),
            self.sys.self_pid,
        )
    }

    pub fn breaker(&self) -> Option<Breaker> {
        self.store
            .state_get(BREAKER_KEY)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
    }

    pub fn reset_breaker(&self) -> Result<bool, String> {
        let was = self.breaker().is_some();
        self.store
            .state_delete(BREAKER_KEY)
            .map_err(|e| e.to_string())?;
        if was {
            info!("circuit breaker reset");
        }
        Ok(was)
    }

    fn decide(&self, action: Action, now: u64) -> Result<Decision, String> {
        let level = action.level();
        if action == Action::Notify {
            return Ok(Decision::Execute);
        }
        if action == Action::Restore {
            return Ok(Decision::Skipped("restore is not built yet (M6)".into()));
        }
        let mode = self.cfg.general.mode;
        if level > mode.max_level() {
            return Ok(Decision::DryRun(format!(
                "mode {} allows up to level {}",
                mode.as_str(),
                mode.max_level()
            )));
        }
        if self.cfg.response.dry_run {
            return Ok(Decision::DryRun("response.dry_run = true".into()));
        }
        if let Some(b) = self.breaker() {
            return Ok(Decision::DryRun(format!(
                "circuit breaker is open ({}); reset with synapsectl breaker-reset",
                b.reason
            )));
        }
        if level > self.cfg.effective_max_auto_level().min(HARD_AUTO_MAX) {
            return Ok(Decision::Pending);
        }
        let budget = u64::from(self.cfg.engine.max_actions_per_minute);
        let used = self
            .store
            .executed_since(now.saturating_sub(MINUTE_NS), 2)
            .map_err(|e| e.to_string())?;
        if used >= budget {
            let reason = format!("{used} automatic actions in the last minute (engine.max_actions_per_minute = {budget})");
            self.trip(now, &reason);
            return Ok(Decision::DryRun(format!(
                "circuit breaker tripped: {reason}"
            )));
        }
        Ok(Decision::Execute)
    }

    fn trip(&self, now: u64, reason: &str) {
        let b = Breaker {
            tripped_ns: now,
            reason: reason.to_owned(),
        };
        if let Ok(v) = serde_json::to_string(&b) {
            if let Err(e) = self.store.state_set(BREAKER_KEY, &v, now) {
                warn!(error = %e, "cannot store the circuit breaker state");
            }
        }
        warn!(
            reason,
            "circuit breaker tripped: falling back to alert-only"
        );
        self.notify(Notification {
            ts_ns: now,
            alert_id: None,
            action_id: None,
            rule_id: "SYN-R-0001".into(),
            severity: "high".into(),
            title: "Synapse responder circuit breaker tripped".into(),
            summary: format!("{reason}. Synapse only records what it would do until you run: synapsectl breaker-reset"),
        });
    }

    fn notify(&self, n: Notification) {
        if let Err(e) = self.sys.notifier.send(&n) {
            warn!(error = %e, "notification not delivered");
        }
    }

    /// Respond to one new alert. Returns the action id, or `None` when the alert only asks to be logged.
    pub fn handle_alert(&mut self, alert: &AlertRow, now: u64) -> Result<Option<i64>, String> {
        let (action, target) = match plan(alert) {
            Ok(p) => p,
            Err(e) => {
                let id = self.record(
                    alert,
                    "log",
                    0,
                    &json!({"kind": "alert"}),
                    ActionStatus::Skipped,
                    Some(&e),
                    now,
                )?;
                warn!(alert = alert.id, error = %e, "alert cannot be acted on");
                return Ok(Some(id));
            }
        };
        if action == Action::Log {
            return Ok(None);
        }
        let decision = self.decide(action, now)?;
        let target_json = serde_json::to_value(&target).map_err(|e| e.to_string())?;
        let id = self.record(
            alert,
            action.as_str(),
            action.level(),
            &target_json,
            ActionStatus::Pending,
            None,
            now,
        )?;
        let what = describe(action, &target);
        let summary = match decision {
            Decision::Execute => match self.execute(id, action, &target, alert, now) {
                Ok(undo) => {
                    self.update(id, ActionStatus::Executed, undo.as_ref(), None, None, now)?;
                    info!(action = id, alert = alert.id, "{what}: done");
                    if action == Action::Notify {
                        return Ok(Some(id));
                    }
                    let undo_hint = if action == Action::Kill {
                        String::new()
                    } else {
                        format!(" Undo: synapsectl undo {id}")
                    };
                    format!("Synapse did: {what}.{undo_hint}")
                }
                Err(e) => {
                    let status = if e.starts_with("refused: ") {
                        ActionStatus::Skipped
                    } else {
                        ActionStatus::Failed
                    };
                    self.update(id, status, None, Some(&e), None, now)?;
                    warn!(action = id, alert = alert.id, error = %e, "{what}: not done");
                    format!("Synapse did not {what}: {e}")
                }
            },
            Decision::DryRun(reason) => {
                let check = self.preview(action, &target);
                let note = format!("{reason}; {check}");
                self.update(id, ActionStatus::DryRun, None, Some(&note), None, now)?;
                info!(
                    action = id,
                    alert = alert.id,
                    "dry run: would {what} ({note})"
                );
                format!("Would {what} ({note}).")
            }
            Decision::Pending => {
                info!(
                    action = id,
                    alert = alert.id,
                    "waiting for approval: {what}"
                );
                format!(
                    "Waiting for your approval to {what}: synapsectl approve {id} (or reject {id})"
                )
            }
            Decision::Skipped(reason) => {
                self.update(id, ActionStatus::Skipped, None, Some(&reason), None, now)?;
                format!("Not done: {what} ({reason})")
            }
        };
        self.notify(Notification {
            ts_ns: now,
            alert_id: Some(alert.id),
            action_id: Some(id),
            rule_id: alert.rule_id.clone(),
            severity: alert.severity.as_str().into(),
            title: alert.title.clone(),
            summary,
        });
        Ok(Some(id))
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        alert: &AlertRow,
        action: &str,
        level: u8,
        target: &Value,
        status: ActionStatus,
        error: Option<&str>,
        now: u64,
    ) -> Result<i64, String> {
        let id = self
            .store
            .insert_action(
                now,
                Some(alert.id),
                Some(&alert.rule_id),
                action,
                level,
                target,
                status,
            )
            .map_err(|e| e.to_string())?;
        if error.is_some() {
            self.update(id, status, None, error, None, now)?;
        }
        Ok(id)
    }

    fn update(
        &self,
        id: i64,
        status: ActionStatus,
        undo: Option<&Value>,
        error: Option<&str>,
        by: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        self.store
            .update_action(id, status, undo, error, by, now)
            .map_err(|e| e.to_string())
    }

    /// What a dry run would have run into (read-only).
    fn preview(&self, action: Action, target: &Target) -> String {
        let (allow, pacman, me) = self.cx();
        let cx = Context {
            allow_exe: &allow,
            pacman_active: pacman,
            self_pid: me,
        };
        let res: Result<String, Refusal> = match target {
            Target::Alert => Ok("nothing to check".into()),
            Target::Process { pid, start_ns, .. } => {
                let key = ProcKey {
                    pid: *pid,
                    start_ns: *start_ns,
                };
                match self.sys.procfs.resolve(key) {
                    None => Err(Refusal("the process is gone".into())),
                    Some(p) => guard::check_process(&p, &self.sys.procfs.ancestor_exes(p.pid), &cx)
                        .map(|()| {
                            format!(
                                "{} process(es) would be affected",
                                self.sys.procfs.tree(p.pid, MAX_TREE).len()
                            )
                        }),
                }
            }
            Target::File { path } => {
                guard::check_file(Path::new(path), self.package_of(path).as_deref(), &cx)
                    .map(|()| "the file may be quarantined".into())
            }
            Target::Ip { addr } => {
                guard::check_ip(*addr).map(|()| "the address may be blocked".into())
            }
        };
        match (action, res) {
            (_, Ok(s)) => s,
            (_, Err(r)) => format!("it would be refused: {r}"),
        }
    }

    fn package_of(&self, path: &str) -> Option<String> {
        self.store
            .trust_get(path.as_bytes())
            .ok()
            .flatten()
            .map(|t| t.package)
    }

    /// Do it. `Err("refused: ...")` when the allowlist said no, any other `Err` when it failed.
    fn execute(
        &self,
        id: i64,
        action: Action,
        target: &Target,
        alert: &AlertRow,
        now: u64,
    ) -> Result<Option<Value>, String> {
        let (allow, pacman, me) = self.cx();
        let cx = Context {
            allow_exe: &allow,
            pacman_active: pacman,
            self_pid: me,
        };
        let refused = |r: Refusal| format!("refused: {r}");
        match (action, target) {
            (Action::Notify, _) => {
                self.notify(Notification {
                    ts_ns: now,
                    alert_id: Some(alert.id),
                    action_id: Some(id),
                    rule_id: alert.rule_id.clone(),
                    severity: alert.severity.as_str().into(),
                    title: alert.title.clone(),
                    summary: alert
                        .detail
                        .get("exe")
                        .and_then(Value::as_str)
                        .map(|e| format!("Program: {e}"))
                        .unwrap_or_default(),
                });
                Ok(None)
            }
            (Action::Freeze | Action::Kill, Target::Process { pid, start_ns, .. }) => {
                let key = ProcKey {
                    pid: *pid,
                    start_ns: *start_ns,
                };
                let c = self.contain(id, key, action == Action::Kill, &cx)?;
                Ok(Some(to_json(&c)?))
            }
            (Action::Quarantine, Target::File { path }) => {
                guard::check_file(Path::new(path), self.package_of(path).as_deref(), &cx)
                    .map_err(refused)?;
                let rec = self
                    .sys
                    .quarantine
                    .put(id, Path::new(path))
                    .map_err(|e| format!("quarantine failed: {e}"))?;
                Ok(Some(to_json(&rec)?))
            }
            (Action::Block, Target::Ip { addr }) => {
                guard::check_ip(*addr).map_err(refused)?;
                let ttl = self.cfg.response.nft_block_ttl_secs;
                nft::block(self.sys.nft.as_ref(), *addr, ttl)?;
                let b = Blocked {
                    addr: *addr,
                    ttl_secs: ttl,
                    expires_ns: now + u64::from(ttl) * 1_000_000_000,
                };
                Ok(Some(to_json(&b)?))
            }
            (a, t) => Err(format!("{} cannot be applied to {t:?}", a.as_str())),
        }
    }

    /// Freeze (and for `kill`, then kill) a process tree in its own suspect cgroup.
    fn contain(
        &self,
        id: i64,
        key: ProcKey,
        kill: bool,
        cx: &Context<'_>,
    ) -> Result<Contained, String> {
        let refused = |r: Refusal| format!("refused: {r}");
        let fs = &self.sys.procfs;
        let root = fs.resolve(key).ok_or_else(|| {
            "refused: the process is gone or its PID now belongs to another process".to_owned()
        })?;
        guard::check_process(&root, &fs.ancestor_exes(root.pid), cx).map_err(refused)?;
        let cgs = &self.sys.cgroups;
        if !cgs.available() {
            if kill {
                return self.kill_pidfd(&root);
            }
            return Err("cgroup v2 is not mounted at response.cgroup_root; cannot freeze".into());
        }
        let cg = cgs
            .create(id)
            .map_err(|e| format!("cannot create the suspect cgroup: {e}"))?;
        let mut members: Vec<Member> = Vec::new();
        // two passes: children forked before their parent moved are still outside
        for _ in 0..2 {
            for p in fs.tree(root.pid, MAX_TREE) {
                if members.iter().any(|m| m.pid == p.pid) {
                    continue;
                }
                if p.pid != root.pid && guard::check_process(&p, &[], cx).is_err() {
                    continue;
                }
                if let Err(e) = self.move_verified(&cg, &p) {
                    if p.pid == root.pid {
                        let _ = cgs.remove(&cg);
                        return Err(format!(
                            "cannot move process {} into the suspect cgroup: {e}",
                            p.pid
                        ));
                    }
                    warn!(pid = p.pid, error = %e, "child not moved");
                    continue;
                }
                members.push(Member {
                    pid: p.pid,
                    start_ns: p.start_ns,
                    from: p.cgroup.clone(),
                });
            }
        }
        cgs.set_frozen(&cg, true)
            .map_err(|e| format!("cannot freeze: {e}"))?;
        if !cgs.wait_frozen(&cg, FREEZE_WAIT) {
            warn!(cgroup = %cg.display(), "not frozen within a second (a process in uninterruptible sleep?); the kernel finishes it later");
        }
        if kill {
            cgs.kill(&cg)
                .map_err(|e| format!("cgroup.kill failed (kernel 5.14+ needed): {e}"))?;
        }
        Ok(Contained {
            cgroup: Cgroups::suspect_name(id),
            members,
            killed: kill,
        })
    }

    /// Move one process, checking its identity right before and right after (PIDs are numbers in `cgroup.procs`).
    fn move_verified(&self, cg: &Path, p: &LiveProc) -> Result<(), String> {
        let same = |q: Option<LiveProc>| q.is_some_and(|q| q.start_ns == p.start_ns);
        if !same(self.sys.procfs.get(p.pid)) {
            return Err("the process changed".into());
        }
        self.sys
            .cgroups
            .move_pid(cg, p.pid)
            .map_err(|e| e.to_string())?;
        if !same(self.sys.procfs.get(p.pid)) {
            // the PID was reused in between: put the newcomer back where the original was
            if let Some(back) = self.sys.cgroups.path_of(&p.cgroup) {
                let _ = self.sys.cgroups.move_pid(&back, p.pid);
            }
            return Err("the PID was reused while moving it".into());
        }
        Ok(())
    }

    /// Without cgroup v2: SIGKILL through a pidfd, which cannot reach a process that reused the PID.
    fn kill_pidfd(&self, root: &LiveProc) -> Result<Contained, String> {
        let fd =
            synapse_sys::process::pidfd_open(root.pid).map_err(|e| format!("pidfd_open: {e}"))?;
        // the pidfd now names whatever owns the PID; it is ours only if the start time still matches
        if !self
            .sys
            .procfs
            .get(root.pid)
            .is_some_and(|q| q.start_ns == root.start_ns)
        {
            return Err("refused: the PID now belongs to another process".into());
        }
        synapse_sys::process::pidfd_send_signal(&fd, libc::SIGKILL)
            .map_err(|e| format!("kill: {e}"))?;
        Ok(Contained {
            cgroup: String::new(),
            members: vec![Member {
                pid: root.pid,
                start_ns: root.start_ns,
                from: root.cgroup.clone(),
            }],
            killed: true,
        })
    }

    /// Run a pending action a human approved.
    pub fn approve(&mut self, id: i64, by: &str, now: u64) -> Result<ActionRow, String> {
        let row = self.pending(id)?;
        let action = action_of(&row)?;
        let target = target_of(&row)?;
        let mode = self.cfg.general.mode;
        let block = if action.level() > mode.max_level() {
            Some(format!(
                "mode {} no longer allows level {}",
                mode.as_str(),
                action.level()
            ))
        } else if self.cfg.response.dry_run {
            Some("approved, but response.dry_run = true".to_owned())
        } else {
            None
        };
        if let Some(reason) = block {
            self.update(id, ActionStatus::DryRun, None, Some(&reason), Some(by), now)?;
        } else {
            let alert = row
                .alert_id
                .and_then(|a| self.store.get_alert(a).ok().flatten())
                .ok_or("the alert of this action is gone")?;
            match self.execute(id, action, &target, &alert, now) {
                Ok(undo) => self.update(
                    id,
                    ActionStatus::Executed,
                    undo.as_ref(),
                    None,
                    Some(by),
                    now,
                )?,
                Err(e) => {
                    let st = if e.starts_with("refused: ") {
                        ActionStatus::Skipped
                    } else {
                        ActionStatus::Failed
                    };
                    self.update(id, st, None, Some(&e), Some(by), now)?;
                }
            }
        }
        info!(action = id, by, "approved");
        self.get(id)
    }

    pub fn reject(&mut self, id: i64, by: &str, now: u64) -> Result<ActionRow, String> {
        self.pending(id)?;
        self.update(id, ActionStatus::Rejected, None, None, Some(by), now)?;
        info!(action = id, by, "rejected");
        self.get(id)
    }

    fn get(&self, id: i64) -> Result<ActionRow, String> {
        self.store
            .get_action(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no action {id}"))
    }

    fn pending(&self, id: i64) -> Result<ActionRow, String> {
        let row = self.get(id)?;
        if row.status != ActionStatus::Pending {
            return Err(format!("action {id} is {}, not pending", row.status));
        }
        Ok(row)
    }

    /// Reverse an executed action.
    pub fn undo(&mut self, id: i64, by: &str, now: u64) -> Result<ActionRow, String> {
        let row = self.get(id)?;
        if row.status != ActionStatus::Executed {
            return Err(format!(
                "action {id} is {}; only executed actions can be undone",
                row.status
            ));
        }
        let undo = row.undo.clone().unwrap_or(Value::Null);
        let note = match action_of(&row)? {
            Action::Notify | Action::Log => return Err("a notification has nothing to undo".into()),
            Action::Kill => {
                return Err("a killed process cannot be brought back; nothing to undo".into())
            }
            Action::Freeze => {
                let c: Contained =
                    serde_json::from_value(undo).map_err(|e| format!("bad undo record: {e}"))?;
                self.thaw(&c)?
            }
            Action::Quarantine => {
                let rec: Record =
                    serde_json::from_value(undo).map_err(|e| format!("bad undo record: {e}"))?;
                self.sys
                    .quarantine
                    .restore(&rec)
                    .map_err(|e| format!("restore failed: {e}"))?;
                None
            }
            Action::Block => {
                let b: Blocked =
                    serde_json::from_value(undo).map_err(|e| format!("bad undo record: {e}"))?;
                nft::unblock(self.sys.nft.as_ref(), b.addr)?;
                None
            }
            Action::Restore => return Err("restore is not built yet (M6)".into()),
        };
        self.update(
            id,
            ActionStatus::Undone,
            None,
            note.as_deref(),
            Some(by),
            now,
        )?;
        info!(action = id, by, "undone");
        self.get(id)
    }

    /// Thaw a suspect cgroup and move its members back. Returns a note when not everything went back.
    fn thaw(&self, c: &Contained) -> Result<Option<String>, String> {
        let cgs = &self.sys.cgroups;
        let cg = cgs
            .path_of(&c.cgroup)
            .ok_or("bad cgroup in the undo record")?;
        if !cg.exists() {
            return Ok(Some("the suspect cgroup is already gone".into()));
        }
        cgs.set_frozen(&cg, false)
            .map_err(|e| format!("cannot thaw: {e}"))?;
        let mut problems = Vec::new();
        let fallback = c.members.first().map(|m| m.from.clone());
        for pid in cgs.procs(&cg).unwrap_or_default() {
            let member = c.members.iter().find(|m| {
                m.pid == pid
                    && self
                        .sys
                        .procfs
                        .get(pid)
                        .is_some_and(|p| p.start_ns == m.start_ns)
            });
            // children born in the suspect cgroup go where their tree's root came from
            let Some(from) = member.map(|m| m.from.clone()).or_else(|| fallback.clone()) else {
                continue;
            };
            let moved = cgs
                .path_of(&from)
                .filter(|p| p.exists())
                .ok_or_else(|| format!("{from} is gone"))
                .and_then(|p| cgs.move_pid(&p, pid).map_err(|e| e.to_string()));
            if let Err(e) = moved {
                problems.push(format!("process {pid} stays in {} ({e})", c.cgroup));
            }
        }
        if problems.is_empty() {
            if let Err(e) = cgs.remove(&cg) {
                problems.push(format!("{} not removed: {e}", c.cgroup));
            }
        }
        Ok((!problems.is_empty()).then(|| problems.join("; ")))
    }

    /// Remove suspect cgroups whose processes are all gone (after a kill). Run now and then.
    pub fn sweep(&self) {
        for (id, path) in self.sys.cgroups.suspects() {
            if self.sys.cgroups.procs(&path).is_ok_and(|p| p.is_empty()) {
                let killed = self
                    .store
                    .get_action(id)
                    .ok()
                    .flatten()
                    .is_some_and(|a| a.action == "kill" || a.status == ActionStatus::Undone);
                if killed && self.sys.cgroups.remove(&path).is_ok() {
                    info!(action = id, "empty suspect cgroup removed");
                }
            }
        }
    }
}

fn to_json<T: Serialize>(v: &T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}
