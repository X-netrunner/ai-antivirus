//! Synapse responder daemon (M4): turns alerts into actions (spec 8). It follows the `alerts` table, decides what may
//! run (mode ladder, `response.dry_run`, circuit breaker, approval for levels above `response.auto_levels_max`, the
//! per-minute action budget), checks the allowlist against the live system, acts, and records every outcome with an
//! undo record in `actions`. A root-only Unix socket takes the human decisions: approve, reject, undo, breaker reset.
//!
//! It is the only Synapse process that changes the system, so it re-checks everything itself: the engine's allowlist
//! capping is a first line, not the only one.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cgroup;
pub mod guard;
pub mod ipc;
pub mod nft;
pub mod notify;
pub mod procfs;
pub mod quarantine;
pub mod responder;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use synapse_common::config::Config;
use synapse_common::event::now_ns;
use synapse_common::notify::Heartbeat;
use synapse_common::store::Store;
use tracing::{error, info, warn};

use crate::responder::{Responder, System};

/// Last alert id handled, kept in the `state` table so a restart neither repeats nor skips alerts.
pub const CURSOR_KEY: &str = "responder.last_alert_id";
const POLL: Duration = Duration::from_millis(300);
const BATCH: usize = 100;
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// Where to start: the stored cursor, or (first start) the newest alert, so history is never acted on.
pub fn start_cursor(store: &Store) -> Result<i64, String> {
    if let Some(v) = store.state_get(CURSOR_KEY).map_err(|e| e.to_string())? {
        return v
            .parse()
            .map_err(|_| format!("bad {CURSOR_KEY} in the state table: {v:?}"));
    }
    let newest = store.max_alert_id().map_err(|e| e.to_string())?;
    store
        .state_set(CURSOR_KEY, &newest.to_string(), now_ns())
        .map_err(|e| e.to_string())?;
    info!(
        after = newest,
        "first start: existing alerts are not acted on"
    );
    Ok(newest)
}

/// Handle every alert after `cursor`; returns the new cursor.
pub fn step(r: &mut Responder, mut cursor: i64) -> Result<i64, String> {
    let alerts = r
        .store()
        .alerts_after(cursor, BATCH)
        .map_err(|e| e.to_string())?;
    for a in &alerts {
        if let Err(e) = r.handle_alert(a, now_ns()) {
            // the cursor still moves on: an alert that cannot be recorded must not block every later one
            error!(alert = a.id, error = %e, "alert not handled");
        }
        cursor = a.id;
        r.store()
            .state_set(CURSOR_KEY, &cursor.to_string(), now_ns())
            .map_err(|e| e.to_string())?;
    }
    Ok(cursor)
}

/// The daemon: serve the control socket and follow the alerts until `shutdown`.
pub fn run(cfg: &Config, shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    let db = cfg.db_path();
    // root must not create the database: it would be root-owned and the engine could not open it
    if !db.exists() {
        return Err(format!(
            "{} does not exist; start synapse-engined first (or run synapsectl db-init as user synapse)",
            db.display()
        ));
    }
    let store = Store::open(&db).map_err(|e| e.to_string())?;
    let mut cursor = start_cursor(&store)?;
    let responder = Arc::new(Mutex::new(Responder::new(
        cfg.clone(),
        store,
        System::real(cfg),
    )));

    let sock = cfg.responder_socket();
    let server = match ipc::bind(&sock) {
        Ok(l) => {
            let (r, stop) = (Arc::clone(&responder), Arc::clone(shutdown));
            Some(thread::spawn(move || ipc::serve(l, r, stop)))
        }
        Err(e) => {
            warn!(socket = %sock.display(), error = %e, "control socket unavailable: approve, reject and undo will not work");
            None
        }
    };
    info!(
        mode = cfg.general.mode.as_str(),
        dry_run = cfg.response.dry_run,
        auto_level_max = cfg.effective_max_auto_level().min(responder::HARD_AUTO_MAX),
        after_alert = cursor,
        "responder running"
    );

    let mut last_sweep = Instant::now();
    let mut heartbeat = Heartbeat::from_env();
    heartbeat.ready("following alerts");
    while !shutdown.load(Ordering::Relaxed) {
        heartbeat.tick();
        let before = cursor;
        match responder.lock() {
            Ok(mut r) => {
                cursor = step(&mut r, cursor).unwrap_or_else(|e| {
                    warn!(error = %e, "cannot read alerts");
                    cursor
                });
                if last_sweep.elapsed() >= SWEEP_EVERY {
                    r.sweep();
                    last_sweep = Instant::now();
                }
            }
            Err(_) => return Err("responder state poisoned".into()),
        }
        if cursor == before {
            thread::sleep(POLL);
        }
    }
    heartbeat.stopping();
    if let Some(t) = server {
        let _ = t.join();
    }
    let _ = std::fs::remove_file(&sock);
    info!("responder stopped");
    Ok(())
}
