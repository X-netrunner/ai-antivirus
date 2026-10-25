//! The responder's control socket (`<run_dir>/responder.sock`, mode 0600): one JSON request per connection, one JSON
//! reply. The peer's uid is taken from `SO_PEERCRED` (hard rule 5) and must be 0, so file permissions are not the only
//! barrier. The requests are the human decisions: approve, reject, undo, breaker reset, plus a status read.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use synapse_common::event::now_ns;
use synapse_common::store::ActionRow;
use tracing::{debug, warn};

use crate::responder::Responder;

const MAX_REQUEST: u64 = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Approve { id: i64 },
    Reject { id: i64 },
    Undo { id: i64 },
    BreakerReset,
    Status,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub data: Value,
}

impl Reply {
    fn err(message: impl Into<String>) -> Reply {
        Reply {
            ok: false,
            message: message.into(),
            data: Value::Null,
        }
    }
}

pub fn action_json(a: &ActionRow) -> Value {
    json!({
        "id": a.id, "ts_ns": a.ts_ns, "alert_id": a.alert_id, "rule_id": a.rule_id, "action": a.action,
        "level": a.level, "target": a.target, "status": a.status.as_str(), "undo": a.undo, "error": a.error,
        "decided_by": a.decided_by,
    })
}

/// Bind the socket: a stale socket file from an earlier run is replaced, anything else at the path is an error.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Answer one request (exposed for tests; `serve` adds the transport and the uid check).
pub fn dispatch(r: &mut Responder, req: &Request, by: &str) -> Reply {
    let now = now_ns();
    let done = |res: Result<ActionRow, String>, verb: &str| match res {
        Ok(a) => Reply {
            ok: true,
            message: format!(
                "action {} {verb}: now {}{}",
                a.id,
                a.status,
                a.error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ),
            data: action_json(&a),
        },
        Err(e) => Reply::err(e),
    };
    match req {
        Request::Approve { id } => done(r.approve(*id, by, now), "approved"),
        Request::Reject { id } => done(r.reject(*id, by, now), "rejected"),
        Request::Undo { id } => done(r.undo(*id, by, now), "undone"),
        Request::BreakerReset => match r.reset_breaker() {
            Ok(true) => Reply {
                ok: true,
                message: "circuit breaker reset; automatic actions resume".into(),
                data: Value::Null,
            },
            Ok(false) => Reply {
                ok: true,
                message: "circuit breaker was not tripped".into(),
                data: Value::Null,
            },
            Err(e) => Reply::err(e),
        },
        Request::Status => {
            let cfg = r.config();
            let pending = r.store().pending_actions().map(|p| p.len()).unwrap_or(0);
            Reply {
                ok: true,
                message: "ok".into(),
                data: json!({
                    "mode": cfg.general.mode.as_str(),
                    "dry_run": cfg.response.dry_run,
                    "auto_level_max": cfg.effective_max_auto_level().min(crate::responder::HARD_AUTO_MAX),
                    "breaker": r.breaker(),
                    "pending": pending,
                }),
            }
        }
    }
}

fn handle(stream: UnixStream, responder: &Mutex<Responder>) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let cred = synapse_sys::process::peer_cred(&stream)?;
    let mut out = stream.try_clone()?;
    let reply = if cred.uid != 0 {
        warn!(
            uid = cred.uid,
            pid = cred.pid,
            "control request from a non-root peer refused"
        );
        Reply::err("only root may control the responder")
    } else {
        let mut line = String::new();
        BufReader::new((&stream).take(MAX_REQUEST)).read_line(&mut line)?;
        match serde_json::from_str::<Request>(line.trim()) {
            Err(e) => Reply::err(format!("bad request: {e}")),
            Ok(req) => {
                debug!(?req, pid = cred.pid, "control request");
                let by = format!("uid {} (pid {})", cred.uid, cred.pid);
                match responder.lock() {
                    Ok(mut r) => dispatch(&mut r, &req, &by),
                    Err(_) => Reply::err("responder state is poisoned; restart the service"),
                }
            }
        }
    };
    let mut text = serde_json::to_vec(&reply).map_err(io::Error::other)?;
    text.push(b'\n');
    out.write_all(&text)
}

/// Accept requests until `stop` is set.
pub fn serve(listener: UnixListener, responder: Arc<Mutex<Responder>>, stop: Arc<AtomicBool>) {
    if let Err(e) = listener.set_nonblocking(true) {
        warn!(error = %e, "control socket cannot be made non-blocking; not serving it");
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = stream
                    .set_nonblocking(false)
                    .and_then(|()| handle(stream, &responder))
                {
                    warn!(error = %e, "control request failed");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => {
                warn!(error = %e, "accept failed");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

/// Client side, for `synapsectl`.
pub fn request(socket: &Path, req: &Request) -> Result<Reply, String> {
    let mut s = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot reach the responder at {} ({e}); is synapse-responderd running, and are you root?",
            socket.display()
        )
    })?;
    s.set_read_timeout(Some(IO_TIMEOUT * 3))
        .map_err(|e| e.to_string())?;
    let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line).map_err(|e| e.to_string())?;
    let mut answer = String::new();
    BufReader::new(s.take(MAX_REQUEST))
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(answer.trim()).map_err(|e| format!("bad reply from the responder: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_have_a_strict_wire_form() {
        let r: Request = serde_json::from_str(r#"{"op":"approve","id":4}"#).unwrap();
        assert_eq!(r, Request::Approve { id: 4 });
        assert_eq!(
            serde_json::to_string(&Request::BreakerReset).unwrap(),
            r#"{"op":"breaker_reset"}"#
        );
        assert!(serde_json::from_str::<Request>(r#"{"op":"approve","id":4,"x":1}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"exec","cmd":"sh"}"#).is_err());
    }

    #[test]
    fn bind_replaces_stale_sockets_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.sock");
        drop(bind(&p).unwrap());
        let l = bind(&p).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(l);
        let f = dir.path().join("file");
        fs::write(&f, "x").unwrap();
        assert!(bind(&f).is_err());
        assert!(f.exists());
    }

    #[test]
    fn the_server_checks_the_peer_uid() {
        use crate::responder::System;
        use synapse_common::config::Config;
        use synapse_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::default();
        let sys = System {
            procfs: crate::procfs::ProcFs::new(dir.path()),
            cgroups: crate::cgroup::Cgroups::emulated(dir.path()),
            quarantine: crate::quarantine::Quarantine::new(dir.path().join("q")),
            restorer: crate::restore::Restorer::new(dir.path()),
            nft: Box::new(crate::nft::fake::FakeNft::default()),
            notifier: crate::notify::Notifier::new(dir.path()),
            pacman_active: Box::new(|| false),
            self_pid: 1,
        };
        let r = Arc::new(Mutex::new(Responder::new(
            cfg,
            Store::open_in_memory().unwrap(),
            sys,
        )));
        let p = dir.path().join("s.sock");
        let l = bind(&p).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let t = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || serve(l, r, stop))
        };
        let status = request(&p, &Request::Status).unwrap();
        let bad = {
            let mut s = UnixStream::connect(&p).unwrap();
            s.write_all(b"{\"op\":\"shell\"}\n").unwrap();
            let mut a = String::new();
            BufReader::new(s).read_line(&mut a).unwrap();
            serde_json::from_str::<Reply>(&a).unwrap()
        };
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        assert!(!bad.ok);
        let root = synapse_sys::process::peer_cred(&UnixStream::pair().unwrap().0)
            .unwrap()
            .uid
            == 0;
        if root {
            assert!(status.ok, "{status:?}");
            assert_eq!(status.data["mode"], "alert-only");
            assert!(bad.message.starts_with("bad request"));
        } else {
            assert!(!status.ok);
            assert_eq!(status.message, "only root may control the responder");
            assert_eq!(bad.message, "only root may control the responder");
        }
    }
}
