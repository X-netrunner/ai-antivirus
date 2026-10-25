//! M4 commands: the action log, and the human decisions sent to the responder over its control socket (root only).

use std::io::{self, Write};
use std::path::Path;

use ai_antivirus_common::config::Config;
use ai_antivirus_common::model::ActionStatus;
use ai_antivirus_responderd::ipc::{self, action_json, Request};

use crate::detect::{open_db, Res};
use crate::render::{format_ts, sanitize};

fn target_text(t: &serde_json::Value) -> String {
    match t.get("kind").and_then(|k| k.as_str()) {
        Some("process") => format!(
            "pid={}{}",
            t["pid"],
            t.get("exe")
                .and_then(|e| e.as_str())
                .map(|e| format!(" {e}"))
                .unwrap_or_default()
        ),
        Some("file") => t["path"].as_str().unwrap_or("?").to_owned(),
        Some("ip") => t["addr"].as_str().unwrap_or("?").to_owned(),
        _ => String::new(),
    }
}

pub fn actions(cfg: &Path, db: Option<&Path>, n: usize, json: bool, pending: bool) -> Res {
    let store = open_db(cfg, db)?;
    let rows = if pending {
        store.pending_actions()
    } else {
        store.recent_actions(n)
    }
    .map_err(|e| e.to_string())?;
    let mut out = io::stdout().lock();
    for a in rows {
        let line = if json {
            action_json(&a).to_string()
        } else {
            let hint = match a.status {
                ActionStatus::Pending => {
                    format!("  -> ai-antivirus approve {} | reject {}", a.id, a.id)
                }
                ActionStatus::Executed if a.action != "kill" && a.action != "notify" => {
                    format!("  -> ai-antivirus undo {}", a.id)
                }
                _ => String::new(),
            };
            format!(
                "{} #{:<5} {:<9} {:<10} {:<12} {}{}{}",
                format_ts(a.ts_ns),
                a.id,
                a.status.as_str(),
                a.action,
                sanitize(a.rule_id.as_deref().unwrap_or("-")),
                sanitize(&target_text(&a.target)),
                a.error
                    .as_deref()
                    .map(|e| format!("  ({})", sanitize(e)))
                    .unwrap_or_default(),
                hint,
            )
        };
        writeln!(out, "{line}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Send one request; `Ok(false)` when the responder said no (exit status 1).
pub fn control(cfg: &Path, req: &Request, json: bool) -> Result<bool, String> {
    let cfg = Config::load(cfg).map_err(|e| e.to_string())?;
    let reply = ipc::request(&cfg.responder_socket(), req)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&reply).map_err(|e| e.to_string())?
        );
    } else if matches!(req, Request::Status) && reply.ok {
        let d = &reply.data;
        println!("mode            {}", d["mode"].as_str().unwrap_or("?"));
        println!("dry_run         {}", d["dry_run"]);
        println!("auto level max  {}", d["auto_level_max"]);
        println!("pending         {}", d["pending"]);
        match d["breaker"].as_object() {
            None => println!("breaker         closed"),
            Some(b) => println!(
                "breaker         OPEN since {} ({}); ai-antivirus breaker-reset",
                b.get("tripped_ns")
                    .and_then(|v| v.as_u64())
                    .map(format_ts)
                    .unwrap_or_default(),
                sanitize(b.get("reason").and_then(|v| v.as_str()).unwrap_or(""))
            ),
        }
    } else {
        println!("{}", sanitize(&reply.message));
    }
    Ok(reply.ok)
}
