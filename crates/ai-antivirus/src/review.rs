//! Interactive alert review, user feedback and self-healing memory commands.
//! When alerts are flagged by the AI analyzer, the user can review them and indicate
//! whether the detected activity is safe. Safe verdicts are recorded in the self-healing
//! memory table (`ai_feedback`), so future recurrences of this activity are automatically
//! recognized by the LLM and dropped without bothering the user.

use std::io::{self, BufRead, Write};
use std::path::Path;

use ai_antivirus_common::config::Config;
use ai_antivirus_common::event::now_ns;
use ai_antivirus_common::store::{AiFeedbackRow, Store};
use serde_json::json;

/// Interactively review pending alerts and query the user for safe/suspicious feedback.
pub fn interactive_review(config: &Path, alert_id: Option<i64>) -> Result<(), String> {
    let cfg = Config::load(config).map_err(|e| e.to_string())?;
    let store = Store::open(&cfg.db_path()).map_err(|e| e.to_string())?;

    let alerts = if let Some(id) = alert_id {
        match store.get_alert(id).map_err(|e| e.to_string())? {
            Some(a) => vec![a],
            None => {
                println!("Alert #{id} not found.");
                return Ok(());
            }
        }
    } else {
        store.unacked_alerts(50).map_err(|e| e.to_string())?
    };

    if alerts.is_empty() {
        println!("No pending unacknowledged alerts to review. Everything is clean!");
        return Ok(());
    }

    println!("\nAI Antivirus Interactive Alert Review & Self-Healing");
    println!("Found {} pending alert(s).\n", alerts.len());

    let notes = store.recent_ai_notes(100).map_err(|e| e.to_string())?;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    for a in &alerts {
        println!("================================================================================");
        println!("Alert ID:     #{}", a.id);
        println!("Rule ID:      {}", a.rule_id);
        println!("Severity:     {}", a.severity.as_str());
        println!("Title:        {}", a.title);

        let exe = a.detail.get("exe").and_then(|v| v.as_str());
        if let Some(e) = exe {
            println!("Executable:   {}", e);
        }
        if let Some(argv) = a.detail.get("argv").and_then(|v| v.as_array()) {
            let cmd: Vec<&str> = argv.iter().filter_map(|x| x.as_str()).collect();
            println!("Command:      {}", cmd.join(" "));
        }

        // Look for corresponding AI analysis note
        let note = notes.iter().find(|n| n.alert_id == Some(a.id));
        if let Some(n) = note {
            println!("\n--- AI Analyzer Review ---");
            println!("Verdict:      {}", n.verdict);
            println!("Confidence:   {:.0}%", n.confidence * 100.0);
            println!("Summary:      {}", n.summary);
            if n.injection_suspected {
                println!("Warning:      Prompt injection suspected in machine evidence!");
            }
        } else {
            println!("\n(No local AI analyzer notes for this alert yet)");
        }
        println!("--------------------------------------------------------------------------------");

        print!("User Verdict: [s]afe (learn & drop), [a]ck (dismiss once), [k]eep pending, [q]uit: ");
        io::stdout().flush().map_err(|e| e.to_string())?;

        let choice = match lines.next() {
            Some(Ok(s)) => s.trim().to_lowercase(),
            _ => break,
        };

        match choice.as_str() {
            "s" | "safe" => {
                print!("Optional notes / reason (e.g., 'known dev script') [Enter for none]: ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let notes_str = lines
                    .next()
                    .and_then(|r| r.ok())
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let user_notes = if notes_str.is_empty() {
                    "User confirmed safe via interactive review".to_string()
                } else {
                    notes_str
                };

                let fb = AiFeedbackRow {
                    id: 0,
                    ts_ns: now_ns(),
                    alert_id: Some(a.id),
                    rule_id: a.rule_id.clone(),
                    exe: exe.map(str::to_string),
                    sha256: None,
                    title: a.title.clone(),
                    verdict: "safe".to_string(),
                    user_notes,
                };
                store.insert_ai_feedback(&fb).map_err(|e| e.to_string())?;
                store.ack_alerts(&[a.id]).map_err(|e| e.to_string())?;
                println!(
                    "✔ Alert #{} marked as SAFE and recorded in self-healing memory.",
                    a.id
                );
                println!("  Future matching alerts will be recognized by AI and dropped automatically.\n");
            }
            "a" | "ack" => {
                store.ack_alerts(&[a.id]).map_err(|e| e.to_string())?;
                println!("✔ Alert #{} acknowledged without learning.\n", a.id);
            }
            "k" | "keep" => {
                println!("Alert #{} remains pending.\n", a.id);
            }
            "q" | "quit" => {
                println!("Exiting review.");
                break;
            }
            _ => {
                println!("Unknown choice; skipping alert #{}.\n", a.id);
            }
        }
    }

    Ok(())
}

/// Directly mark an alert as safe and learn its pattern into self-healing memory.
pub fn mark_safe(config: &Path, alert_id: i64, notes: Option<String>) -> Result<(), String> {
    let cfg = Config::load(config).map_err(|e| e.to_string())?;
    let store = Store::open(&cfg.db_path()).map_err(|e| e.to_string())?;

    let alert = store
        .get_alert(alert_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Alert #{alert_id} not found in database"))?;

    let exe = alert.detail.get("exe").and_then(|v| v.as_str());
    let user_notes = notes.unwrap_or_else(|| "User confirmed safe via CLI".to_string());

    let fb = AiFeedbackRow {
        id: 0,
        ts_ns: now_ns(),
        alert_id: Some(alert.id),
        rule_id: alert.rule_id.clone(),
        exe: exe.map(str::to_string),
        sha256: None,
        title: alert.title.clone(),
        verdict: "safe".to_string(),
        user_notes: user_notes.clone(),
    };

    let fb_id = store.insert_ai_feedback(&fb).map_err(|e| e.to_string())?;
    store.ack_alerts(&[alert.id]).map_err(|e| e.to_string())?;

    println!("✔ Alert #{} successfully marked as SAFE (Memory record #{fb_id}).", alert.id);
    println!("  Rule:       {}", alert.rule_id);
    if let Some(e) = exe {
        println!("  Executable: {e}");
    }
    println!("  Notes:      {user_notes}");
    println!("  Self-healing active: recurrence of this pattern will be dropped automatically by AI review.");

    Ok(())
}

/// List learned safe entries from self-healing memory.
pub fn list_feedback(config: &Path, limit: usize, json_output: bool) -> Result<(), String> {
    let cfg = Config::load(config).map_err(|e| e.to_string())?;
    let store = Store::open(&cfg.db_path()).map_err(|e| e.to_string())?;
    let entries = store.recent_ai_feedback(limit).map_err(|e| e.to_string())?;

    if json_output {
        println!("{}", json!({ "feedback": entries }));
        return Ok(());
    }

    if entries.is_empty() {
        println!("No learned self-healing entries recorded yet.");
        println!("Use `ai-antivirus review` or `ai-antivirus mark-safe <id>` to teach safe patterns.");
        return Ok(());
    }

    println!("\nAI Antivirus Self-Healing Memory (Learned Safe Patterns)");
    println!("==========================================================================================");
    println!(
        "{:<6} {:<16} {:<28} {:<10} {:<24}",
        "ID", "Rule ID", "Executable", "Verdict", "User Notes"
    );
    println!("------------------------------------------------------------------------------------------");
    for f in &entries {
        let exe = f.exe.as_deref().unwrap_or("-");
        let exe_trunc: String = if exe.len() > 26 {
            format!("...{}", &exe[exe.len() - 23..])
        } else {
            exe.to_string()
        };
        let notes_trunc: String = if f.user_notes.len() > 24 {
            format!("{}...", &f.user_notes[..21])
        } else {
            f.user_notes.clone()
        };
        println!(
            "{:<6} {:<16} {:<28} {:<10} {:<24}",
            f.id, f.rule_id, exe_trunc, f.verdict, notes_trunc
        );
    }
    println!("==========================================================================================\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::model::Severity;
    use ai_antivirus_common::store::NewAlert;

    #[test]
    fn mark_safe_records_feedback_and_drops_alert() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ai-antivirus.db");
        let cfg_path = dir.path().join("ai-antivirus.toml");
        std::fs::write(
            &cfg_path,
            format!("[paths]\nstate_dir = \"{}\"\n", dir.path().display()),
        )
        .unwrap();

        let store = Store::open(&db_path).unwrap();
        let alert_id = store
            .insert_alert(&NewAlert {
                ts_ns: 1000,
                rule_id: "AV-B-0002".into(),
                severity: Severity::High,
                confidence: 0.8,
                title: "Download piped to shell".into(),
                proc_key: None,
                event_id: None,
                detail: json!({"exe": "/usr/bin/curl", "argv": ["curl", "sh"]}),
            })
            .unwrap();

        assert_eq!(store.unacked_alerts(10).unwrap().len(), 1);

        mark_safe(&cfg_path, alert_id, Some("Developer toolchain".into())).unwrap();

        // Alert is now dropped (acknowledged)
        assert_eq!(store.unacked_alerts(10).unwrap().len(), 0);

        // Feedback memory is recorded
        let fb = store.get_ai_feedback("AV-B-0002", Some("/usr/bin/curl")).unwrap();
        assert_eq!(fb.len(), 1);
        assert_eq!(fb[0].verdict, "safe");
        assert_eq!(fb[0].user_notes, "Developer toolchain");

        // list_feedback prints successfully
        assert!(list_feedback(&cfg_path, 10, true).is_ok());
        assert!(list_feedback(&cfg_path, 10, false).is_ok());
    }
}
