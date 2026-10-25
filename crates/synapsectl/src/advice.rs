//! M5 commands: the analyzer's advice and the human decision on rule proposals.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use synapse_common::config::Config;
use synapse_common::event::now_ns;
use synapse_common::model::ProposalStatus;
use synapse_engined::ai::approved_rule_path;
use synapse_rules::rule::{Rule, RuleFile, RuleSet};

use crate::detect::{open_db, Res};
use crate::render::{format_ts, sanitize};

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub fn ai_notes(cfg: &Path, db: Option<&Path>, n: usize, json: bool) -> Res {
    let store = open_db(cfg, db)?;
    for note in store.recent_ai_notes(n).map_err(s)? {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "id": note.id, "ts_ns": note.ts_ns, "alert_id": note.alert_id, "model": note.model,
                    "verdict": note.verdict, "confidence": note.confidence, "summary": note.summary,
                    "attack_techniques": note.techniques, "indicators": note.indicators,
                    "injection_suspected": note.injection_suspected, "dropped": note.problems,
                })
            );
        } else {
            println!(
                "{} #{:<4} alert {:<5} {:<10} {:.2}{}  {}",
                format_ts(note.ts_ns),
                note.id,
                note.alert_id.map_or("-".to_owned(), |a| a.to_string()),
                note.verdict,
                note.confidence,
                if note.injection_suspected {
                    "  [INJECTION ATTEMPT IN THE DATA]"
                } else {
                    ""
                },
                sanitize(&note.summary)
            );
        }
    }
    Ok(())
}

pub fn proposals(cfg: &Path, db: Option<&Path>, n: usize, json: bool) -> Res {
    let store = open_db(cfg, db)?;
    for p in store.proposals(n).map_err(s)? {
        if json {
            println!(
                "{}",
                serde_json::json!({"id": p.id, "ts_ns": p.ts_ns, "source": p.source, "alert_id": p.alert_id, "rule": p.rule,
                                   "status": p.status.as_str(), "decided_by": p.decided_by, "reason": p.reason})
            );
        } else {
            let title = p.rule.get("title").and_then(|v| v.as_str()).unwrap_or("?");
            println!(
                "{} #{:<4} {:<13} {}  {}{}",
                format_ts(p.ts_ns),
                p.id,
                p.status.as_str(),
                sanitize(title),
                p.reason
                    .as_deref()
                    .map(|r| format!("({})", sanitize(r)))
                    .unwrap_or_default(),
                if p.status == ProposalStatus::Pending {
                    "   -> synapsectl proposal-show ID, approve-rule ID, reject-rule ID"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

/// The rule as it would be installed: id `LOCAL-ai-<proposal id>`, as TOML.
fn rule_toml(rule_json: &serde_json::Value, id: i64) -> Result<(String, Rule), String> {
    let mut rule: Rule = serde_json::from_value(rule_json.clone())
        .map_err(|e| format!("stored rule is invalid: {e}"))?;
    rule.id = format!("LOCAL-ai-{id}");
    let problems = rule.problems();
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let text = toml::to_string_pretty(&RuleFile {
        rule: vec![rule.clone()],
    })
    .map_err(s)?;
    Ok((format!("# Approved AI proposal {id}. Edit or delete this file; the engine reloads rules by itself.\n{text}"), rule))
}

pub fn proposal_show(cfg: &Path, db: Option<&Path>, id: i64) -> Res {
    let store = open_db(cfg, db)?;
    let p = store
        .get_proposal(id)
        .map_err(s)?
        .ok_or(format!("no proposal {id}"))?;
    println!(
        "proposal {id}: {} ({})",
        p.status.as_str(),
        p.reason.as_deref().unwrap_or("-")
    );
    let (text, _) = rule_toml(&p.rule, id)?;
    println!("\nThis is the rule that approve-rule would install:\n\n{text}");
    Ok(())
}

/// Install the rule in `<rules_dir>/behavior/local/ai-<id>.toml` after the whole set still validates, then mark it approved.
pub fn approve_rule(cfg_path: &Path, db: Option<&Path>, id: i64, rules_dir: Option<&Path>) -> Res {
    let cfg = Config::load(cfg_path).map_err(s)?;
    let store = open_db(cfg_path, db)?;
    let p = store
        .get_proposal(id)
        .map_err(s)?
        .ok_or(format!("no proposal {id}"))?;
    if p.status != ProposalStatus::Pending {
        return Err(format!(
            "proposal {id} is {}, not pending",
            p.status.as_str()
        ));
    }
    let (text, _) = rule_toml(&p.rule, id)?;
    let dir = rules_dir.map_or_else(|| cfg.engine.rules_dir.clone(), Path::to_path_buf);
    let path = approved_rule_path(&dir, id);
    fs::create_dir_all(path.parent().ok_or("bad path")?)
        .map_err(|e| format!("{}: {e} (run as root)", path.display()))?;
    let tmp = path.with_extension("toml.new");
    // written under a name the loader ignores, so the check below sees the set as it would be
    fs::write(&tmp, &text).map_err(|e| format!("{}: {e} (run as root)", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).map_err(s)?;
    // the existing set must be valid, the id free, and the new text must parse on its own
    let existing = RuleSet::load_dir(&dir.join("behavior"))
        .map_err(|e| format!("the current rules are invalid: {e}"))?;
    if existing
        .rules
        .iter()
        .any(|r| r.id == format!("LOCAL-ai-{id}"))
    {
        let _ = fs::remove_file(&tmp);
        return Err(format!("a rule LOCAL-ai-{id} is already installed"));
    }
    if let Err(e) = RuleSet::parse_str(&text, "the proposal") {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    fs::rename(&tmp, &path).map_err(s)?;
    let set = RuleSet::load_dir(&dir.join("behavior"));
    if let Err(e) = set {
        let _ = fs::remove_file(&path);
        return Err(format!(
            "the rule set would not validate with this rule, so it was not installed: {e}"
        ));
    }
    store
        .decide_proposal(id, ProposalStatus::Approved, "root", None, now_ns())
        .map_err(s)?;
    println!("proposal {id} approved: {} installed as LOCAL-ai-{id}; the engine reloads it within seconds", path.display());
    Ok(())
}

pub fn reject_rule(cfg: &Path, db: Option<&Path>, id: i64, reason: Option<&str>) -> Res {
    let store = open_db(cfg, db)?;
    if store
        .decide_proposal(id, ProposalStatus::Rejected, "root", reason, now_ns())
        .map_err(s)?
    {
        println!("proposal {id} rejected");
        Ok(())
    } else {
        Err(format!("proposal {id} does not exist or is not pending"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synapse_common::store::Store;

    const RULE: &str = r#"{"id":"LOCAL-ai-x","title":"curl into sh","severity":"medium","confidence":0.6,"match":{"event":"exec","exe_in":["/usr/bin/sh"],"stdin_from_exe_in":["/usr/bin/curl"]},"action":"notify"}"#;

    fn setup() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        fs::create_dir_all(rules.join("behavior")).unwrap();
        let cfg = dir.path().join("synapse.toml");
        fs::write(
            &cfg,
            format!(
                "[engine]\nrules_dir = '{}'\n[paths]\nstate_dir = '{}'\n",
                rules.display(),
                dir.path().display()
            ),
        )
        .unwrap();
        let db = dir.path().join("t.db");
        (dir, cfg, db, rules)
    }

    #[test]
    fn a_rule_round_trips_through_toml_with_a_fresh_id() {
        let v: serde_json::Value = serde_json::from_str(RULE).unwrap();
        let (text, rule) = rule_toml(&v, 12).unwrap();
        assert_eq!(rule.id, "LOCAL-ai-12");
        let back = RuleSet::parse_str(&text, "t").unwrap();
        assert_eq!(back, vec![rule]);
        // a stored rule that no longer validates is refused
        let bad = serde_json::json!({"id": "x", "title": "", "severity": "low", "confidence": 3, "match": {"event": "exec"}, "action": "log"});
        assert!(rule_toml(&bad, 1).is_err());
    }

    #[test]
    fn approving_installs_the_rule_once_and_rejecting_decides_once() {
        let (_d, cfg, db, rules) = setup();
        let store = Store::open(&db).unwrap();
        let rule: serde_json::Value = serde_json::from_str(RULE).unwrap();
        let a = store
            .insert_proposal(1, "ai", None, &rule, ProposalStatus::Pending, None)
            .unwrap();
        let b = store
            .insert_proposal(1, "ai", None, &rule, ProposalStatus::Pending, None)
            .unwrap();
        let c = store
            .insert_proposal(
                1,
                "ai",
                None,
                &rule,
                ProposalStatus::AutoRejected,
                Some("fires"),
            )
            .unwrap();
        drop(store);

        approve_rule(&cfg, Some(&db), a, None).unwrap();
        let installed = RuleSet::load_dir(&rules.join("behavior")).unwrap();
        assert_eq!(installed.rules.len(), 1);
        assert_eq!(installed.rules[0].id, format!("LOCAL-ai-{a}"));
        assert!(approve_rule(&cfg, Some(&db), a, None).is_err(), "not twice");
        approve_rule(&cfg, Some(&db), b, None).unwrap();
        assert_eq!(
            RuleSet::load_dir(&rules.join("behavior"))
                .unwrap()
                .rules
                .len(),
            2
        );
        assert!(
            approve_rule(&cfg, Some(&db), c, None).is_err(),
            "an auto-rejected proposal cannot be approved"
        );

        let d = Store::open(&db)
            .unwrap()
            .insert_proposal(2, "ai", None, &rule, ProposalStatus::Pending, None)
            .unwrap();
        reject_rule(&cfg, Some(&db), d, Some("too broad")).unwrap();
        assert!(reject_rule(&cfg, Some(&db), d, None).is_err());
        let st = Store::open(&db).unwrap();
        assert_eq!(
            st.get_proposal(d).unwrap().unwrap().status,
            ProposalStatus::Rejected
        );
        assert_eq!(
            st.get_proposal(a).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        // no stray files left behind
        let names: Vec<_> = fs::read_dir(rules.join("behavior/local"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| n.ends_with(".toml")), "{names:?}");
    }

    #[test]
    fn a_broken_existing_rule_set_blocks_approval() {
        let (_d, cfg, db, rules) = setup();
        fs::write(rules.join("behavior/broken.toml"), "[[rule]]\nid = 'nope'").unwrap();
        let store = Store::open(&db).unwrap();
        let rule: serde_json::Value = serde_json::from_str(RULE).unwrap();
        let id = store
            .insert_proposal(1, "ai", None, &rule, ProposalStatus::Pending, None)
            .unwrap();
        assert!(approve_rule(&cfg, Some(&db), id, None).is_err());
        assert_eq!(
            store.get_proposal(id).unwrap().unwrap().status,
            ProposalStatus::Pending
        );
    }
}
