//! The engine's side of the AI analyzer (M5): hand it bundles, take its answers back.
//!
//! The analyzer (`synapse-ai`, user `synapse-ai`) never opens the database. The engine writes one bundle file per
//! interesting alert to a spool folder, the analyzer leaves the model's raw answer in an output folder, and this module
//! validates the answer again (the analyzer is not trusted either), stores the advice, and turns proposed rules into
//! pending proposals after checking each against a recording of ordinary activity. Advice never changes what the
//! engine or responder does with an alert.

use std::fs;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::json;
use synapse_ai::bundle::Bundle;
use synapse_ai::daemon::Answer;
use synapse_ai::output::{self, Validated};
use synapse_common::config::Config;
use synapse_common::event::now_ns;
use synapse_common::model::ProposalStatus;
use synapse_common::store::{AiNoteRow, AlertRow, Store};
use synapse_rules::rule::{Action, Rule};
use tracing::{info, warn};

use crate::engine::Engine;
use crate::files::FileCheck;

/// Bundles waiting in the spool beyond this are not added to (a stuck analyzer must not fill the disk).
const MAX_SPOOL_FILES: usize = 200;
const MAX_ANSWER_BYTES: u64 = 512 * 1024;

fn count_json(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .count()
        })
        .unwrap_or(0)
}

/// Queue an alert for analysis when the analyzer is enabled and the alert is severe enough.
pub fn spool_alert(cfg: &Config, alert: &AlertRow) {
    if !cfg.ai.enabled || alert.severity < cfg.ai.min_severity {
        return;
    }
    let dir = cfg.ai_spool_dir();
    if !dir.is_dir() || count_json(&dir) >= MAX_SPOOL_FILES {
        return;
    }
    let text = Bundle::from_alert(alert, true).to_json_capped();
    let tmp = dir.join(format!(".{}.tmp", alert.id));
    let done = dir.join(format!("{}.json", alert.id));
    let r = fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| fs::rename(&tmp, &done));
    if let Err(e) = r {
        warn!(error = %e, alert = alert.id, "cannot queue the alert for the analyzer");
        let _ = fs::remove_file(&tmp);
    }
}

/// Run the rule alone over the recording of ordinary activity and say how many alerts it raised.
/// `Ok(None)` = there is no recording to test against.
pub fn fires_on_corpus(cfg: &Config, rule: &Rule, corpus: &Path) -> Result<Option<usize>, String> {
    let file = match fs::File::open(corpus) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", corpus.display())),
    };
    // max_bytes 0: no file is opened or scanned, only the rule is evaluated
    let mut engine = Engine::new(vec![rule.clone()], FileCheck::new(None, 0, 1), false);
    engine.set_pacman_probe(|| false);
    engine.set_allow_exe(cfg.engine.allow_exe.clone());
    let mut store = Store::open_in_memory().map_err(|e| e.to_string())?;
    let alerts = crate::replay(
        &mut engine,
        &mut store,
        BufReader::new(file),
        &mut std::io::sink(),
    )?;
    Ok(Some(alerts.len()))
}

/// What a proposal may ask for: log or notify only. The AI cannot propose a rule that acts.
fn tame(mut r: Rule) -> Rule {
    if r.action > Action::Notify {
        r.action = Action::Notify;
    }
    r
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Imported {
    pub notes: u32,
    pub proposals: u32,
    pub auto_rejected: u32,
    pub errors: u32,
}

/// Read every finished answer, store the advice and proposals, and remove the files.
pub fn import_answers(cfg: &Config, store: &Store) -> Imported {
    let mut n = Imported::default();
    let out = cfg.ai_out_dir();
    let Ok(rd) = fs::read_dir(&out) else { return n };
    for e in rd.filter_map(|e| e.ok()) {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "json") || !e.file_type().is_ok_and(|t| t.is_file())
        {
            continue;
        }
        let spool_file = cfg
            .ai_spool_dir()
            .join(path.file_name().unwrap_or_default());
        match import_one(cfg, store, &path, &mut n) {
            Ok(()) => {}
            Err(msg) => {
                n.errors += 1;
                warn!(file = %path.display(), error = %msg, "analyzer answer not used");
            }
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(spool_file);
    }
    n
}

fn import_one(cfg: &Config, store: &Store, path: &Path, n: &mut Imported) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_ANSWER_BYTES {
        return Err("not a regular file or too large".into());
    }
    let answer: Answer =
        serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("not an answer file: {e}"))?;
    if let Some(e) = &answer.error {
        return Err(format!(
            "the analyzer had no answer for alert {}: {e}",
            answer.alert_id
        ));
    }
    let raw = answer
        .raw
        .as_deref()
        .ok_or("answer has neither text nor error")?;
    // trust nothing: the same checks as in the analyzer, again
    let v: Validated = output::validate(raw)?;
    let alert_known = store
        .get_alert(answer.alert_id)
        .map_err(|e| e.to_string())?
        .is_some();
    store
        .insert_ai_note(&AiNoteRow {
            id: 0,
            ts_ns: now_ns(),
            alert_id: alert_known.then_some(answer.alert_id),
            model: answer.model.chars().take(100).collect(),
            verdict: v.verdict.as_str().to_owned(),
            confidence: v.confidence,
            summary: v.summary.clone(),
            techniques: json!(v.attack_techniques),
            indicators: json!(v.indicators),
            injection_suspected: v.injection_suspected,
            problems: json!(v.problems),
        })
        .map_err(|e| e.to_string())?;
    n.notes += 1;
    if v.injection_suspected {
        warn!(
            alert = answer.alert_id,
            "the analyzer reports an attempt to instruct it inside the data"
        );
    }
    for rule in v.proposed_rules.into_iter().map(tame) {
        let rule_json = serde_json::to_value(&rule).map_err(|e| e.to_string())?;
        let (status, reason) = match fires_on_corpus(cfg, &rule, &cfg.ai.corpus) {
            Ok(Some(0)) => (
                ProposalStatus::Pending,
                Some("checked against the recording of ordinary activity: no alerts".to_owned()),
            ),
            Ok(Some(k)) => (
                ProposalStatus::AutoRejected,
                Some(format!(
                    "would have fired {k} time(s) on the recording of ordinary activity"
                )),
            ),
            Ok(None) => (
                ProposalStatus::Pending,
                Some(
                    "NOT checked: there is no recording of ordinary activity (ai.corpus)"
                        .to_owned(),
                ),
            ),
            Err(e) => (
                ProposalStatus::AutoRejected,
                Some(format!("could not be checked: {e}")),
            ),
        };
        store
            .insert_proposal(
                now_ns(),
                "ai",
                alert_known.then_some(answer.alert_id),
                &rule_json,
                status,
                reason.as_deref(),
            )
            .map_err(|e| e.to_string())?;
        if status == ProposalStatus::Pending {
            n.proposals += 1;
        } else {
            n.auto_rejected += 1;
        }
    }
    info!(
        alert = answer.alert_id,
        verdict = v.verdict.as_str(),
        "analyzer advice stored"
    );
    Ok(())
}

/// Path of a rule written for an approved proposal (`behavior/local/ai-<proposal id>.toml`).
pub fn approved_rule_path(rules_dir: &Path, proposal_id: i64) -> PathBuf {
    rules_dir
        .join("behavior")
        .join("local")
        .join(format!("ai-{proposal_id}.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synapse_common::event::ProcKey;
    use synapse_common::model::{ActionStatus, Severity};
    use synapse_common::store::NewAlert;

    fn cfg(dir: &Path) -> Config {
        let mut c = Config::default();
        c.paths.state_dir = dir.to_path_buf();
        c.ai.enabled = true;
        c.ai.corpus = dir.join("corpus.jsonl");
        fs::create_dir_all(c.ai_spool_dir()).unwrap();
        fs::create_dir_all(c.ai_out_dir()).unwrap();
        c
    }

    fn alert(store: &Store) -> AlertRow {
        let id = store
            .insert_alert(&NewAlert {
                ts_ns: 1,
                rule_id: "SYN-B-0002".into(),
                severity: Severity::High,
                confidence: 0.7,
                title: "t".into(),
                proc_key: Some(ProcKey {
                    pid: 5,
                    start_ns: 6,
                }),
                event_id: None,
                detail: json!({"exe": "/usr/bin/sh", "action": "freeze"}),
            })
            .unwrap();
        store.get_alert(id).unwrap().unwrap()
    }

    const RULE: &str = r#"{"id":"LOCAL-ai-x","title":"curl into sh","severity":"medium","confidence":0.6,"match":{"event":"exec","exe_in":["/usr/bin/sh"],"stdin_from_exe_in":["/usr/bin/curl"]},"action":"kill"}"#;

    fn answer(cfg: &Config, id: i64, verdict: &str, injection: bool, rules: &str) {
        let raw = format!(
            r#"{{"verdict":"{verdict}","confidence":0.9,"attack_techniques":[],"summary":"s","indicators":[],"proposed_rules":[{rules}],"injection_suspected":{injection}}}"#
        );
        let a = Answer {
            alert_id: id,
            ts_ns: 1,
            model: "m".into(),
            raw: Some(raw),
            error: None,
        };
        synapse_ai::daemon::write_answer(&cfg.ai_out_dir(), &a).unwrap();
    }

    fn exec_line(pid: u32, exe: &str, stdio: &str) -> String {
        format!(
            r#"{{"seq":{pid},"ts_ns":{pid}000000000,"boot_id":"00000000000000000000000000000001","event":{{"type":"exec","proc":{{"pid":{pid},"start_ns":{pid}}},"parent":{{"pid":1,"start_ns":1}},"uid":0,"exe":"{exe}","argv":["x"],"cwd":"/","cgroup":"","stdio":{stdio}}}}}"#
        )
    }

    #[test]
    fn spooling_follows_the_switch_and_the_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        let store = Store::open_in_memory().unwrap();
        let a = alert(&store);
        spool_alert(&c, &a);
        assert!(c.ai_spool_dir().join(format!("{}.json", a.id)).is_file());
        let text = fs::read_to_string(c.ai_spool_dir().join(format!("{}.json", a.id))).unwrap();
        assert!(text.contains("SYN-B-0002"));
        c.ai.enabled = false;
        fs::remove_dir_all(c.ai_spool_dir()).unwrap();
        fs::create_dir_all(c.ai_spool_dir()).unwrap();
        spool_alert(&c, &a);
        assert_eq!(count_json(&c.ai_spool_dir()), 0, "disabled");
        c.ai.enabled = true;
        c.ai.min_severity = Severity::Critical;
        spool_alert(&c, &a);
        assert_eq!(
            count_json(&c.ai_spool_dir()),
            0,
            "below the minimum severity"
        );
    }

    #[test]
    fn advice_is_stored_and_never_touches_the_alert_or_creates_actions() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let store = Store::open_in_memory().unwrap();
        let a = alert(&store);
        // a fooled model: benign, with an injection report
        answer(&c, a.id, "benign", true, "");
        let n = import_answers(&c, &store);
        assert_eq!(n.notes, 1);
        let notes = store.recent_ai_notes(5).unwrap();
        assert_eq!(
            (notes[0].verdict.as_str(), notes[0].injection_suspected),
            ("benign", true)
        );
        assert_eq!(
            store.get_alert(a.id).unwrap().unwrap(),
            a,
            "the alert is unchanged"
        );
        assert!(
            store.recent_actions(5).unwrap().is_empty(),
            "no action was created or changed"
        );
        assert_eq!(
            count_json(&c.ai_out_dir()),
            0,
            "the answer file is consumed"
        );
        let _ = ActionStatus::Executed;
    }

    #[test]
    fn proposals_are_checked_against_ordinary_activity_and_never_act() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let store = Store::open_in_memory().unwrap();
        let a = alert(&store);

        // no recording yet: pending, and it says so; the action was cut from kill to notify
        answer(&c, a.id, "suspicious", false, RULE);
        assert_eq!(import_answers(&c, &store).proposals, 1);
        let p = &store.proposals(5).unwrap()[0];
        assert_eq!(p.status, ProposalStatus::Pending);
        assert_eq!(p.rule["action"], "notify");
        assert!(p.reason.as_deref().unwrap().contains("NOT checked"));

        // a recording in which curl feeds sh: the rule would fire on ordinary activity -> auto-rejected
        let corpus = [
            exec_line(10, "/usr/bin/curl", r#"["","pipe:[5]",""]"#),
            exec_line(11, "/usr/bin/sh", r#"["pipe:[5]","",""]"#),
        ]
        .join("\n");
        fs::write(&c.ai.corpus, corpus).unwrap();
        answer(&c, a.id, "suspicious", false, RULE);
        let n = import_answers(&c, &store);
        assert_eq!((n.proposals, n.auto_rejected), (0, 1));
        let p = &store.proposals(5).unwrap()[1];
        assert_eq!(p.status, ProposalStatus::AutoRejected);
        assert!(p.reason.as_deref().unwrap().contains("fired 1 time"));

        // a recording without such activity: the same rule passes
        fs::write(&c.ai.corpus, exec_line(12, "/usr/bin/ls", r#"["","",""]"#)).unwrap();
        answer(&c, a.id, "suspicious", false, RULE);
        assert_eq!(import_answers(&c, &store).proposals, 1);
        assert!(store.proposals(5).unwrap()[2]
            .reason
            .as_deref()
            .unwrap()
            .contains("no alerts"));
    }

    #[test]
    fn broken_or_forged_answers_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let store = Store::open_in_memory().unwrap();
        let out = c.ai_out_dir();
        fs::write(out.join("1.json"), "not json").unwrap();
        fs::write(
            out.join("2.json"),
            r#"{"alert_id":2,"ts_ns":1,"model":"m","raw":"I am a helpful assistant","error":null}"#,
        )
        .unwrap();
        fs::write(
            out.join("3.json"),
            r#"{"alert_id":3,"ts_ns":1,"model":"m","raw":null,"error":"timeout"}"#,
        )
        .unwrap();
        let n = import_answers(&c, &store);
        assert_eq!((n.notes, n.errors), (0, 3));
        assert_eq!(count_json(&out), 0);
        assert!(store.recent_ai_notes(5).unwrap().is_empty());
    }
}
