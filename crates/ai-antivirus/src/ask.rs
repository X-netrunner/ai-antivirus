//! `ai-antivirus ask "..."`: a question to the local model, answered from AI Antivirus's own facts (the `status` figures and
//! the newest alerts). Advice only: the answer can name commands for you to run, nothing runs by itself. The endpoint
//! comes from `[ai]` in the config, which only accepts a loopback address, so nothing leaves the machine.

use std::path::Path;
use std::time::Duration;

use ai_antivirus_common::config::Config;
use serde_json::{json, Value};

use crate::detect::Res;
use crate::status::{self, Inputs};

/// Small instruct models first: quick enough for a panel, good enough to read facts. qwen3.5:4b (3.3 GB at q4) fits a
/// 6 GB GPU with room for the context; it is a thinking model, so requests turn thinking off (`"think": false`).
const PREFERRED: &[&str] = &[
    "qwen3.5:4b",
    "qwen3.5:4b-q4_K_M",
    "qwen2.5:3b-instruct",
    "qwen2.5:3b",
    "llama3.2:3b",
    "qwen3:4b",
    "qwen2.5:7b-instruct",
    "qwen2.5:7b",
    "llama3.1:8b",
    "qwen3:8b",
];
const PLACEHOLDER: &str = "set-your-local-model";
const ALERTS_IN_CONTEXT: usize = 15;

/// What AI Antivirus is and how it differs from a classic signature scanner (ClamAV) or a cloud antivirus. Fixed, and only
/// claims what the code and docs/GAPS.md support, so the model can answer "why use this" without inventing features.
const ABOUT: &str = "\
## About AI Antivirus (fixed facts, always true)\n\
- It is a host EDR for Linux, not only a file scanner: a sensor (eBPF, fanotify, /proc) sees programs starting, files written \
and network connections as they happen; an engine judges them with pacman trust (is the file from a package and unchanged), a \
hash table, YARA rules and behaviour rules (for example a download piped into a shell, a new autostart entry, a program run from /tmp).\n\
- A signature scanner such as ClamAV only matches file contents against known samples. It does not see behaviour, so it misses \
a new or self-made script that does something bad, and it is quiet about a clean-looking file that behaves badly. AI Antivirus \
looks at what runs, so it can flag what no signature knows yet; ClamAV is better at a huge library of known samples. They \
complement each other and can run together.\n\
- It runs entirely on this computer: no cloud upload of your files, no account, no telemetry. The optional local model only \
advises and explains; it never decides or acts, and every automatic response (freeze, kill, quarantine, block) is off in the \
default alert-only mode, needs approval above a set level, has a budget, an undo record and a circuit breaker.\n\
- It protects itself (signed rules, watchdog, own-file checks) and exceptions are narrow (exact program path, never a shell).\n\
- Honest limits: it is young (the two-week soak on a real desktop is still open), it does not scan a file before it runs yet, \
it has a much smaller sample library than commercial antivirus, and enforcement has only been tried on harmless test targets. \
Do not claim it catches everything, or that it replaces updates, backups or care.\n\n";

fn system_prompt(facts: &str) -> String {
    format!(
        "You are the help assistant of AI Antivirus, the antivirus and EDR on this Arch Linux desktop. It watches programs, \
files and connections, checks files with pacman trust, a hash table, YARA and behaviour rules, and raises alerts. \
Answer the user's question using ONLY the facts below, collected just now, and the fixed facts about AI Antivirus.\n\
Rules:\n\
- Be short and concrete: what happened, how serious it is, what to do. Plain text, no headings.\n\
- If the facts do not answer the question, say so and say what to check.\n\
- When asked why to use it, or how it compares with another antivirus, answer from the About section, including the honest limits.\n\
- You may name these commands for the user to run, and no others: ai-antivirus alerts, ai-antivirus ack <id>, \
ai-antivirus scan <path>, ai-antivirus actions, sudo ai-antivirus approve <id>, sudo ai-antivirus reject <id>, \
sudo ai-antivirus undo <id>, ai-antivirus rules.\n\
- Never tell the user to switch AI Antivirus off.\n\n{ABOUT}{facts}"
    )
}

/// The facts the model gets: the status figures and the newest alerts (unacknowledged ones marked).
pub fn facts(inp: &Inputs) -> String {
    let st = status::gather(inp);
    let mut out = format!("## Status\n{st}\n");
    out.push_str(
        "(services: sensord watches, engined detects, responderd acts as the mode allows; analyzer is an optional AI \
         helper, off by default, so `inactive` there is normal)\n",
    );
    if st["db_readable"] == false {
        out.push_str(
            "(the alert database is not readable by this user, so alert figures are unknown, not zero: the user needs \
             the ai-antivirus group (log in again after install) or sudo)\n",
        );
    }
    if let Some(st) = &inp.store {
        if let Ok(alerts) = st.recent_alerts(ALERTS_IN_CONTEXT) {
            out.push_str("\n## Newest alerts (oldest first)\n");
            if alerts.is_empty() {
                out.push_str("none\n");
            }
            for a in alerts {
                out.push_str(&format!(
                    "- #{} {} {} {}{}{}\n",
                    a.id,
                    a.severity.as_str(),
                    a.rule_id,
                    a.title,
                    if a.acknowledged {
                        ""
                    } else {
                        " [not acknowledged]"
                    },
                    a.detail
                        .get("exe")
                        .and_then(Value::as_str)
                        .map(|e| format!(" exe={e}"))
                        .unwrap_or_default()
                ));
            }
        }
    }
    out
}

/// The configured model, or the first preferred one the Ollama server has.
fn pick_model(endpoint: &str, configured: &str) -> Result<String, String> {
    if configured != PLACEHOLDER && !configured.is_empty() {
        return Ok(configured.to_string());
    }
    let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
    let v: Value = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .get(&url)
        .call()
        .map_err(|_| format!("no model server at {endpoint}"))?
        .into_json()
        .map_err(|e| e.to_string())?;
    let names: Vec<String> = v["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["name"].as_str().map(String::from))
        .collect();
    let has = |m: &str| {
        names
            .iter()
            .any(|n| n == m || n.strip_suffix(":latest") == Some(m))
    };
    PREFERRED
        .iter()
        .find(|m| has(m))
        .map(|m| (*m).to_string())
        .or_else(|| {
            names
                .iter()
                .find(|n| !n.contains("embed") && !n.contains("vl") && !n.contains("llava"))
                .cloned()
        })
        .ok_or_else(|| "Ollama has no models; run `ollama pull qwen3.5:4b`".into())
}

pub fn ask(cfg_path: &Path, question: &str, json_out: bool) -> Res {
    let question = question.trim();
    let emit = |v: Value| println!("{v}");
    if question.is_empty() {
        return Err("ask a question, e.g. ai-antivirus ask \"is anything wrong?\"".into());
    }
    let inp = Inputs::system(cfg_path);
    let ai = inp
        .config
        .as_ref()
        .map(|c| c.ai.clone())
        .unwrap_or_else(|_| Config::default().ai);
    let model = match pick_model(&ai.endpoint, &ai.model) {
        Ok(m) => m,
        Err(why) => {
            // no model: the status itself is the most useful answer
            let text = format!(
                "No local model ({why}). AI Antivirus right now:\n{}",
                status::human(
                    &status::gather(&inp),
                    ai_antivirus_common::event::now_ns() / 1_000_000_000
                )
            );
            if json_out {
                emit(json!({"type": "done", "text": text, "offline": true}));
            } else {
                println!("{text}");
            }
            return Ok(());
        }
    };
    if json_out {
        emit(json!({"type": "model", "name": model}));
    } else {
        eprintln!("({model})\n");
    }
    let body = json!({
        "model": model,
        "stream": false,
        "think": false,
        "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": system_prompt(&facts(&inp))},
            {"role": "user", "content": question},
        ],
    });
    let timeout = Duration::from_secs(u64::from(ai.timeout_secs).max(60));
    match ai_antivirus_analyzer::ollama::chat(&ai.endpoint, timeout, &body) {
        Ok(text) if json_out => {
            emit(json!({"type": "done", "text": ai_antivirus_analyzer::ollama::strip_think(&text)}))
        }
        Ok(text) => println!("{}", ai_antivirus_analyzer::ollama::strip_think(&text)),
        Err(e) if json_out => emit(json!({"type": "error", "error": e})),
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::model::Severity;
    use ai_antivirus_common::store::{NewAlert, Store};

    #[test]
    fn facts_hold_status_and_alerts() {
        let store = Store::open_in_memory().unwrap();
        store
            .insert_alert(&NewAlert {
                ts_ns: 5,
                rule_id: "AV-B-0013".into(),
                severity: Severity::Medium,
                confidence: 0.5,
                title: "Program executed from a world-writable temporary folder".into(),
                proc_key: None,
                event_id: None,
                detail: json!({"exe": "/tmp/x"}),
            })
            .unwrap();
        let inp = Inputs {
            config: Ok(Config::default()),
            services: vec![("engined".into(), "active".into())],
            log_tail: None,
            store: Some(store),
            now_ns: 10,
        };
        let f = facts(&inp);
        assert!(f.contains("\"engined\":\"active\""), "{f}");
        assert!(f.contains("#1 medium AV-B-0013"), "{f}");
        assert!(
            f.contains("[not acknowledged]") && f.contains("exe=/tmp/x"),
            "{f}"
        );
        assert!(system_prompt(&f).contains("Never tell the user to switch AI Antivirus off"));
        let p = system_prompt(&f);
        assert!(p.contains("ClamAV") && p.contains("Honest limits"), "{p}");
    }

    #[test]
    fn a_configured_model_is_used_without_asking_the_server() {
        assert_eq!(
            pick_model("http://127.0.0.1:1", "qwen2.5:7b").unwrap(),
            "qwen2.5:7b"
        );
        assert!(pick_model("http://127.0.0.1:1", PLACEHOLDER).is_err());
    }
}
