//! `ai-antivirus status`: the daily check in one command. Read-only and fine without root: whatever cannot be read
//! (the database and event log are group `ai-antivirus`) is reported as null instead of failing. `--json` has stable
//! keys; the Halcyon Security center reads it.

use std::path::Path;
use std::process::Command;

use ai_antivirus_common::config::Config;
use ai_antivirus_common::event::{now_ns, Envelope, Event};
use ai_antivirus_common::eventlog;
use ai_antivirus_common::store::Store;
use serde_json::{json, Value};

use crate::detect::Res;

/// Unit `ai-antivirus-<name>.service` for each (the analyzer is optional and off by default).
pub const SERVICES: &[&str] = &["sensord", "engined", "responderd", "analyzer"];
const DAY_NS: u64 = 86_400 * 1_000_000_000;
/// How far back the event log is searched for the sensor's health record.
const LOG_LINES: usize = 400;

/// Everything `status` looks at, gathered by [`Inputs::system`] or built by hand in tests.
pub struct Inputs {
    pub config: Result<Config, String>,
    /// service name (without `ai-antivirus-`/`.service`) -> `systemctl is-active` answer, "unknown" without systemctl
    pub services: Vec<(String, String)>,
    /// The last lines of the event log, None when it cannot be read.
    pub log_tail: Option<Vec<Vec<u8>>>,
    /// The database, None when it cannot be opened.
    pub store: Option<Store>,
    pub now_ns: u64,
}

impl Inputs {
    pub fn system(cfg_path: &Path) -> Self {
        let config = Config::load(cfg_path).map_err(|e| e.to_string());
        let services = SERVICES
            .iter()
            .map(|s| {
                (
                    (*s).to_string(),
                    is_active(&format!("ai-antivirus-{s}.service")),
                )
            })
            .collect();
        let (log_tail, store) = match &config {
            Ok(c) => (
                eventlog::last_lines(&eventlog::log_path(&c.paths.log_dir), LOG_LINES).ok(),
                // the file must exist: opening would otherwise create an empty database
                c.db_path()
                    .exists()
                    .then(|| Store::open(&c.db_path()).ok())
                    .flatten(),
            ),
            Err(_) => (None, None),
        };
        Self {
            config,
            services,
            log_tail,
            store,
            now_ns: now_ns(),
        }
    }
}

fn is_active(unit: &str) -> String {
    match Command::new("systemctl").args(["is-active", unit]).output() {
        Ok(o) => {
            let word = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match word.as_str() {
                "active" | "inactive" | "failed" | "activating" | "deactivating" => word,
                _ => "inactive".into(),
            }
        }
        Err(_) => "unknown".into(),
    }
}

pub fn gather(inp: &Inputs) -> Value {
    let services: serde_json::Map<String, Value> = inp
        .services
        .iter()
        .map(|(k, v)| (k.clone(), Value::from(v.clone())))
        .collect();

    // newest first: the last event and the most recent sensor health record
    let events: Vec<Envelope> = inp
        .log_tail
        .iter()
        .flatten()
        .rev()
        .filter_map(|l| serde_json::from_slice(l).ok())
        .collect();
    let last_event_unix = events.first().map(|e| e.ts_ns / 1_000_000_000);
    let sensor_degraded = inp.log_tail.as_ref().and_then(|_| {
        events.iter().find_map(|e| match e.event {
            Event::SensorHealth { degraded, .. } => Some(degraded),
            _ => None,
        })
    });

    let (alerts_24h, unacked, pending, breaker) = match &inp.store {
        Some(st) => {
            let counts = st.alert_counts(inp.now_ns.saturating_sub(DAY_NS)).ok();
            let alerts = counts.as_ref().map(|(c, _)| {
                c.iter()
                    .map(|(s, n)| (s.as_str().to_string(), Value::from(*n)))
                    .collect::<serde_json::Map<_, _>>()
            });
            (
                alerts.map(Value::Object).unwrap_or(Value::Null),
                counts.map_or(Value::Null, |(_, u)| Value::from(u)),
                st.pending_actions()
                    .map_or(Value::Null, |p| Value::from(p.len())),
                st.state_get("breaker")
                    .map_or(Value::Null, |b| Value::from(b.is_some())),
            )
        }
        None => (Value::Null, Value::Null, Value::Null, Value::Null),
    };

    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": inp.config.as_ref().ok().map(|c| c.general.mode.as_str()),
        "config_ok": inp.config.is_ok(),
        "config_error": inp.config.as_ref().err(),
        "services": services,
        "sensor_degraded": sensor_degraded,
        "last_event_unix": last_event_unix,
        "alerts_24h": alerts_24h,
        "unacked": unacked,
        "pending_actions": pending,
        "breaker_open": breaker,
        "db_readable": inp.store.is_some(),
        "log_readable": inp.log_tail.is_some(),
    })
}

fn show(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn human(v: &Value, now_unix: u64) -> String {
    let mut out = String::new();
    let mut row = |k: &str, val: String| out.push_str(&format!("{k:<16} {val}\n"));
    row(
        "ai-antivirus",
        format!("{}  mode {}", show(&v["version"]), show(&v["mode"])),
    );
    if let Some(e) = v["config_error"].as_str() {
        row("config", format!("ERROR {e}"));
    }
    let services = v["services"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, s)| format!("{k} {}", show(s)))
                .collect::<Vec<_>>()
                .join("  ")
        })
        .unwrap_or_default();
    row("services", services);
    row(
        "sensor",
        match v["sensor_degraded"].as_bool() {
            Some(true) => "DEGRADED (some probes missing)".into(),
            Some(false) => "full".into(),
            None => "-".into(),
        },
    );
    row(
        "last event",
        v["last_event_unix"].as_u64().map_or("-".into(), |t| {
            format!("{}s ago", now_unix.saturating_sub(t))
        }),
    );
    let alerts = v["alerts_24h"]
        .as_object()
        .map(|m| {
            ["critical", "high", "medium", "low"]
                .iter()
                .map(|k| format!("{k} {}", show(&m.get(*k).cloned().unwrap_or(Value::Null))))
                .collect::<Vec<_>>()
                .join("  ")
        })
        .unwrap_or_else(|| "-".into());
    row("alerts (24h)", alerts);
    row("unacknowledged", show(&v["unacked"]));
    row("pending actions", show(&v["pending_actions"]));
    row(
        "breaker",
        match v["breaker_open"].as_bool() {
            Some(true) => "OPEN (automatic actions paused)".into(),
            Some(false) => "closed".into(),
            None => "-".into(),
        },
    );
    if v["db_readable"] == Value::Bool(false) || v["log_readable"] == Value::Bool(false) {
        row(
            "note",
            "some figures need the ai-antivirus group or root".into(),
        );
    }
    out
}

pub fn status(cfg: &Path, json: bool) -> Res {
    let v = gather(&Inputs::system(cfg));
    if json {
        println!("{v}");
    } else {
        print!("{}", human(&v, now_ns() / 1_000_000_000));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::event::{BootId, ProcKey};
    use ai_antivirus_common::model::Severity;
    use ai_antivirus_common::store::NewAlert;

    fn env(seq: u64, ts_s: u64, event: Event) -> Vec<u8> {
        serde_json::to_vec(&Envelope {
            seq,
            ts_ns: ts_s * 1_000_000_000,
            boot_id: BootId(1),
            event,
        })
        .unwrap()
    }

    const NOW_S: u64 = 1_800_000_000;

    #[test]
    fn everything_readable() {
        let store = Store::open_in_memory().unwrap();
        for sev in [Severity::High, Severity::High, Severity::Low] {
            store
                .insert_alert(&NewAlert {
                    ts_ns: (NOW_S - 60) * 1_000_000_000,
                    rule_id: "AV-B-0001".into(),
                    severity: sev,
                    confidence: 0.9,
                    title: "t".into(),
                    proc_key: None,
                    event_id: None,
                    detail: json!({}),
                })
                .unwrap();
        }
        store.ack_alerts(&[1]).unwrap();
        let inp = Inputs {
            config: Ok(Config::default()),
            services: vec![
                ("sensord".into(), "active".into()),
                ("analyzer".into(), "inactive".into()),
            ],
            log_tail: Some(vec![
                env(
                    1,
                    NOW_S - 30,
                    Event::SensorHealth {
                        dropped: 0,
                        degraded: true,
                    },
                ),
                env(
                    2,
                    NOW_S - 5,
                    Event::Exit {
                        proc: ProcKey {
                            pid: 3,
                            start_ns: 4,
                        },
                        code: 0,
                    },
                ),
                b"garbage".to_vec(),
            ]),
            store: Some(store),
            now_ns: NOW_S * 1_000_000_000,
        };
        let v = gather(&inp);
        assert_eq!(v["config_ok"], true);
        assert_eq!(v["mode"], "alert-only");
        assert_eq!(v["services"]["sensord"], "active");
        assert_eq!(v["sensor_degraded"], true);
        assert_eq!(v["last_event_unix"], NOW_S - 5);
        assert_eq!(v["alerts_24h"]["high"], 2);
        assert_eq!(v["alerts_24h"]["critical"], 0);
        assert_eq!(v["unacked"], 2);
        assert_eq!(v["pending_actions"], 0);
        assert_eq!(v["breaker_open"], false);
        assert_eq!(v["db_readable"], true);
        let text = human(&v, NOW_S);
        assert!(text.contains("DEGRADED"), "{text}");
        assert!(text.contains("high 2"), "{text}");
        assert!(text.contains("5s ago"), "{text}");
        assert!(!text.contains("ai-antivirus group"), "{text}");
    }

    #[test]
    fn nothing_readable_is_not_an_error() {
        let inp = Inputs {
            config: Err("no such file".into()),
            services: SERVICES
                .iter()
                .map(|s| ((*s).into(), "unknown".into()))
                .collect(),
            log_tail: None,
            store: None,
            now_ns: NOW_S * 1_000_000_000,
        };
        let v = gather(&inp);
        assert_eq!(v["config_ok"], false);
        assert_eq!(v["config_error"], "no such file");
        for k in [
            "mode",
            "sensor_degraded",
            "last_event_unix",
            "alerts_24h",
            "unacked",
            "pending_actions",
            "breaker_open",
        ] {
            assert!(v[k].is_null(), "{k} should be null");
        }
        assert_eq!(v["db_readable"], false);
        let text = human(&v, NOW_S);
        assert!(text.contains("ERROR no such file"));
        assert!(text.contains("ai-antivirus group"));
    }
}
