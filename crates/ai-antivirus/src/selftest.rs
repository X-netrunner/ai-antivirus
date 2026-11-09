//! Read-only detection verification; no quarantine or service mutation.
use std::{path::Path, time::Duration};
use ai_antivirus_common::config::Config;
use ai_antivirus_rules::scan::{Yara, EICAR};
use serde_json::json;

pub fn run(config: &Path, json_output: bool) -> Result<bool, String> {
    let cfg = Config::load(config).map_err(|e| e.to_string())?;
    let yara = Yara::load_dir(&cfg.engine.rules_dir.join("yara"),
        Duration::from_millis(u64::from(cfg.engine.yara_timeout_ms)))
        .map_err(|e| e.to_string())?;
    let detected = !yara.scan_bytes(EICAR).map_err(|e| e.to_string())?.is_empty();
    let clean = yara.scan_bytes(b"ordinary harmless text file\n").map_err(|e| e.to_string())?.is_empty();
    let ok = detected && clean;
    if json_output {
        println!("{}", json!({"ok":ok, "eicar_detected":detected, "clean_control_passed":clean,
            "scope":"configured YARA rules in memory; sensor and responder not exercised"}));
    } else {
        println!("Detection self-test: {}\n  EICAR detected: {detected}\n  Clean control passed: {clean}\n  Scope: configured YARA rules; sensor and responder not exercised.",
            if ok { "PASS" } else { "FAIL" });
    }
    Ok(!ok)
}
