//! What the model must answer (spec 9, output schema) and the checks every answer goes through.
//!
//! Model output is untrusted data: it is parsed with `deny_unknown_fields`, every field is range- and pattern-checked,
//! indicators are parsed into their real types, regexes are compiled with a size limit, and proposed rules must pass the
//! same validation as hand-written ones. Nothing here is ever run, interpolated into a command or written to a rules
//! directory; a proposal only becomes a rule when a human approves it.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use synapse_rules::rule::Rule;

pub const MAX_SUMMARY: usize = 500;
pub const MAX_TECHNIQUES: usize = 10;
pub const MAX_INDICATORS: usize = 32;
pub const MAX_RULES: usize = 3;
const MAX_INDICATOR_LEN: usize = 512;
const REGEX_SIZE_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiVerdict {
    Benign,
    Suspicious,
    Malicious,
    Unknown,
}

impl AiVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            AiVerdict::Benign => "benign",
            AiVerdict::Suspicious => "suspicious",
            AiVerdict::Malicious => "malicious",
            AiVerdict::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    Sha256,
    Domain,
    Ip,
    Path,
    Regex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
}

/// The answer as the model gives it (before validation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiOutput {
    pub verdict: AiVerdict,
    pub confidence: f64,
    #[serde(default)]
    pub attack_techniques: Vec<String>,
    pub summary: String,
    #[serde(default)]
    pub indicators: Vec<Indicator>,
    #[serde(default)]
    pub proposed_rules: Vec<Rule>,
    pub injection_suspected: bool,
}

/// `T1059` or `T1059.004`.
fn valid_technique(t: &str) -> bool {
    let b = t.as_bytes();
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => b[0] == b'T' && digits(&b[1..]),
        9 => b[0] == b'T' && digits(&b[1..5]) && b[5] == b'.' && digits(&b[6..]),
        _ => false,
    }
}

/// A host name: 2+ labels of letters, digits and hyphens (not at the ends), 253 characters at most.
fn valid_domain(d: &str) -> bool {
    let d = d.strip_suffix('.').unwrap_or(d);
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        && d.parse::<IpAddr>().is_err()
}

fn valid_indicator(i: &Indicator) -> bool {
    let v = i.value.as_str();
    if v.is_empty() || v.len() > MAX_INDICATOR_LEN || v.chars().any(char::is_control) {
        return false;
    }
    match i.kind {
        IndicatorKind::Sha256 => v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit()),
        IndicatorKind::Domain => valid_domain(v),
        IndicatorKind::Ip => v.parse::<IpAddr>().is_ok(),
        IndicatorKind::Path => v.starts_with('/') && !v.split('/').any(|c| c == ".."),
        IndicatorKind::Regex => regex::RegexBuilder::new(v)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .is_ok(),
    }
}

/// Remove control characters (terminal escapes, NUL) from text that will be shown to a person.
pub fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect()
}

/// A validated answer. Parts that failed their check are dropped and listed in `problems`, so a mostly good answer
/// keeps its verdict while a bad indicator or rule does not get through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Validated {
    pub verdict: AiVerdict,
    pub confidence: f64,
    pub attack_techniques: Vec<String>,
    pub summary: String,
    pub indicators: Vec<Indicator>,
    pub proposed_rules: Vec<Rule>,
    pub injection_suspected: bool,
    pub problems: Vec<String>,
}

/// Parse and check the model's raw text. An answer that is not JSON in the schema at all is an error.
pub fn validate(raw: &str) -> Result<Validated, String> {
    if raw.len() > 256 * 1024 {
        return Err("answer larger than 256 KiB".into());
    }
    let o: AiOutput = serde_json::from_str(raw.trim())
        .map_err(|e| format!("answer does not fit the schema: {e}"))?;
    validate_output(o)
}

pub fn validate_output(o: AiOutput) -> Result<Validated, String> {
    if !(0.0..=1.0).contains(&o.confidence) || o.confidence.is_nan() {
        return Err(format!("confidence {} is outside 0..1", o.confidence));
    }
    let mut problems = Vec::new();
    if o.summary.chars().count() > MAX_SUMMARY {
        problems.push(format!(
            "summary longer than {MAX_SUMMARY} characters (cut)"
        ));
    }
    let summary = clean_text(&o.summary, MAX_SUMMARY);

    let mut techniques = Vec::new();
    for t in o.attack_techniques.into_iter().take(MAX_TECHNIQUES * 2) {
        if !valid_technique(&t) {
            problems.push(format!("dropped ATT&CK id {:?}", clean_text(&t, 40)));
        } else if techniques.len() < MAX_TECHNIQUES && !techniques.contains(&t) {
            techniques.push(t);
        }
    }

    let mut indicators = Vec::new();
    for i in o.indicators.into_iter().take(MAX_INDICATORS * 2) {
        if valid_indicator(&i) && indicators.len() < MAX_INDICATORS {
            indicators.push(i);
        } else {
            problems.push(format!(
                "dropped {:?} indicator {:?}",
                i.kind,
                clean_text(&i.value, 60)
            ));
        }
    }

    let mut rules = Vec::new();
    for r in o.proposed_rules.into_iter().take(MAX_RULES * 2) {
        let p = r.problems();
        if p.is_empty() && rules.len() < MAX_RULES {
            rules.push(r);
        } else if !p.is_empty() {
            problems.push(format!(
                "dropped proposed rule: {}",
                clean_text(&p.join("; "), 300)
            ));
        }
    }

    Ok(Validated {
        verdict: o.verdict,
        confidence: o.confidence,
        attack_techniques: techniques,
        summary,
        indicators,
        proposed_rules: rules,
        injection_suspected: o.injection_suspected,
        problems,
    })
}

/// The JSON schema handed to Ollama's structured output (`format`), so the model is steered to the shape that
/// `validate` accepts. The rule objects are left open here; `validate` is what enforces them.
pub fn json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "confidence", "attack_techniques", "summary", "indicators", "proposed_rules", "injection_suspected"],
        "properties": {
            "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious", "unknown"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "attack_techniques": {"type": "array", "maxItems": MAX_TECHNIQUES, "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}},
            "summary": {"type": "string", "maxLength": MAX_SUMMARY},
            "indicators": {"type": "array", "maxItems": MAX_INDICATORS, "items": {
                "type": "object", "additionalProperties": false, "required": ["kind", "value"],
                "properties": {"kind": {"type": "string", "enum": ["sha256", "domain", "ip", "path", "regex"]}, "value": {"type": "string"}}
            }},
            "proposed_rules": {"type": "array", "maxItems": MAX_RULES, "items": {"type": "object"}},
            "injection_suspected": {"type": "boolean"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "verdict": "suspicious", "confidence": 0.7, "attack_techniques": ["T1059.004", "T1105", "T99", "drop table"],
        "summary": "A script fetches a file and runs it.\u001b[2J",
        "indicators": [
            {"kind": "domain", "value": "updates.example.invalid"},
            {"kind": "ip", "value": "198.51.100.4"},
            {"kind": "ip", "value": "not-an-ip"},
            {"kind": "sha256", "value": "ab"},
            {"kind": "regex", "value": "(a+)+$"},
            {"kind": "path", "value": "/tmp/x/../../etc"}
        ],
        "proposed_rules": [
            {"id": "LOCAL-ai-1", "title": "pipe into sh from cron", "severity": "medium", "confidence": 0.6,
             "match": {"event": "exec", "exe_in": ["/usr/bin/sh"], "stdin_from_exe_in": ["/usr/bin/curl"]}, "action": "notify"},
            {"id": "evil", "title": "t", "severity": "low", "confidence": 2, "match": {"event": "exec"}, "action": "kill"}
        ],
        "injection_suspected": false
    }"#;

    #[test]
    fn a_good_answer_keeps_what_checks_out_and_drops_the_rest() {
        let v = validate(GOOD).unwrap();
        assert_eq!(v.verdict, AiVerdict::Suspicious);
        assert_eq!(v.attack_techniques, ["T1059.004", "T1105"]);
        assert!(!v.summary.contains('\u{1b}'), "escape removed");
        let kinds: Vec<_> = v.indicators.iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [
                IndicatorKind::Domain,
                IndicatorKind::Ip,
                IndicatorKind::Regex
            ]
        );
        assert_eq!(v.proposed_rules.len(), 1);
        assert_eq!(v.proposed_rules[0].id, "LOCAL-ai-1");
        assert!(v.problems.len() >= 5, "{:?}", v.problems);
    }

    #[test]
    fn answers_outside_the_schema_are_refused() {
        let extra = GOOD.replacen(
            "\"injection_suspected\": false",
            "\"injection_suspected\": false, \"run\": \"x\"",
            1,
        );
        assert!(validate(&extra).is_err());
        assert!(validate("Sure! Here is my analysis: it is benign.").is_err());
        assert!(validate(&GOOD.replace("\"suspicious\"", "\"definitely-fine\"")).is_err());
        assert!(validate(&GOOD.replace("\"confidence\": 0.7", "\"confidence\": 7")).is_err());
        let bad_rule = GOOD.replace(
            "\"action\": \"notify\"",
            "\"action\": \"notify\", \"shell\": \"x\"",
        );
        assert!(
            validate(&bad_rule).is_err(),
            "unknown keys inside a rule fail the whole answer"
        );
    }

    #[test]
    fn domains_and_techniques() {
        assert!(valid_domain("a.example.org"));
        assert!(!valid_domain("localhost"));
        assert!(!valid_domain("-bad.example"));
        assert!(!valid_domain("10.0.0.1"));
        assert!(!valid_domain("a..b"));
        assert!(valid_technique("T1059"));
        assert!(!valid_technique("T1059.4"));
        assert!(!valid_technique("t1059"));
    }

    #[test]
    fn the_schema_is_an_object_schema() {
        let s = json_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["required"].as_array().unwrap().len(), 7);
    }
}
