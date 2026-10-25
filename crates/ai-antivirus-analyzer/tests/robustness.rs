//! Mutation robustness for everything that reads untrusted text in the analyzer: the model's answer and file contents.
//! Fixed seeds; runs on every `cargo test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ai_antivirus_analyzer::bundle::{extract_names, extract_strings, is_credential_path};
use ai_antivirus_analyzer::output::{
    validate, MAX_INDICATORS, MAX_RULES, MAX_SUMMARY, MAX_TECHNIQUES,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64).max(1)) as usize
    }
}

const TOKENS: &[&str] = &[
    "\"",
    "{",
    "}",
    "[",
    "]",
    ",",
    ":",
    "null",
    "1e999",
    "-0",
    "\\u0000",
    "\\ud800",
    "\"verdict\"",
    "\"proposed_rules\":[{}]",
    "true",
    "99999999999999999999",
];

fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        if data.is_empty() {
            data.push(b'{');
        }
        let at = rng.below(data.len());
        match rng.below(6) {
            0 => data[at] ^= 1 << rng.below(8),
            1 => {
                let end = (at + 1 + rng.below(16)).min(data.len());
                data.drain(at..end);
            }
            2 => {
                let end = (at + 1 + rng.below(32)).min(data.len());
                let chunk: Vec<u8> = data[at..end].to_vec();
                data.splice(at..at, chunk);
            }
            3 => {
                for _ in 0..1 + rng.below(8) {
                    data.insert(at.min(data.len()), (rng.next() & 0xff) as u8);
                }
            }
            4 => data.truncate(at),
            _ => {
                let t = TOKENS[rng.below(TOKENS.len())];
                data.splice(at..at, t.bytes());
            }
        }
    }
}

const GOOD: &str = r#"{"verdict":"suspicious","confidence":0.8,"attack_techniques":["T1059.004","T1105"],"summary":"A script fetched a file and ran it.","indicators":[{"kind":"domain","value":"files.example.invalid"},{"kind":"ip","value":"198.51.100.4"},{"kind":"regex","value":"a+b"},{"kind":"path","value":"/tmp/x"}],"proposed_rules":[{"id":"LOCAL-ai-x","title":"t","severity":"medium","confidence":0.6,"match":{"event":"exec","exe_in":["/usr/bin/sh"]},"action":"notify"}],"injection_suspected":false}"#;

#[test]
fn mutated_model_answers_never_panic_and_accepted_ones_obey_the_limits() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let (mut ok, mut err) = (0u32, 0u32);
    for _ in 0..20_000 {
        let mut bytes = GOOD.as_bytes().to_vec();
        mutate(&mut rng, &mut bytes);
        let text = String::from_utf8_lossy(&bytes);
        match validate(&text) {
            Ok(v) => {
                ok += 1;
                assert!((0.0..=1.0).contains(&v.confidence));
                assert!(v.summary.chars().count() <= MAX_SUMMARY);
                assert!(v.summary.chars().all(|c| !c.is_control() || c == '\n'));
                assert!(v.attack_techniques.len() <= MAX_TECHNIQUES);
                assert!(v.indicators.len() <= MAX_INDICATORS);
                assert!(v.proposed_rules.len() <= MAX_RULES);
                assert!(v.proposed_rules.iter().all(|r| r.problems().is_empty()));
            }
            Err(_) => err += 1,
        }
    }
    assert!(ok > 100 && err > 1000, "ok {ok}, err {err}");
}

#[test]
fn random_bytes_never_break_the_string_and_name_extractors() {
    let mut rng = Rng(0x0F0F_F0F0_1357_2468);
    for round in 0..2_000 {
        let len = rng.below(4096);
        let data: Vec<u8> = (0..len)
            .map(|_| {
                if round % 2 == 0 {
                    (rng.next() & 0xff) as u8
                } else {
                    b" ./:-abcXYZ019\0\n"[rng.below(16)]
                }
            })
            .collect();
        let s = extract_strings(&data);
        assert!(s.len() <= 48 && s.iter().all(|x| x.len() >= 6 && x.len() <= 160));
        let (d, i) = extract_names(&String::from_utf8_lossy(&data));
        assert!(d.len() <= 24 && i.len() <= 24);
        let path = String::from_utf8_lossy(&data[..data.len().min(80)]).into_owned();
        let _ = is_credential_path(&path);
    }
}
