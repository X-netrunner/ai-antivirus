//! Mutation robustness (spec 14, "fuzz the rule parser"): seeded random edits of valid inputs must never panic or hang,
//! and anything the parser accepts must still satisfy the rule invariants. Real `cargo-fuzz` targets are not set up; this
//! runs on every `cargo test` instead, with a fixed seed so a failure reproduces.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use ai_antivirus_rules::mtree::parse_mtree;
use ai_antivirus_rules::rule::RuleSet;

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
    "[[rule]]",
    "'",
    "\"",
    "\\u0000",
    "99999999999999999999",
    "-1",
    "= {",
    "}",
    "[",
    "]",
    "\n",
    "\\",
    "event = 'exec'",
    "threshold = {",
    "~/",
    "../",
    "0.5",
    "true",
];

fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        if data.is_empty() {
            data.push(b'a');
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

const ITERATIONS: usize = 20_000;

#[test]
fn mutated_rule_files_never_panic_and_accepted_ones_are_valid() {
    let seed_text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/behavior/00-shipped.toml"
    ))
    .unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut accepted, mut rejected) = (0u32, 0u32);
    for _ in 0..ITERATIONS {
        let mut bytes = seed_text.clone().into_bytes();
        mutate(&mut rng, &mut bytes);
        let text = String::from_utf8_lossy(&bytes);
        match RuleSet::parse_str(&text, "fuzz") {
            Ok(rules) => {
                accepted += 1;
                for r in &rules {
                    assert!(
                        r.problems().is_empty(),
                        "accepted a rule with problems: {r:?}"
                    );
                    assert!((0.0..=1.0).contains(&r.confidence));
                }
            }
            Err(_) => rejected += 1,
        }
    }
    // the mutations are meaningful: most break the file, some do not
    assert!(rejected > 1000, "rejected {rejected}, accepted {accepted}");
}

#[test]
fn mutated_mtree_text_never_panics() {
    let seed = "#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr/bin/bash time=1700000123.5 mode=755 size=1112880 sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n./usr/share/doc/a\\040file time=1700000000.0 size=3 sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n./usr/lib time=1.0 type=dir\n";
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..ITERATIONS {
        let mut bytes = seed.as_bytes().to_vec();
        mutate(&mut rng, &mut bytes);
        if let Ok(entries) = parse_mtree(Cursor::new(&bytes)) {
            // every path it hands out is absolute
            assert!(entries.iter().all(|e| e.path.is_absolute()));
        }
    }
}
