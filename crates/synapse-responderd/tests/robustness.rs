//! Mutation robustness for the control socket's request parser: whatever arrives, it either parses into one of the five
//! known requests or is refused, never anything else and never a panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use synapse_responderd::ipc::Request;

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

#[test]
fn mutated_requests_are_one_of_the_known_operations_or_refused() {
    let seeds = [
        r#"{"op":"approve","id":4}"#,
        r#"{"op":"reject","id":9}"#,
        r#"{"op":"undo","id":1}"#,
        r#"{"op":"breaker_reset"}"#,
        r#"{"op":"status"}"#,
    ];
    let tokens = [
        "\"",
        "{",
        "}",
        ",",
        ":",
        "99999999999999999999",
        "-1",
        "null",
        "\"cmd\":\"sh\"",
        "\"op\":\"exec\"",
        "\\u0000",
    ];
    let mut rng = Rng(0xABCD_EF01_2345_6789);
    let mut accepted = 0u32;
    for i in 0..30_000 {
        let mut b = seeds[i % seeds.len()].as_bytes().to_vec();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(b.len().max(1));
            match rng.below(5) {
                0 if !b.is_empty() => b[at] ^= 1 << rng.below(8),
                1 if !b.is_empty() => {
                    b.remove(at);
                }
                2 => b.insert(at.min(b.len()), (rng.next() & 0xff) as u8),
                3 => b.truncate(at),
                _ => {
                    let t = tokens[rng.below(tokens.len())];
                    b.splice(at.min(b.len())..at.min(b.len()), t.bytes());
                }
            }
        }
        let text = String::from_utf8_lossy(&b);
        if let Ok(req) = serde_json::from_str::<Request>(text.trim()) {
            accepted += 1;
            assert!(matches!(
                req,
                Request::Approve { .. }
                    | Request::Reject { .. }
                    | Request::Undo { .. }
                    | Request::BreakerReset
                    | Request::Status
            ));
        }
    }
    // the seeds themselves are valid, and a few mutations (a changed id, say) still are; the rest are refused
    for seed in seeds {
        assert!(serde_json::from_str::<Request>(seed).is_ok(), "{seed}");
    }
    assert!(accepted > 0);
}
