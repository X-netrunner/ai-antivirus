//! Shannon entropy of a byte sample, used to tell encrypted or compressed output from ordinary files.

/// How many bytes of a written file are sampled (`FileWrite::head_entropy`).
pub const SAMPLE_BYTES: usize = 4096;

/// Below this many bytes the figure says little; `None` is returned instead.
pub const MIN_SAMPLE_BYTES: usize = 256;

/// Entropy of `bytes` in milli-bits per byte: 0 (all one value) to 8000 (uniformly random).
pub fn shannon_milli(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < MIN_SAMPLE_BYTES {
        return None;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let n = bytes.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum();
    // 0.0..=8.0 by construction, so the cast cannot overflow
    Some((bits * 1000.0).round().clamp(0.0, 8000.0) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_text_and_random_data_are_far_apart() {
        assert_eq!(shannon_milli(&[b'a'; 4096]), Some(0));
        let text = "the quick brown fox jumps over the lazy dog ".repeat(100);
        let t = shannon_milli(text.as_bytes()).unwrap();
        assert!(t > 3000 && t < 5000, "text entropy {t}");
        // every byte value equally often: exactly 8 bits
        let all: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(shannon_milli(&all), Some(8000));
        assert_eq!(shannon_milli(b"short"), None);
    }
}
