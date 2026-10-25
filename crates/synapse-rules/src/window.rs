//! Sliding windows for threshold rules: counts per group (a process or a process tree) over `window_secs`.
//!
//! Memory is bounded: at most `MAX_ENTRIES` events per group and `MAX_GROUPS` groups per rule (the group seen least recently
//! is dropped first). When a threshold is reached the group's window is cleared and the group stays quiet for one window
//! length, so a burst gives one alert, not one per further event.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::path::{Path, PathBuf};

use crate::rule::{Threshold, HIGH_ENTROPY_MILLI};

const MAX_ENTRIES: usize = 20_000;
const MAX_GROUPS: usize = 4096;
const NS_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Default)]
struct Group {
    /// (time, path) in arrival order; path is None for events that are not file writes
    order: VecDeque<(u64, Option<PathBuf>)>,
    /// path -> (time of its newest write, that write looked random)
    files: HashMap<PathBuf, (u64, bool)>,
    high: usize,
    quiet_until: u64,
    last_seen: u64,
}

/// What a window held when its threshold was reached.
#[derive(Debug, Clone, PartialEq)]
pub struct Fired {
    pub events: usize,
    pub distinct_files: usize,
    /// Share of distinct files whose newest write looked random.
    pub high_entropy_ratio: f64,
    /// A few of the files, for the alert's evidence.
    pub sample: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct Windows<K: Hash + Eq + Clone> {
    window_ns: u64,
    threshold: Threshold,
    groups: HashMap<K, Group>,
}

impl<K: Hash + Eq + Clone> Windows<K> {
    pub fn new(window_secs: u64, threshold: Threshold) -> Windows<K> {
        Windows {
            window_ns: window_secs.saturating_mul(NS_PER_SEC),
            threshold,
            groups: HashMap::new(),
        }
    }

    /// Record one matching event at `ts_ns` for `key` (`path`/`entropy` for file writes). Returns what the window held if
    /// this event reached the threshold.
    pub fn push(
        &mut self,
        key: &K,
        ts_ns: u64,
        path: Option<&Path>,
        entropy: Option<u16>,
    ) -> Option<Fired> {
        if !self.groups.contains_key(key) && self.groups.len() >= MAX_GROUPS {
            self.evict_oldest();
        }
        let window_ns = self.window_ns;
        let g = self.groups.entry(key.clone()).or_default();
        g.last_seen = ts_ns;
        if ts_ns < g.quiet_until {
            return None;
        }
        // drop what fell out of the window
        let horizon = ts_ns.saturating_sub(window_ns);
        while g.order.front().is_some_and(|(t, _)| *t < horizon) || g.order.len() >= MAX_ENTRIES {
            let Some((t, p)) = g.order.pop_front() else {
                break;
            };
            if let Some(p) = p {
                if g.files.get(&p).is_some_and(|(newest, _)| *newest == t) {
                    if let Some((_, high)) = g.files.remove(&p) {
                        g.high -= usize::from(high);
                    }
                }
            }
        }
        let high_now = entropy.is_some_and(|e| e >= HIGH_ENTROPY_MILLI);
        if let Some(p) = path {
            let p = p.to_path_buf();
            if let Some((_, was_high)) = g.files.insert(p.clone(), (ts_ns, high_now)) {
                g.high -= usize::from(was_high);
            }
            g.high += usize::from(high_now);
            g.order.push_back((ts_ns, Some(p)));
        } else {
            g.order.push_back((ts_ns, None));
        }

        let t = &self.threshold;
        let distinct = g.files.len();
        let ratio = if distinct == 0 {
            0.0
        } else {
            g.high as f64 / distinct as f64
        };
        let reached = t.events.is_none_or(|n| g.order.len() >= n as usize)
            && t.distinct_files_written
                .is_none_or(|n| distinct >= n as usize)
            && t.high_entropy_ratio.is_none_or(|r| ratio >= r);
        if !reached {
            return None;
        }
        let fired = Fired {
            events: g.order.len(),
            distinct_files: distinct,
            high_entropy_ratio: ratio,
            sample: g.files.keys().take(5).cloned().collect(),
        };
        g.order.clear();
        g.files.clear();
        g.high = 0;
        g.quiet_until = ts_ns.saturating_add(window_ns);
        Some(fired)
    }

    fn evict_oldest(&mut self) {
        if let Some(k) = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.groups.remove(&k);
        }
    }

    /// Forget groups with nothing in their window (called now and then by the engine).
    pub fn sweep(&mut self, now_ns: u64) {
        let window_ns = self.window_ns;
        self.groups
            .retain(|_, g| now_ns.saturating_sub(g.last_seen) < window_ns.saturating_mul(2));
    }

    pub fn groups(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = NS_PER_SEC;

    fn ransom(n: u32, ratio: Option<f64>) -> Windows<u32> {
        Windows::new(
            10,
            Threshold {
                events: None,
                distinct_files_written: Some(n),
                high_entropy_ratio: ratio,
            },
        )
    }

    #[test]
    fn many_random_files_in_the_window_fire_once() {
        let mut w = ransom(100, Some(0.7));
        let mut fired = Vec::new();
        for i in 0..250u64 {
            let p = PathBuf::from(format!("/home/u/doc{i}.locked"));
            if let Some(f) = w.push(&1, i * S / 50, Some(&p), Some(7990)) {
                fired.push(f);
            }
        }
        assert_eq!(fired.len(), 1, "one alert per burst");
        assert_eq!(fired[0].distinct_files, 100);
        assert!(fired[0].high_entropy_ratio > 0.99);
    }

    #[test]
    fn plain_text_bursts_and_rewrites_of_one_file_do_not() {
        let mut w = ransom(100, Some(0.7));
        for i in 0..500u64 {
            let p = PathBuf::from(format!("/home/u/node_modules/f{i}.js"));
            assert!(
                w.push(&1, i * S / 100, Some(&p), Some(4500)).is_none(),
                "text is not random"
            );
        }
        let mut w = ransom(100, None);
        let p = PathBuf::from("/home/u/db.sqlite");
        for i in 0..1000u64 {
            assert!(
                w.push(&2, i * S / 100, Some(&p), Some(7990)).is_none(),
                "one file is one file"
            );
        }
    }

    #[test]
    fn writes_spread_over_time_fall_out_of_the_window() {
        let mut w = ransom(50, None);
        for i in 0..200u64 {
            let p = PathBuf::from(format!("/home/u/f{i}"));
            // one write every second: never more than 10 in a 10 s window
            assert!(w.push(&1, i * S, Some(&p), None).is_none());
        }
    }

    #[test]
    fn groups_are_counted_apart_and_bounded() {
        let mut w: Windows<u32> = Windows::new(
            10,
            Threshold {
                events: Some(3),
                ..Threshold::default()
            },
        );
        assert!(w.push(&1, 0, None, None).is_none());
        assert!(w.push(&2, 1, None, None).is_none());
        assert!(w.push(&1, 2, None, None).is_none());
        assert!(w.push(&1, 3, None, None).is_some());
        for k in 0..(MAX_GROUPS as u32 + 10) {
            w.push(&(k + 10), 100 + u64::from(k), None, None);
        }
        assert!(w.groups() <= MAX_GROUPS);
        w.sweep(1_000 * S);
        assert_eq!(w.groups(), 0);
    }
}
