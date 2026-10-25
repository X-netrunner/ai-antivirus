//! Hand-off from the sensor threads to the single log-writer thread.
//!
//! The channel is bounded. A sensor never blocks: when the channel is full the
//! event is dropped and counted, and the count is reported in `SensorHealth`
//! events (spec hard rule 6, "explicit drop-and-count backpressure").

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use synapse_common::event::{now_ns, Event};

/// An event with the wall-clock time at which the sensor saw it.
pub type Stamped = (u64, Event);

/// Counters and flags shared by all sensor threads.
#[derive(Debug)]
pub struct Stats {
    /// Events lost: channel full, or the kernel reported a queue overflow.
    pub dropped: AtomicU64,
    /// File events merged into an identical one seen moments earlier.
    pub coalesced: AtomicU64,
    /// The fanotify thread is running.
    pub fan_alive: AtomicBool,
    /// The last `/proc` scan succeeded.
    pub poll_ok: AtomicBool,
    /// The eBPF consumer is running (fork, exec and exit are attached).
    pub ebpf_alive: AtomicBool,
    /// Some optional eBPF program (argv, exit status, connect) is missing.
    pub ebpf_partial: AtomicBool,
}

impl Stats {
    pub fn new() -> Stats {
        Stats {
            dropped: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
            fan_alive: AtomicBool::new(false),
            poll_ok: AtomicBool::new(true),
            ebpf_alive: AtomicBool::new(false),
            ebpf_partial: AtomicBool::new(false),
        }
    }

    /// True when a sensor that was asked for is not delivering events, or
    /// eBPF is running without some of its programs.
    pub fn degraded(&self, fanotify_wanted: bool, ebpf_wanted: bool) -> bool {
        (fanotify_wanted && !self.fan_alive.load(Ordering::Relaxed))
            || !self.poll_ok.load(Ordering::Relaxed)
            || (ebpf_wanted
                && (!self.ebpf_alive.load(Ordering::Relaxed)
                    || self.ebpf_partial.load(Ordering::Relaxed)))
    }
}

impl Default for Stats {
    fn default() -> Self {
        Stats::new()
    }
}

/// Cloneable sending side given to each sensor.
#[derive(Debug, Clone)]
pub struct Sink {
    tx: SyncSender<Stamped>,
    pub stats: Arc<Stats>,
}

impl Sink {
    /// Create a sink and the receiver for the writer thread.
    pub fn channel(capacity: usize) -> (Sink, Receiver<Stamped>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        (
            Sink {
                tx,
                stats: Arc::new(Stats::new()),
            },
            rx,
        )
    }

    /// Queue an event without ever blocking.
    pub fn send(&self, event: Event) {
        match self.tx.try_send((now_ns(), event)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer has stopped; we are shutting down.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> Event {
        Event::SensorHealth {
            dropped: 0,
            degraded: false,
        }
    }

    #[test]
    fn full_channel_drops_and_counts_without_blocking() {
        let (sink, rx) = Sink::channel(2);
        for _ in 0..5 {
            sink.send(health());
        }
        assert_eq!(sink.stats.dropped.load(Ordering::Relaxed), 3);
        assert_eq!(rx.try_iter().count(), 2);
    }

    #[test]
    fn sending_after_the_writer_is_gone_is_harmless() {
        let (sink, rx) = Sink::channel(2);
        drop(rx);
        sink.send(health());
        assert_eq!(sink.stats.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn degraded_reflects_wanted_sensors() {
        let stats = Stats::new();
        assert!(stats.degraded(true, false), "fanotify wanted but not alive");
        assert!(!stats.degraded(false, false));
        stats.fan_alive.store(true, Ordering::Relaxed);
        assert!(!stats.degraded(true, false));
        stats.poll_ok.store(false, Ordering::Relaxed);
        assert!(stats.degraded(false, false));
    }

    #[test]
    fn degraded_reflects_ebpf_state() {
        let stats = Stats::new();
        assert!(stats.degraded(false, true), "eBPF wanted but not running");
        stats.ebpf_alive.store(true, Ordering::Relaxed);
        assert!(!stats.degraded(false, true));
        stats.ebpf_partial.store(true, Ordering::Relaxed);
        assert!(stats.degraded(false, true), "an optional program is missing");
        assert!(!stats.degraded(false, false), "eBPF not wanted: not degraded");
    }
}
