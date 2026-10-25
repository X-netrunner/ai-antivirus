//! Synapse sensor daemon: an eBPF process and network sensor (M2) with a
//! `/proc` poller as fallback (M1), and a fanotify file-write sensor, all
//! feeding one JSONL event log.
//!
//! Threads: one per sensor (`ebpf` or `poller`, and `fanotify`) plus the
//! calling thread, which stamps events with sequence numbers and appends them
//! to the log.
//! Sensors talk to the writer through a bounded channel and never block
//! (see [`sink`]). tokio arrives with the engine in M3, when async IPC does.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod ebpf;
pub mod fan;
pub mod poller;
pub mod procinfo;
pub mod proctree;
pub mod selfwatch;
pub mod sink;
pub mod tracefs;
pub mod translate;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use synapse_common::config::Config;
use synapse_common::event::{BootId, Envelope, Event};
use synapse_common::eventlog::EventLogWriter;
use synapse_common::notify::Heartbeat;
use synapse_common::{Error, Result};
use tracing::{error, info, warn};

use crate::poller::Poller;
use crate::selfwatch::{SelfWatch, Verdict};
use crate::sink::{Sink, Stamped};

/// Capacity of the sensor-to-writer channel.
const CHANNEL_CAPACITY: usize = 8192;
/// How often a `SensorHealth` event is written.
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
/// How long the writer waits for events before checking the shutdown flag.
const WRITER_TICK: Duration = Duration::from_millis(500);
/// Granularity at which sleeping sensors notice shutdown.
const SLEEP_SLICE: Duration = Duration::from_millis(100);

pub(crate) fn spawn_named<F>(name: &str, body: F) -> Result<JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    let label = format!("<thread {name}>");
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .map_err(|e| Error::io(label.as_str(), e))
}

/// Sleep for `total`, waking early if `shutdown` is set.
fn sleep_unless_shutdown(total: Duration, shutdown: &AtomicBool) {
    let deadline = Instant::now() + total;
    while !shutdown.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        thread::sleep(remaining.min(SLEEP_SLICE));
    }
}

fn poll_loop(sink: &Sink, interval: Duration, shutdown: &AtomicBool) {
    let mut poller = Poller::new("/proc");
    match poller.baseline() {
        Ok(n) => info!(processes = n, "process poller baseline recorded"),
        Err(e) => {
            error!(error = %e, "cannot read /proc");
            sink.stats.poll_ok.store(false, Ordering::Relaxed);
        }
    }
    while !shutdown.load(Ordering::Relaxed) {
        sleep_unless_shutdown(interval, shutdown);
        match poller.scan() {
            Ok(events) => {
                if !sink.stats.poll_ok.swap(true, Ordering::Relaxed) {
                    info!("/proc polling recovered");
                }
                for event in events {
                    sink.send(event);
                }
            }
            Err(e) => {
                if sink.stats.poll_ok.swap(false, Ordering::Relaxed) {
                    error!(error = %e, "/proc scan failed; process events are not being collected");
                }
            }
        }
    }
}

/// Stamps events with sequence numbers and appends them to the log.
struct Writer {
    log: EventLogWriter,
    boot_id: BootId,
    seq: u64,
    failing: bool,
}

impl Writer {
    fn write(&mut self, ts_ns: u64, event: Event) {
        self.seq += 1;
        let envelope = Envelope {
            seq: self.seq,
            ts_ns,
            boot_id: self.boot_id,
            event,
        };
        match self.log.append(&envelope) {
            Ok(()) => {
                if self.failing {
                    info!("event log writes recovered");
                    self.failing = false;
                }
            }
            Err(e) => {
                // Log once per outage; the event is lost either way.
                if !self.failing {
                    error!(error = %e, "cannot write the event log; events are being lost");
                    self.failing = true;
                }
            }
        }
    }
}

/// Run the sensors until `shutdown` becomes true, then flush and return.
pub fn run(cfg: &Config, shutdown: &Arc<AtomicBool>) -> Result<()> {
    let boot_id = procinfo::read_boot_id()?;
    let log = EventLogWriter::open(
        &cfg.paths.log_dir,
        cfg.event_log_max_bytes(),
        cfg.sensors.event_log_keep,
    )?;
    let mut writer = Writer {
        log,
        boot_id,
        seq: 0,
        failing: false,
    };

    let (sink, rx) = Sink::channel(CHANNEL_CAPACITY);
    let mut threads: Vec<JoinHandle<()>> = Vec::new();

    // Process events come from eBPF when it loads, otherwise from polling.
    let ebpf_wanted = cfg.sensors.use_ebpf;
    let mut table = None;
    if ebpf_wanted {
        let shared = ebpf::new_table();
        match ebpf::start(cfg, &sink, &shared, shutdown) {
            Ok(handle) => {
                threads.push(handle);
                table = Some(shared);
            }
            Err(why) => {
                warn!(
                    reason = %why,
                    "eBPF sensor unavailable; falling back to /proc polling (degraded)"
                );
            }
        }
    }
    if table.is_none() {
        let sink = sink.clone();
        let shutdown = Arc::clone(shutdown);
        let interval = Duration::from_millis(u64::from(cfg.sensors.poll_interval_ms));
        threads.push(spawn_named("poller", move || {
            poll_loop(&sink, interval, &shutdown);
        })?);
    }

    let fan_wanted = cfg.sensors.use_fanotify;
    if fan_wanted {
        if let Some(fan) = fan::setup(&cfg.sensors.fanotify_marks) {
            let mut handler = fan::Handler::new(
                std::process::id(),
                cfg.sensors.fanotify_exclude.clone(),
                sink.clone(),
            );
            if let Some(table) = &table {
                handler = handler.with_table(Arc::clone(table));
            }
            let flag = Arc::clone(shutdown);
            sink.stats.fan_alive.store(true, Ordering::Relaxed);
            match spawn_named("fanotify", move || fan::run(&fan, handler, &flag)) {
                Ok(handle) => threads.push(handle),
                Err(e) => {
                    error!(error = %e, "cannot start the fanotify thread");
                    sink.stats.fan_alive.store(false, Ordering::Relaxed);
                }
            }
        }
    }

    info!(
        boot_id = %boot_id,
        log_dir = %cfg.paths.log_dir.display(),
        fanotify = sink.stats.fan_alive.load(Ordering::Relaxed),
        ebpf = sink.stats.ebpf_alive.load(Ordering::Relaxed),
        "sensor daemon running"
    );

    let write_health = |writer: &mut Writer| {
        writer.write(
            synapse_common::event::now_ns(),
            Event::SensorHealth {
                dropped: sink.stats.dropped.load(Ordering::Relaxed),
                degraded: sink.stats.degraded(fan_wanted, ebpf_wanted),
            },
        );
    };

    write_health(&mut writer);
    let mut next_health = Instant::now() + HEALTH_INTERVAL;
    let mut heartbeat = Heartbeat::from_env();
    heartbeat.ready("collecting events");
    let mut selfwatch = SelfWatch::new();
    let mut restart_reason: Option<&'static str> = None;
    loop {
        heartbeat.tick();
        match rx.recv_timeout(WRITER_TICK) {
            Ok((ts_ns, event)) => {
                selfwatch.saw(&event);
                writer.write(ts_ns, event);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        match selfwatch.poll(
            sink.stats.ebpf_alive.load(Ordering::Relaxed),
            Instant::now(),
        ) {
            Verdict::Quiet => {}
            Verdict::Report(event) => writer.write(synapse_common::event::now_ns(), event),
            Verdict::Restart(event) => {
                error!("the eBPF probes stopped reporting (the canary exec never arrived): restarting to attach them again");
                writer.write(synapse_common::event::now_ns(), event);
                restart_reason = Some("the eBPF probes stopped reporting");
                break;
            }
        }
        if Instant::now() >= next_health {
            write_health(&mut writer);
            next_health = Instant::now() + HEALTH_INTERVAL;
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }

    if restart_reason.is_some() {
        // the sensor threads only stop when told to; without this the join below would wait forever
        shutdown.store(true, Ordering::Relaxed);
    }
    heartbeat.stopping();
    // Drain what the sensors queued before they noticed the shutdown.
    let pending: Vec<Stamped> = rx.try_iter().collect();
    for (ts_ns, event) in pending {
        writer.write(ts_ns, event);
    }
    drop(rx);
    for handle in threads {
        if handle.join().is_err() {
            warn!("a sensor thread panicked");
        }
    }
    info!("sensor daemon stopped");
    match restart_reason {
        Some(why) => Err(Error::SelfProtection(why.to_owned())),
        None => Ok(()),
    }
}
