//! The sensor watching itself (spec 10): is the eBPF path still delivering, and is anything tracing the sensor?
//!
//! **Canary.** Every minute the sensor runs `/usr/bin/true` and waits for the exec to come back through the event
//! stream. If three seconds pass without it, the probes are no longer reporting (detached, unloaded, or the consumer
//! died): the sensor logs a `Tamper::ProbeDetached` event and asks to exit so systemd restarts it, which loads and
//! attaches everything again ("reload detached probes"). The canary only runs while the eBPF consumer is the process
//! source; with `/proc` polling it would only measure the poll interval.
//!
//! **Debugger.** A non-zero `TracerPid` in the sensor's own `/proc/self/status` is reported once as `PtraceAttach`.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use synapse_common::event::{Event, ProcKey, TamperKind};

pub const CANARY_EVERY: Duration = Duration::from_secs(60);
pub const CANARY_WAIT: Duration = Duration::from_secs(3);
pub const TRACE_EVERY: Duration = Duration::from_secs(5);
const CANARY_PROGRAM: &str = "/usr/bin/true";

#[derive(Debug)]
pub enum Verdict {
    /// Nothing to report.
    Quiet,
    /// Write this event.
    Report(Event),
    /// Write this event, then exit so the service manager restarts the sensor.
    Restart(Event),
}

#[derive(Debug)]
pub struct SelfWatch {
    canary: Option<(Child, Instant)>,
    next_canary: Instant,
    next_trace: Instant,
    traced_reported: bool,
    program: String,
}

impl SelfWatch {
    pub fn new() -> SelfWatch {
        SelfWatch::with_program(CANARY_PROGRAM)
    }

    pub fn with_program(program: &str) -> SelfWatch {
        let now = Instant::now();
        SelfWatch {
            canary: None,
            // not right at start: the consumer needs a moment to be running
            next_canary: now + Duration::from_secs(20),
            next_trace: now + TRACE_EVERY,
            traced_reported: false,
            program: program.to_owned(),
        }
    }

    /// Call from the writer loop for every event it writes.
    pub fn saw(&mut self, event: &Event) {
        if let (Some((child, _)), Event::Exec { proc, .. }) = (&self.canary, event) {
            if proc.pid == child.id() {
                self.finish_canary();
            }
        }
    }

    fn finish_canary(&mut self) {
        if let Some((mut child, _)) = self.canary.take() {
            let _ = child.wait();
        }
    }

    /// Call regularly. `ebpf_active`: the eBPF consumer is the process source.
    pub fn poll(&mut self, ebpf_active: bool, now: Instant) -> Verdict {
        if let Some((child, started)) = self.canary.as_mut() {
            // reap it as soon as it exits, even if its event never shows up
            let _ = child.try_wait();
            if now.duration_since(*started) >= CANARY_WAIT {
                self.finish_canary();
                return Verdict::Restart(Event::Tamper {
                    what: TamperKind::ProbeDetached,
                });
            }
        } else if ebpf_active && now >= self.next_canary {
            self.next_canary = now + CANARY_EVERY;
            if Path::new(&self.program).is_file() {
                if let Ok(child) = Command::new(&self.program)
                    .arg0("synapse-canary")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    self.canary = Some((child, now));
                }
            }
        }
        if now >= self.next_trace {
            self.next_trace = now + TRACE_EVERY;
            match tracer_of_self() {
                Some(t) if !self.traced_reported => {
                    self.traced_reported = true;
                    return Verdict::Report(Event::Tamper {
                        what: TamperKind::PtraceAttach {
                            from: ProcKey {
                                pid: t,
                                start_ns: 0,
                            },
                        },
                    });
                }
                None => self.traced_reported = false,
                Some(_) => {}
            }
        }
        Verdict::Quiet
    }
}

impl Default for SelfWatch {
    fn default() -> Self {
        SelfWatch::new()
    }
}

/// The pid tracing this process, if any.
pub fn tracer_of_self() -> Option<u32> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let t: u32 = text
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))?
        .trim()
        .parse()
        .ok()?;
    (t != 0).then_some(t)
}

use std::os::unix::process::CommandExt;

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_of(pid: u32) -> Event {
        Event::Exec {
            proc: ProcKey { pid, start_ns: 1 },
            parent: ProcKey {
                pid: 1,
                start_ns: 1,
            },
            uid: 0,
            exe: "/usr/bin/true".into(),
            argv: Vec::new(),
            cwd: "/".into(),
            cgroup: String::new(),
            stdio: Vec::new(),
            lineage: Vec::new(),
        }
    }

    #[test]
    fn a_canary_that_comes_back_is_fine_and_one_that_does_not_asks_for_a_restart() {
        let mut w = SelfWatch::with_program("/usr/bin/true");
        let t0 = Instant::now();
        w.next_canary = t0;
        assert!(matches!(w.poll(true, t0), Verdict::Quiet));
        let pid = w.canary.as_ref().expect("canary started").0.id();
        // the exec shows up in the stream: all good, nothing to restart later
        w.saw(&exec_of(pid));
        assert!(w.canary.is_none());
        assert!(matches!(
            w.poll(true, t0 + Duration::from_secs(10)),
            Verdict::Quiet
        ));

        // next round: the event never comes
        w.next_canary = t0;
        assert!(matches!(w.poll(true, t0), Verdict::Quiet));
        assert!(w.canary.is_some());
        assert!(
            matches!(w.poll(true, t0 + Duration::from_secs(1)), Verdict::Quiet),
            "still waiting"
        );
        let v = w.poll(true, t0 + CANARY_WAIT + Duration::from_millis(1));
        let Verdict::Restart(Event::Tamper {
            what: TamperKind::ProbeDetached,
        }) = v
        else {
            panic!("expected a restart request, got {v:?}")
        };
        assert!(w.canary.is_none());
    }

    #[test]
    fn no_canary_while_polling_or_for_an_unrelated_exec() {
        let mut w = SelfWatch::with_program("/usr/bin/true");
        let t0 = Instant::now();
        w.next_canary = t0;
        assert!(matches!(w.poll(false, t0), Verdict::Quiet));
        assert!(
            w.canary.is_none(),
            "the eBPF consumer is not the process source"
        );
        w.poll(true, t0);
        let pid = w.canary.as_ref().unwrap().0.id();
        w.saw(&exec_of(pid + 100000));
        assert!(w.canary.is_some(), "another process's exec does not count");
        w.finish_canary();
        // a missing program is skipped quietly
        let mut m = SelfWatch::with_program("/nonexistent/true");
        m.next_canary = t0;
        assert!(matches!(m.poll(true, t0), Verdict::Quiet));
        assert!(m.canary.is_none());
    }

    #[test]
    fn this_test_process_is_not_traced() {
        assert_eq!(tracer_of_self(), None);
    }
}
