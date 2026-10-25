//! Self-protection (spec 10): the engine notices when AI Antivirus itself is being interfered with, and says so as an alert.
//!
//! - **Own binaries.** Every few minutes the files in `engine.self_check_files` are compared with pacman's records. A
//!   package file that differs is `AV-T-0001`. Files no package owns (a development build) are not checked.
//! - **Debugger.** A non-zero `TracerPid` in `/proc/self/status` means something is tracing the engine: `AV-T-0002`.
//! - **Silent sensor.** The sensor writes a health line every 10 s. No new line for a minute means the sensor is stopped,
//!   hung or blinded: `AV-T-0003`, once per outage.
//! - **Rule bundle.** With `engine.require_signed_rules`, rules that are not covered by a valid signature are refused at
//!   start and on every reload (the running rules stay); a failed reload is `AV-T-0004`.
//!
//! These alerts name no process (the culprit is not known), carry the action `notify`, and are stored like any other.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ai_antivirus_common::config::Config;
use ai_antivirus_common::event::TamperKind;
use ai_antivirus_common::model::Severity;
use ai_antivirus_common::store::Store;
use ai_antivirus_rules::rule::Action;
use ai_antivirus_rules::signing;
use serde_json::json;

use crate::engine::{Alert, Engine};
use crate::files::{Finding, Outcome};

pub const SELF_CHECK_EVERY: Duration = Duration::from_secs(300);
pub const PTRACE_CHECK_EVERY: Duration = Duration::from_secs(5);
/// The sensor writes a health line every 10 s; this long without any line is "silent".
pub const SENSOR_SILENT_AFTER: Duration = Duration::from_secs(60);

fn alert(
    ts_ns: u64,
    id: &str,
    severity: Severity,
    confidence: f64,
    title: &str,
    detail: serde_json::Value,
) -> Alert {
    Alert {
        ts_ns,
        rule_id: id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        action: Action::Notify,
        layer: "self-protection",
        proc_key: None,
        detail,
    }
}

/// Verify the rule bundle when signatures are required. `Ok` when they are not.
pub fn verify_rules(cfg: &Config, rules_dir: &Path) -> Result<(), String> {
    if !cfg.engine.require_signed_rules {
        return Ok(());
    }
    signing::verify(rules_dir, &cfg.engine.rules_pubkey)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn bundle_invalid(ts_ns: u64, problems: &str) -> Alert {
    alert(
        ts_ns,
        "AV-T-0004",
        Severity::Critical,
        0.95,
        "The rules are not covered by a valid signature; the running rules stay",
        json!({"problems": problems}),
    )
}

/// An alert for a `Tamper` event the sensor wrote.
pub fn from_tamper(ts_ns: u64, what: &TamperKind) -> Alert {
    match what {
        TamperKind::ProbeDetached => alert(
            ts_ns,
            "AV-T-0010",
            Severity::High,
            0.9,
            "The eBPF probes stopped reporting; the sensor restarted to attach them again",
            json!({}),
        ),
        TamperKind::PtraceAttach { from } => alert(
            ts_ns,
            "AV-T-0011",
            Severity::High,
            0.9,
            "A debugger is attached to the sensor",
            json!({"tracer_pid": from.pid}),
        ),
        TamperKind::BinaryModified { path } | TamperKind::ConfigModified { path } => alert(
            ts_ns,
            "AV-T-0012",
            Severity::Critical,
            0.9,
            "The sensor reports that one of AI Antivirus's files was modified",
            json!({"path": path.display().to_string()}),
        ),
        TamperKind::RuleBundleInvalid => bundle_invalid(ts_ns, "reported by the sensor"),
        TamperKind::SensorSilent => alert(
            ts_ns,
            "AV-T-0003",
            Severity::High,
            0.8,
            "The sensor has gone silent",
            json!({}),
        ),
        TamperKind::SignalReceived { from, signal } => alert(
            ts_ns,
            "AV-T-0013",
            Severity::High,
            0.7,
            "A signal was sent to an AI Antivirus process",
            json!({"from_pid": from.pid, "signal": signal}),
        ),
    }
}

/// The tracer's pid from the text of `/proc/<pid>/status` (0 = none).
pub fn tracer_pid(status: &str) -> u32 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

pub fn check_debugger(ts_ns: u64) -> Option<Alert> {
    let t = tracer_pid(&std::fs::read_to_string("/proc/self/status").ok()?);
    (t != 0).then(|| {
        let by = std::fs::read_to_string(format!("/proc/{t}/comm")).unwrap_or_default();
        alert(
            ts_ns,
            "AV-T-0002",
            Severity::High,
            0.9,
            "A debugger is attached to the engine",
            json!({"tracer_pid": t, "tracer": by.trim()}),
        )
    })
}

/// Watches for a stalled event log.
#[derive(Debug)]
pub struct SensorWatch {
    last_line: Instant,
    reported: bool,
}

impl SensorWatch {
    pub fn new() -> SensorWatch {
        SensorWatch {
            last_line: Instant::now(),
            reported: false,
        }
    }

    /// A line arrived from the sensor.
    pub fn saw_line(&mut self) {
        self.last_line = Instant::now();
        self.reported = false;
    }

    /// The alert, once, when the log has been quiet too long.
    pub fn check(&mut self, ts_ns: u64) -> Option<Alert> {
        if self.reported || self.last_line.elapsed() < SENSOR_SILENT_AFTER {
            return None;
        }
        self.reported = true;
        Some(alert(
            ts_ns,
            "AV-T-0003",
            Severity::High,
            0.8,
            "The sensor has gone silent (no events, not even its health line)",
            json!({"silent_secs": self.last_line.elapsed().as_secs()}),
        ))
    }
}

impl Default for SensorWatch {
    fn default() -> Self {
        SensorWatch::new()
    }
}

impl Engine {
    /// Compare AI Antivirus's own files with pacman's records.
    pub fn self_check(
        &mut self,
        store: &mut Store,
        files: &[PathBuf],
        pacman_active: bool,
        ts_ns: u64,
    ) -> Vec<Alert> {
        let mut out = Vec::new();
        for f in files {
            if let Outcome::Findings(list) = self.files.check(store, f, false, pacman_active, ts_ns)
            {
                for finding in list {
                    if let Finding::Modified {
                        package,
                        expected,
                        actual,
                    } = finding
                    {
                        let mut a = alert(
                            ts_ns,
                            "AV-T-0001",
                            Severity::Critical,
                            0.95,
                            "An AI Antivirus file differs from what its package installed",
                            json!({"path": f.display().to_string(), "package": package, "expected_sha256": expected.to_string(), "sha256": actual.to_string()}),
                        );
                        // offered to the responder: put the package's copy back (needs `ai-antivirus approve`)
                        a.action = Action::Restore;
                        out.push(a);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracer_pid_is_read_from_status() {
        assert_eq!(tracer_pid("Name:\tx\nTracerPid:\t0\nUid:\t1"), 0);
        assert_eq!(tracer_pid("Name:\tx\nTracerPid:\t4321\n"), 4321);
        assert_eq!(tracer_pid("garbage"), 0);
        // this test process is not being traced
        assert!(check_debugger(1).is_none());
    }

    #[test]
    fn a_package_file_that_differs_is_a_tamper_alert_and_an_unowned_file_is_not() {
        use crate::files::FileCheck;
        use ai_antivirus_common::event::Sha256;
        use ai_antivirus_common::store::TrustEntry;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let owned = dir.path().join("ai-antivirus-engined");
        let unowned = dir.path().join("dev-build");
        std::fs::write(&owned, b"changed behind pacman's back").unwrap();
        std::fs::write(&unowned, b"my own build").unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let entry = TrustEntry {
            path: owned.as_os_str().as_bytes().to_vec(),
            sha256: Sha256([9; 32]),
            package: "ai-antivirus".into(),
            size: 1,
            mtime_ns: 0,
            verified_ns: 0,
        };
        store
            .trust_replace_package("ai-antivirus", &[entry])
            .unwrap();
        let mut engine = Engine::new(Vec::new(), FileCheck::new(None, 1 << 20, 100), false);
        let a = engine.self_check(&mut store, &[owned.clone(), unowned], false, 7);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].rule_id, "AV-T-0001");
        assert_eq!(a[0].detail["package"], "ai-antivirus");
        assert_eq!(a[0].action, Action::Restore);
        // during a pacman transaction a changed package file is expected
        let mut engine = Engine::new(Vec::new(), FileCheck::new(None, 1 << 20, 100), false);
        assert!(engine.self_check(&mut store, &[owned], true, 8).is_empty());
    }

    #[test]
    fn the_sensor_is_reported_silent_once_and_again_after_it_comes_back() {
        let mut w = SensorWatch::new();
        assert!(w.check(1).is_none(), "grace period at start");
        w.last_line = Instant::now() - SENSOR_SILENT_AFTER - Duration::from_secs(1);
        let a = w.check(2).unwrap();
        assert_eq!(a.rule_id, "AV-T-0003");
        assert!(w.check(3).is_none(), "once per outage");
        w.saw_line();
        assert!(w.check(4).is_none());
        w.last_line = Instant::now() - SENSOR_SILENT_AFTER - Duration::from_secs(1);
        assert!(w.check(5).is_some(), "a new outage reports again");
    }
}
