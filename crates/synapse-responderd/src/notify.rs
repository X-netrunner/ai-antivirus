//! Desktop notifications (spec 8, level 1). The responder runs as root outside any desktop session, so it does not talk
//! to D-Bus itself: it appends one JSON line per notification to `<notify_dir>/notify.jsonl`, and `synapse-notify`, a
//! small program in the user's session, follows that file and shows each line. `notify_dir` is a setgid directory of
//! group `synapse-notify` (tmpfiles.d), so only members of that group can read what Synapse saw.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SPOOL: &str = "notify.jsonl";
const MAX_SPOOL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub ts_ns: u64,
    pub alert_id: Option<i64>,
    pub action_id: Option<i64>,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    /// What the responder did or would do, in one sentence.
    pub summary: String,
}

pub struct Notifier {
    dir: PathBuf,
}

impl Notifier {
    pub fn new(dir: impl Into<PathBuf>) -> Notifier {
        Notifier { dir: dir.into() }
    }

    pub fn spool(&self) -> PathBuf {
        self.dir.join(SPOOL)
    }

    /// Append one notification. Best effort: a missing directory or a full disk is reported, never fatal.
    pub fn send(&self, n: &Notification) -> Result<(), String> {
        let path = self.spool();
        if fs::metadata(&path).is_ok_and(|m| m.len() > MAX_SPOOL_BYTES) {
            let _ = fs::rename(&path, self.dir.join(format!("{SPOOL}.1")));
        }
        let mut line = serde_json::to_vec(n).map_err(|e| e.to_string())?;
        line.push(b'\n');
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .and_then(|mut f| f.write_all(&line))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_lines_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let n = Notifier::new(dir.path());
        let note = Notification {
            ts_ns: 1,
            alert_id: Some(2),
            action_id: None,
            rule_id: "SYN-B-0001".into(),
            severity: "high".into(),
            title: "t".into(),
            summary: "would freeze".into(),
        };
        n.send(&note).unwrap();
        n.send(&note).unwrap();
        let text = fs::read_to_string(n.spool()).unwrap();
        assert_eq!(text.lines().count(), 2);
        let back: Notification = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(back, note);

        fs::write(n.spool(), vec![b'x'; 1024 * 1024 + 1]).unwrap();
        n.send(&note).unwrap();
        assert_eq!(fs::read_to_string(n.spool()).unwrap().lines().count(), 1);
        assert!(dir.path().join("notify.jsonl.1").exists());
        assert!(Notifier::new(dir.path().join("missing"))
            .send(&note)
            .is_err());
    }
}
