//! The analyzer loop. It reads bundles from the spool, asks the model, and leaves the raw answer in the output folder.
//! It never opens the database, never touches rules and runs no commands; the engine validates the answer again and
//! decides what to store. If Ollama is down, slow or answers badly the rest of Synapse is not affected (spec 9).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use synapse_common::config::Config;
use tracing::{info, warn};

use crate::bundle::Bundle;
use crate::ollama;

const POLL: Duration = Duration::from_millis(500);
const BACKOFF: Duration = Duration::from_secs(30);
/// After this many failed tries an alert gets an error answer and is not tried again.
const MAX_TRIES: u32 = 3;
const MAX_BUNDLE_FILE: u64 = 128 * 1024;

/// What the analyzer leaves for the engine, one file per alert (`<alert id>.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub alert_id: i64,
    pub ts_ns: u64,
    pub model: String,
    /// The model's text, exactly as received (not yet trusted).
    pub raw: Option<String>,
    pub error: Option<String>,
}

fn alert_id_of(path: &Path) -> Option<i64> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".json")?;
    (stem.len() <= 18 && !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()))
        .then(|| stem.parse().ok())?
}

/// Write `answer` as `<out>/<id>.json` through a temporary file and a rename.
pub fn write_answer(out: &Path, answer: &Answer) -> Result<(), String> {
    let final_path = out.join(format!("{}.json", answer.alert_id));
    let tmp = out.join(format!(".{}.tmp", answer.alert_id));
    let text = serde_json::to_string(answer).map_err(|e| e.to_string())?;
    // 0660: the engine reads and removes it through the shared group (see the engine's spool for why the mode is explicit)
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o660)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.set_permissions(fs::Permissions::from_mode(0o660))
        .map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, &final_path).map_err(|e| e.to_string())
}

/// Bundle files waiting, oldest alert first, that have no answer yet.
pub fn pending(spool: &Path, out: &Path) -> Vec<(i64, PathBuf)> {
    let Ok(rd) = fs::read_dir(spool) else {
        return Vec::new();
    };
    let mut v: Vec<(i64, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| alert_id_of(&e.path()).map(|id| (id, e.path())))
        .filter(|(id, _)| !out.join(format!("{id}.json")).exists())
        .collect();
    v.sort_by_key(|(id, _)| *id);
    v
}

/// Sliding one-hour budget.
struct Budget {
    max: usize,
    times: VecDeque<Instant>,
}

impl Budget {
    fn take(&mut self) -> bool {
        let now = Instant::now();
        while self
            .times
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(3600))
        {
            self.times.pop_front();
        }
        if self.times.len() >= self.max {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

pub fn run(cfg: &Config, shutdown: &AtomicBool) -> Result<(), String> {
    if !cfg.ai.enabled {
        return Err("ai.enabled is false in the configuration; nothing to do".into());
    }
    let (spool, out) = (cfg.ai_spool_dir(), cfg.ai_out_dir());
    for d in [&spool, &out] {
        if !d.is_dir() {
            return Err(format!(
                "{} does not exist (systemd-tmpfiles creates it)",
                d.display()
            ));
        }
    }
    let timeout = Duration::from_secs(u64::from(cfg.ai.timeout_secs));
    let mut budget = Budget {
        max: cfg.ai.max_per_hour as usize,
        times: VecDeque::new(),
    };
    let mut tries: HashMap<i64, u32> = HashMap::new();
    info!(model = %cfg.ai.model, endpoint = %cfg.ai.endpoint, spool = %spool.display(), "analyzer running (advice only)");

    while !shutdown.load(Ordering::Relaxed) {
        let todo = pending(&spool, &out);
        let Some((id, path)) = todo.into_iter().next() else {
            thread::sleep(POLL);
            continue;
        };
        if !budget.take() {
            warn!(id, "hourly budget used up; waiting");
            thread::sleep(Duration::from_secs(60));
            continue;
        }
        let bundle = match read_bundle(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(id, error = %e, "bad bundle");
                let _ = write_answer(
                    &out,
                    &Answer {
                        alert_id: id,
                        ts_ns: synapse_common::event::now_ns(),
                        model: cfg.ai.model.clone(),
                        raw: None,
                        error: Some(e),
                    },
                );
                continue;
            }
        };
        match ollama::chat(
            &cfg.ai.endpoint,
            timeout,
            &ollama::request(&cfg.ai.model, &bundle, &ollama::new_marker()),
        ) {
            Ok(raw) => {
                tries.remove(&id);
                info!(id, bytes = raw.len(), "answer received");
                let a = Answer {
                    alert_id: id,
                    ts_ns: synapse_common::event::now_ns(),
                    model: cfg.ai.model.clone(),
                    raw: Some(raw),
                    error: None,
                };
                if let Err(e) = write_answer(&out, &a) {
                    warn!(id, error = %e, "cannot write the answer");
                }
            }
            Err(e) => {
                let n = tries.entry(id).or_insert(0);
                *n += 1;
                warn!(id, try_ = *n, error = %e, "the model did not answer; the rest of Synapse is not affected");
                if *n >= MAX_TRIES {
                    tries.remove(&id);
                    let _ = write_answer(
                        &out,
                        &Answer {
                            alert_id: id,
                            ts_ns: synapse_common::event::now_ns(),
                            model: cfg.ai.model.clone(),
                            raw: None,
                            error: Some(e),
                        },
                    );
                } else {
                    sleep_unless(BACKOFF, shutdown);
                }
            }
        }
    }
    info!("analyzer stopped");
    Ok(())
}

fn sleep_unless(total: Duration, shutdown: &AtomicBool) {
    let end = Instant::now() + total;
    while !shutdown.load(Ordering::Relaxed) && Instant::now() < end {
        thread::sleep(Duration::from_millis(200));
    }
}

fn read_bundle(path: &Path) -> Result<Bundle, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_BUNDLE_FILE {
        return Err("bundle is not a regular file or is too large".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("bundle is not valid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_must_be_alert_ids() {
        assert_eq!(alert_id_of(Path::new("/x/42.json")), Some(42));
        assert_eq!(alert_id_of(Path::new("/x/4a.json")), None);
        assert_eq!(alert_id_of(Path::new("/x/.42.tmp")), None);
        assert_eq!(alert_id_of(Path::new("/x/../42.json.bak")), None);
        assert_eq!(alert_id_of(Path::new("/x/99999999999999999999.json")), None);
    }

    #[test]
    fn answered_alerts_are_not_asked_again_and_order_is_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let (spool, out) = (dir.path().join("spool"), dir.path().join("out"));
        fs::create_dir_all(&spool).unwrap();
        fs::create_dir_all(&out).unwrap();
        for id in [10, 2, 7] {
            fs::write(spool.join(format!("{id}.json")), "{}").unwrap();
        }
        fs::write(spool.join("note.txt"), "x").unwrap();
        write_answer(
            &out,
            &Answer {
                alert_id: 2,
                ts_ns: 1,
                model: "m".into(),
                raw: Some("{}".into()),
                error: None,
            },
        )
        .unwrap();
        let ids: Vec<i64> = pending(&spool, &out).into_iter().map(|(i, _)| i).collect();
        assert_eq!(ids, [7, 10]);
    }

    #[test]
    fn answers_are_group_readable_whatever_the_umask() {
        let dir = tempfile::tempdir().unwrap();
        write_answer(
            dir.path(),
            &Answer {
                alert_id: 5,
                ts_ns: 1,
                model: "m".into(),
                raw: Some("{}".into()),
                error: None,
            },
        )
        .unwrap();
        let mode = fs::metadata(dir.path().join("5.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660);
    }

    #[test]
    fn the_hourly_budget_holds() {
        let mut b = Budget {
            max: 2,
            times: VecDeque::new(),
        };
        assert!(b.take() && b.take() && !b.take());
    }

    #[test]
    fn oversized_or_linked_bundles_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("1.json");
        fs::write(&big, vec![b'x'; (MAX_BUNDLE_FILE + 1) as usize]).unwrap();
        assert!(read_bundle(&big).is_err());
        let real = dir.path().join("real");
        fs::write(&real, "{}").unwrap();
        let link = dir.path().join("2.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_bundle(&link).is_err(), "symlink");
    }
}
