//! SQLite store (rusqlite, WAL mode, mode 0600).
//!
//! `Store` owns one connection and is `Send` but not `Sync`: give it to one
//! task, or use `spawn_blocking`. The schema lives in `schema_v1.sql`.
//!
//! M0 provides the generic operations: open and migrate, batched event
//! inserts, recent-event reads, alert inserts, statistics and retention
//! cleanup. M3 adds alert reads, the hash table and the trust cache. Verdicts,
//! actions, proposals and baselines arrive with the milestones that use them.

use std::fs::{OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection};

use crate::error::{Error, Result};
use crate::event::{Envelope, ProcKey, Sha256};
use crate::model::{ActionStatus, HashClass, ProposalStatus, Severity};

pub const SCHEMA_VERSION: i64 = 3;
const SCHEMA_V1: &str = include_str!("schema_v1.sql");
const SCHEMA_V2: &str = include_str!("schema_v2.sql");
const SCHEMA_V3: &str = include_str!("schema_v3.sql");

/// Fixed table list used for statistics. Never built from outside input.
const TABLES: [&str; 10] = [
    "state",
    "ai_notes",
    "events",
    "alerts",
    "verdicts",
    "actions",
    "proposals",
    "hashes",
    "baselines",
    "trust_cache",
];

const CLEANUP_BATCH: i64 = 1000;
const MAX_RECENT: usize = 10_000;
const NS_PER_DAY: u64 = 86_400 * 1_000_000_000;

/// An alert to insert. `detail` is free-form JSON for the rule's evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    pub ts_ns: u64,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub proc_key: Option<ProcKey>,
    pub event_id: Option<i64>,
    pub detail: serde_json::Value,
}

/// Row counts and sizes, for `ai-antivirus db-stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStats {
    pub schema_version: i64,
    /// Database size in bytes including free pages.
    pub file_bytes: u64,
    /// Database size in bytes excluding free pages; this is what the size cap compares.
    pub used_bytes: u64,
    pub events: u64,
    pub alerts: u64,
    pub verdicts: u64,
    pub actions: u64,
    pub proposals: u64,
    pub hashes: u64,
    pub baselines: u64,
    pub trust_cache: u64,
}

/// What a cleanup run removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupReport {
    pub deleted_by_age: u64,
    pub deleted_by_size: u64,
    pub used_bytes_after: u64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the database at `path`.
    ///
    /// The file is created with mode 0600, an existing file is tightened to
    /// 0600, and a symlink at `path` is refused. SQLite creates the `-wal` and
    /// `-shm` files with the database file's mode.
    pub fn open(path: &Path) -> Result<Store> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| Error::io(path, e))?;
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|e| Error::io(path, e))?;
        drop(file);

        let conn = Connection::open(path)?;
        Store::init(conn, true)
    }

    /// An in-memory store, for tests and dry runs.
    pub fn open_in_memory() -> Result<Store> {
        Store::init(Connection::open_in_memory()?, false)
    }

    fn init(conn: Connection, file_backed: bool) -> Result<Store> {
        conn.busy_timeout(Duration::from_secs(5))?;

        // auto_vacuum only takes effect before the first table exists, and it
        // lets cleanup actually shrink the file.
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
        }

        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if file_backed && !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::NotWal(mode));
        }
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )?;

        let mut store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let found = self.schema_version()?;
        if found > SCHEMA_VERSION {
            return Err(Error::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found < SCHEMA_VERSION {
            let tx = self.conn.transaction()?;
            if found < 1 {
                tx.execute_batch(SCHEMA_V1)?;
            }
            if found < 2 {
                tx.execute_batch(SCHEMA_V2)?;
            }
            if found < 3 {
                tx.execute_batch(SCHEMA_V3)?;
            }
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Insert a batch of events in one transaction. Either all rows are
    /// stored or none are. Returns the number inserted.
    pub fn insert_events(&mut self, envelopes: &[Envelope]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (boot_id, seq, ts_ns, kind, pid, proc_start_ns, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for env in envelopes {
                let key = env.event.proc_key();
                let start = key
                    .map(|k| to_i64(k.start_ns, "proc start_ns"))
                    .transpose()?;
                stmt.execute(params![
                    env.boot_id.to_string(),
                    to_i64(env.seq, "seq")?,
                    to_i64(env.ts_ns, "ts_ns")?,
                    env.event.kind(),
                    key.map(|k| i64::from(k.pid)),
                    start,
                    serde_json::to_string(env)?,
                ])?;
            }
        }
        tx.commit()?;
        Ok(envelopes.len())
    }

    /// Insert one event and return its row id.
    pub fn insert_event(&mut self, envelope: &Envelope) -> Result<i64> {
        self.insert_events(std::slice::from_ref(envelope))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The most recent `limit` events (capped at 10 000), oldest first.
    pub fn recent_events(&self, limit: usize) -> Result<Vec<Envelope>> {
        let limit = to_i64(u64::try_from(limit.min(MAX_RECENT)).unwrap_or(0), "limit")?;
        let mut stmt = self
            .conn
            .prepare_cached("SELECT body FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str::<Envelope>(&row?)?);
        }
        out.reverse();
        Ok(out)
    }

    /// Insert an alert and return its row id.
    pub fn insert_alert(&self, alert: &NewAlert) -> Result<i64> {
        if !(0.0..=1.0).contains(&alert.confidence) {
            return Err(Error::OutOfRange("confidence must be within 0.0..=1.0"));
        }
        let start = alert
            .proc_key
            .map(|k| to_i64(k.start_ns, "proc start_ns"))
            .transpose()?;
        self.conn.execute(
            "INSERT INTO alerts
                 (ts_ns, rule_id, severity, confidence, title, pid, proc_start_ns, event_id, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                to_i64(alert.ts_ns, "ts_ns")?,
                alert.rule_id,
                alert.severity.as_str(),
                alert.confidence,
                alert.title,
                alert.proc_key.map(|k| i64::from(k.pid)),
                start,
                alert.event_id,
                alert.detail.to_string(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Row counts per table plus size figures.
    pub fn stats(&self) -> Result<StoreStats> {
        let page_size = self.pragma_i64("page_size")?;
        let page_count = self.pragma_i64("page_count")?;
        let free = self.pragma_i64("freelist_count")?;
        Ok(StoreStats {
            schema_version: self.schema_version()?,
            file_bytes: pages_to_bytes(page_count, page_size),
            used_bytes: pages_to_bytes(page_count - free, page_size),
            events: self.count("events")?,
            alerts: self.count("alerts")?,
            verdicts: self.count("verdicts")?,
            actions: self.count("actions")?,
            proposals: self.count("proposals")?,
            hashes: self.count("hashes")?,
            baselines: self.count("baselines")?,
            trust_cache: self.count("trust_cache")?,
        })
    }

    /// Enforce retention on `events`: drop rows older than `retention_days`,
    /// then drop the oldest rows until the database fits in `max_db_bytes`.
    /// Alerts, verdicts and actions are kept; their event link becomes NULL.
    pub fn cleanup(
        &self,
        retention_days: u32,
        max_db_bytes: u64,
        now_ns: u64,
    ) -> Result<CleanupReport> {
        let window = u64::from(retention_days).saturating_mul(NS_PER_DAY);
        let cutoff = to_i64(now_ns.saturating_sub(window), "cutoff")?;
        let by_age = self
            .conn
            .execute("DELETE FROM events WHERE ts_ns < ?1", [cutoff])?;

        let mut by_size: u64 = 0;
        while self.used_bytes()? > max_db_bytes {
            let n = self.conn.execute(
                "DELETE FROM events WHERE id IN
                     (SELECT id FROM events ORDER BY id LIMIT ?1)",
                [CLEANUP_BATCH],
            )?;
            if n == 0 {
                break; // nothing left to prune; the floor is the schema itself
            }
            by_size += count_u64(n);
        }

        if by_age > 0 || by_size > 0 {
            self.run_pragma("PRAGMA incremental_vacuum")?;
            self.run_pragma("PRAGMA wal_checkpoint(TRUNCATE)")?;
        }

        Ok(CleanupReport {
            deleted_by_age: count_u64(by_age),
            deleted_by_size: by_size,
            used_bytes_after: self.used_bytes()?,
        })
    }

    fn used_bytes(&self) -> Result<u64> {
        let page_size = self.pragma_i64("page_size")?;
        let page_count = self.pragma_i64("page_count")?;
        let free = self.pragma_i64("freelist_count")?;
        Ok(pages_to_bytes(page_count - free, page_size))
    }

    /// Read a numeric pragma. `name` is always a string literal in this file.
    fn pragma_i64(&self, name: &str) -> Result<i64> {
        Ok(self
            .conn
            .query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?)
    }

    /// Run a pragma and drain any rows it returns.
    fn run_pragma(&self, sql: &str) -> Result<()> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;
        while rows.next()?.is_some() {}
        Ok(())
    }

    /// `table` must come from [`TABLES`].
    fn count(&self, table: &'static str) -> Result<u64> {
        debug_assert!(TABLES.contains(&table));
        let n: i64 = self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

/// An alert as stored (for `ai-antivirus alerts`).
#[derive(Debug, Clone, PartialEq)]
pub struct AlertRow {
    pub id: i64,
    pub ts_ns: u64,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub proc_key: Option<ProcKey>,
    pub detail: serde_json::Value,
    pub acknowledged: bool,
}

const ALERT_COLS: &str =
    "id, ts_ns, rule_id, severity, confidence, title, pid, proc_start_ns, detail, acknowledged";

fn alert_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
    let pid: Option<i64> = r.get(6)?;
    let start: Option<i64> = r.get(7)?;
    let sev: String = r.get(3)?;
    let detail: String = r.get(8)?;
    let ack: i64 = r.get(9)?;
    let proc_key = match (pid, start) {
        (Some(p), Some(s)) => Some(ProcKey {
            pid: u32::try_from(p).unwrap_or(0),
            start_ns: u64::try_from(s).unwrap_or(0),
        }),
        _ => None,
    };
    Ok(AlertRow {
        id: r.get(0)?,
        ts_ns: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        rule_id: r.get(2)?,
        // the CHECK constraint keeps this valid; fall back rather than fail a read
        severity: sev.parse().unwrap_or(Severity::Medium),
        confidence: r.get(4)?,
        title: r.get(5)?,
        proc_key,
        detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
        acknowledged: ack != 0,
    })
}

/// What pacman says one file should be (spec 7, L0). `verified_ns` is 0 until the file's hash was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    pub path: Vec<u8>,
    pub sha256: Sha256,
    pub package: String,
    pub size: u64,
    /// The mtree time, whole seconds, stored as nanoseconds.
    pub mtime_ns: u64,
    pub verified_ns: u64,
}

impl Store {
    /// The newest `limit` alerts, oldest first.
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<AlertRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ALERT_COLS} FROM alerts ORDER BY id DESC LIMIT ?1"
        ))?;
        let mut out = stmt
            .query_map([limit], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    pub fn get_alert(&self, id: i64) -> Result<Option<AlertRow>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {ALERT_COLS} FROM alerts WHERE id = ?1"))?;
        let mut rows = stmt.query_map([id], alert_row)?;
        Ok(rows.next().transpose()?)
    }

    /// Mark these alerts as seen. Returns how many changed (unknown or already acknowledged ids do not count).
    pub fn ack_alerts(&self, ids: &[i64]) -> Result<usize> {
        let mut n = 0;
        let mut stmt = self
            .conn
            .prepare("UPDATE alerts SET acknowledged = 1 WHERE id = ?1 AND acknowledged = 0")?;
        for id in ids {
            n += stmt.execute([id])?;
        }
        Ok(n)
    }

    /// Mark every alert as seen. Returns how many changed.
    pub fn ack_all_alerts(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0",
            [],
        )?)
    }

    /// The newest `limit` alerts not acknowledged yet, oldest first.
    pub fn unacked_alerts(&self, limit: usize) -> Result<Vec<AlertRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ALERT_COLS} FROM alerts WHERE acknowledged = 0 ORDER BY id DESC LIMIT ?1"
        ))?;
        let mut out = stmt
            .query_map([limit], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    /// Alerts per severity since `since_ns` (every severity present, zero when none), plus the unacknowledged total.
    pub fn alert_counts(&self, since_ns: u64) -> Result<(Vec<(Severity, u64)>, u64)> {
        let mut stmt = self
            .conn
            .prepare("SELECT severity, COUNT(*) FROM alerts WHERE ts_ns >= ?1 GROUP BY severity")?;
        let found: Vec<(String, i64)> = stmt
            .query_map([to_i64(since_ns, "since_ns")?], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let counts = Severity::ALL
            .iter()
            .map(|s| {
                let n = found
                    .iter()
                    .find(|f| f.0 == s.as_str())
                    .map_or(0, |f| u64::try_from(f.1).unwrap_or(0));
                (*s, n)
            })
            .collect();
        let unacked: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0",
            [],
            |r| r.get(0),
        )?;
        Ok((counts, u64::try_from(unacked).unwrap_or(0)))
    }

    /// Id of the newest alert (0 when there is none).
    pub fn max_alert_id(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?)
    }

    /// Look a SHA-256 up in the hash table (L1).
    pub fn hash_class(&self, sha: &Sha256) -> Result<Option<(HashClass, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT class, label FROM hashes WHERE sha256 = ?1")?;
        let mut rows = stmt.query([&sha.as_bytes()[..]])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let class: String = row.get(0)?;
        let label: Option<String> = row.get(1)?;
        Ok(class.parse().ok().map(|c| (c, label)))
    }

    /// Add or replace a hash-table entry.
    pub fn put_hash(
        &self,
        sha: &Sha256,
        class: HashClass,
        label: Option<&str>,
        source: &str,
        now_ns: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO hashes (sha256, class, label, source, added_ts_ns) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(sha256) DO UPDATE SET class = excluded.class, label = excluded.label, source = excluded.source",
            params![&sha.as_bytes()[..], class.as_str(), label, source, to_i64(now_ns, "added_ts_ns")?],
        )?;
        Ok(())
    }

    /// The trust-cache entry for `path`, if pacman owns it.
    pub fn trust_get(&self, path: &[u8]) -> Result<Option<TrustEntry>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT sha256, package, size, mtime_ns, verified_ns FROM trust_cache WHERE path = ?1",
        )?;
        let mut rows = stmt.query([path])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let sha: Vec<u8> = row.get(0)?;
        let mut digest = [0u8; 32];
        if sha.len() != 32 {
            return Ok(None);
        }
        digest.copy_from_slice(&sha);
        Ok(Some(TrustEntry {
            path: path.to_vec(),
            sha256: Sha256(digest),
            package: row.get(1)?,
            size: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
            mtime_ns: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
            verified_ns: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        }))
    }

    /// Replace one package's entries in a single transaction (a package upgrade removes files too).
    pub fn trust_replace_package(
        &mut self,
        package: &str,
        entries: &[TrustEntry],
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM trust_cache WHERE package = ?1", [package])?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO trust_cache (path, sha256, package, size, mtime_ns, verified_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for e in entries {
                stmt.execute(params![
                    e.path,
                    &e.sha256.as_bytes()[..],
                    e.package,
                    to_i64(e.size, "size")?,
                    to_i64(e.mtime_ns, "mtime_ns")?,
                    to_i64(e.verified_ns, "verified_ns")?,
                ])?;
            }
        }
        tx.commit()?;
        Ok(entries.len())
    }

    /// Record that `path` was hashed and matched at `now_ns`.
    pub fn trust_mark_verified(&self, path: &[u8], now_ns: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE trust_cache SET verified_ns = ?2 WHERE path = ?1",
            params![path, to_i64(now_ns, "verified_ns")?],
        )?;
        Ok(())
    }

    /// Packages in the trust cache and their file counts.
    pub fn trust_packages(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT package, COUNT(*) FROM trust_cache GROUP BY package ORDER BY package",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (p, n) = row?;
            out.push((p, u64::try_from(n).unwrap_or(0)));
        }
        Ok(out)
    }

    /// Every entry of one package (for `ai-antivirus integrity`).
    pub fn trust_entries(&self, package: &str) -> Result<Vec<TrustEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, size, mtime_ns, verified_ns FROM trust_cache WHERE package = ?1 ORDER BY path",
        )?;
        let rows = stmt.query_map([package], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (path, sha, size, mtime, verified) = row?;
            if sha.len() != 32 {
                continue;
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&sha);
            out.push(TrustEntry {
                path,
                sha256: Sha256(digest),
                package: package.to_owned(),
                size: u64::try_from(size).unwrap_or(0),
                mtime_ns: u64::try_from(mtime).unwrap_or(0),
                verified_ns: u64::try_from(verified).unwrap_or(0),
            });
        }
        Ok(out)
    }
}

/// A response action record (M4). `target` and `undo` are typed JSON owned by the responder.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRow {
    pub id: i64,
    pub ts_ns: u64,
    pub alert_id: Option<i64>,
    pub rule_id: Option<String>,
    pub action: String,
    pub level: u8,
    pub target: serde_json::Value,
    pub status: ActionStatus,
    pub undo: Option<serde_json::Value>,
    pub error: Option<String>,
    pub decided_by: Option<String>,
}

/// An AI rule proposal (M5).
#[derive(Debug, Clone, PartialEq)]
pub struct ProposalRow {
    pub id: i64,
    pub ts_ns: u64,
    pub source: String,
    pub alert_id: Option<i64>,
    pub rule: serde_json::Value,
    pub status: ProposalStatus,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
}

const ACTION_COLS: &str =
    "id, ts_ns, alert_id, rule_id, action, level, target, status, undo, error, decided_by";

fn action_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRow> {
    let target: String = r.get(6)?;
    let status: String = r.get(7)?;
    let undo: Option<String> = r.get(8)?;
    Ok(ActionRow {
        id: r.get(0)?,
        ts_ns: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        alert_id: r.get(2)?,
        rule_id: r.get(3)?,
        action: r.get(4)?,
        level: u8::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
        target: serde_json::from_str(&target).unwrap_or(serde_json::Value::Null),
        // the CHECK constraint keeps this valid
        status: status.parse().unwrap_or(ActionStatus::Failed),
        undo: undo.and_then(|u| serde_json::from_str(&u).ok()),
        error: r.get(9)?,
        decided_by: r.get(10)?,
    })
}

impl Store {
    /// Record a new action and return its id.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_action(
        &self,
        ts_ns: u64,
        alert_id: Option<i64>,
        rule_id: Option<&str>,
        action: &str,
        level: u8,
        target: &serde_json::Value,
        status: ActionStatus,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO actions (ts_ns, alert_id, rule_id, action, level, target, status, updated_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?1)",
            params![to_i64(ts_ns, "ts_ns")?, alert_id, rule_id, action, i64::from(level), target.to_string(), status.as_str()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Change an action's status (and, when given, its undo data, error and who decided).
    pub fn update_action(
        &self,
        id: i64,
        status: ActionStatus,
        undo: Option<&serde_json::Value>,
        error: Option<&str>,
        decided_by: Option<&str>,
        now_ns: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE actions SET status = ?2,
                 undo = COALESCE(?3, undo), error = ?4, decided_by = COALESCE(?5, decided_by), updated_ns = ?6
             WHERE id = ?1",
            params![id, status.as_str(), undo.map(ToString::to_string), error, decided_by, to_i64(now_ns, "updated_ns")?],
        )?;
        Ok(())
    }

    pub fn get_action(&self, id: i64) -> Result<Option<ActionRow>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {ACTION_COLS} FROM actions WHERE id = ?1"))?;
        let mut rows = stmt.query_map([id], action_row)?;
        Ok(rows.next().transpose()?)
    }

    /// The newest `limit` actions, oldest first.
    pub fn recent_actions(&self, limit: usize) -> Result<Vec<ActionRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ACTION_COLS} FROM actions ORDER BY id DESC LIMIT ?1"
        ))?;
        let mut out = stmt
            .query_map([limit], action_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    /// Automatic actions (no human decided them) of at least `min_level` executed since `since_ns`: what the action
    /// budget and the circuit breaker count. Notifications (level 1) and approved actions do not use up the budget.
    pub fn executed_since(&self, since_ns: u64, min_level: u8) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM actions
             WHERE status IN ('executed', 'undone') AND ts_ns >= ?1 AND level >= ?2 AND decided_by IS NULL",
            params![to_i64(since_ns, "since_ns")?, i64::from(min_level)],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    pub fn state_get(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT value FROM state WHERE key = ?1")?;
        let mut rows = stmt.query([key])?;
        Ok(match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        })
    }

    pub fn state_set(&self, key: &str, value: &str, now_ns: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO state (key, value, updated_ns) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ns = excluded.updated_ns",
            params![key, value, to_i64(now_ns, "updated_ns")?],
        )?;
        Ok(())
    }

    pub fn state_delete(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM state WHERE key = ?1", [key])?;
        Ok(())
    }

    /// Store an AI rule proposal (status pending, or auto_rejected with a reason).
    pub fn insert_proposal(
        &self,
        ts_ns: u64,
        source: &str,
        alert_id: Option<i64>,
        rule: &serde_json::Value,
        status: ProposalStatus,
        reason: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO proposals (ts_ns, source, alert_id, rule, status, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![to_i64(ts_ns, "ts_ns")?, source, alert_id, rule.to_string(), status.as_str(), reason],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn decide_proposal(
        &self,
        id: i64,
        status: ProposalStatus,
        by: &str,
        reason: Option<&str>,
        now_ns: u64,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE proposals SET status = ?2, decided_by = ?3, reason = COALESCE(?4, reason), decided_ts_ns = ?5
             WHERE id = ?1 AND status = 'pending'",
            params![id, status.as_str(), by, reason, to_i64(now_ns, "decided_ts_ns")?],
        )?;
        Ok(n == 1)
    }

    pub fn proposals(&self, limit: usize) -> Result<Vec<ProposalRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ns, source, alert_id, rule, status, decided_by, reason FROM proposals ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            let rule: String = r.get(4)?;
            let status: String = r.get(5)?;
            Ok(ProposalRow {
                id: r.get(0)?,
                ts_ns: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                source: r.get(2)?,
                alert_id: r.get(3)?,
                rule: serde_json::from_str(&rule).unwrap_or(serde_json::Value::Null),
                status: status.parse().unwrap_or(ProposalStatus::Rejected),
                decided_by: r.get(6)?,
                reason: r.get(7)?,
            })
        })?;
        let mut out = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    /// Alerts newer than `after_id` (oldest first), for followers such as the notifier and the AI spool.
    pub fn alerts_after(&self, after_id: i64, limit: usize) -> Result<Vec<AlertRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ALERT_COLS} FROM alerts WHERE id > ?1 ORDER BY id ASC LIMIT ?2"
        ))?;
        let out = stmt
            .query_map(params![after_id, limit], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(out)
    }

    /// Actions waiting for a human decision, oldest first.
    pub fn pending_actions(&self) -> Result<Vec<ActionRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ACTION_COLS} FROM actions WHERE status = 'pending' ORDER BY id ASC LIMIT {MAX_RECENT}"
        ))?;
        let out = stmt
            .query_map([], action_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(out)
    }
}

/// The analyzer's advice about one alert (M5).
#[derive(Debug, Clone, PartialEq)]
pub struct AiNoteRow {
    pub id: i64,
    pub ts_ns: u64,
    pub alert_id: Option<i64>,
    pub model: String,
    pub verdict: String,
    pub confidence: f64,
    pub summary: String,
    pub techniques: serde_json::Value,
    pub indicators: serde_json::Value,
    pub injection_suspected: bool,
    pub problems: serde_json::Value,
}

impl Store {
    pub fn insert_ai_note(&self, n: &AiNoteRow) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO ai_notes (ts_ns, alert_id, model, verdict, confidence, summary, techniques, indicators,
                                   injection_suspected, problems)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                to_i64(n.ts_ns, "ts_ns")?,
                n.alert_id,
                n.model,
                n.verdict,
                n.confidence,
                n.summary,
                n.techniques.to_string(),
                n.indicators.to_string(),
                i64::from(n.injection_suspected),
                n.problems.to_string(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The newest `limit` notes, oldest first.
    pub fn recent_ai_notes(&self, limit: usize) -> Result<Vec<AiNoteRow>> {
        let limit = i64::try_from(limit.min(MAX_RECENT)).unwrap_or(0);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ns, alert_id, model, verdict, confidence, summary, techniques, indicators,
                    injection_suspected, problems FROM ai_notes ORDER BY id DESC LIMIT ?1",
        )?;
        let json = |s: String| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
        let rows = stmt.query_map([limit], |r| {
            Ok(AiNoteRow {
                id: r.get(0)?,
                ts_ns: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                alert_id: r.get(2)?,
                model: r.get(3)?,
                verdict: r.get(4)?,
                confidence: r.get(5)?,
                summary: r.get(6)?,
                techniques: json(r.get(7)?),
                indicators: json(r.get(8)?),
                injection_suspected: r.get::<_, i64>(9)? != 0,
                problems: json(r.get(10)?),
            })
        })?;
        let mut out = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    pub fn get_proposal(&self, id: i64) -> Result<Option<ProposalRow>> {
        Ok(self.proposals(MAX_RECENT)?.into_iter().find(|p| p.id == id))
    }
}

fn to_i64(v: u64, what: &'static str) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::OutOfRange(what))
}

fn count_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn pages_to_bytes(pages: i64, page_size: i64) -> u64 {
    u64::try_from(pages.max(0))
        .unwrap_or(0)
        .saturating_mul(u64::try_from(page_size.max(0)).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_1_database_is_migrated_and_keeps_its_actions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
            c.execute_batch(SCHEMA_V1).unwrap();
            c.execute_batch("PRAGMA user_version = 1;").unwrap();
            c.execute(
                "INSERT INTO actions (ts_ns, action, level, target, status) VALUES (5,'freeze',2,'{}','dry_run')",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let a = store.get_action(1).unwrap().unwrap();
        assert_eq!(
            (a.action.as_str(), a.status),
            ("freeze", ActionStatus::DryRun)
        );
    }

    #[test]
    fn alerts_after_pages_forward_without_skipping() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.max_alert_id().unwrap(), 0);
        for _ in 0..7 {
            store.insert_alert(&alert(None)).unwrap();
        }
        let mut seen = Vec::new();
        let mut cursor = 0;
        loop {
            let page = store.alerts_after(cursor, 3).unwrap();
            let Some(last) = page.last() else { break };
            cursor = last.id;
            seen.extend(page.iter().map(|a| a.id));
        }
        assert_eq!(seen, (1..=7).collect::<Vec<i64>>());
        assert_eq!(store.max_alert_id().unwrap(), 7);
        assert_eq!(store.get_alert(3).unwrap().unwrap().id, 3);
        assert!(store.get_alert(99).unwrap().is_none());
    }

    #[test]
    fn ai_notes_round_trip() {
        let store = Store::open_in_memory().unwrap();
        let note = AiNoteRow {
            id: 0,
            ts_ns: 5,
            alert_id: None,
            model: "m".into(),
            verdict: "suspicious".into(),
            confidence: 0.5,
            summary: "s".into(),
            techniques: serde_json::json!(["T1059"]),
            indicators: serde_json::json!([{"kind": "ip", "value": "198.51.100.1"}]),
            injection_suspected: true,
            problems: serde_json::json!([]),
        };
        let id = store.insert_ai_note(&note).unwrap();
        let back = store.recent_ai_notes(5).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].id, id);
        assert!(back[0].injection_suspected);
        assert_eq!(back[0].techniques[0], "T1059");
        assert!(store
            .insert_ai_note(&AiNoteRow {
                verdict: "bogus".into(),
                ..note
            })
            .is_err());
    }

    #[test]
    fn actions_state_and_proposals() {
        let store = Store::open_in_memory().unwrap();
        let t = serde_json::json!({"pid": 5});
        let id = store
            .insert_action(
                10,
                None,
                Some("AV-B-0001"),
                "freeze",
                2,
                &t,
                ActionStatus::Pending,
            )
            .unwrap();
        assert_eq!(store.pending_actions().unwrap()[0].id, id);
        store
            .update_action(
                id,
                ActionStatus::Executed,
                Some(&serde_json::json!({"cgroup": "/x"})),
                None,
                Some("root"),
                11,
            )
            .unwrap();
        assert!(store.pending_actions().unwrap().is_empty());
        let a = store.get_action(id).unwrap().unwrap();
        assert_eq!(a.status, ActionStatus::Executed);
        assert_eq!(a.undo.unwrap()["cgroup"], "/x");
        assert_eq!(a.decided_by.as_deref(), Some("root"));
        assert_eq!(store.executed_since(0, 2).unwrap(), 0, "decided by a human");
        let auto = store
            .insert_action(12, None, None, "kill", 3, &t, ActionStatus::Executed)
            .unwrap();
        assert_eq!(store.executed_since(0, 2).unwrap(), 1);
        assert_eq!(store.executed_since(0, 4).unwrap(), 0);
        assert_eq!(store.executed_since(13, 2).unwrap(), 0);
        assert!(auto > id);
        assert_eq!(store.recent_actions(5).unwrap().len(), 2);

        assert!(store.state_get("breaker").unwrap().is_none());
        store.state_set("breaker", "tripped", 1).unwrap();
        store.state_set("breaker", "tripped again", 2).unwrap();
        assert_eq!(
            store.state_get("breaker").unwrap().as_deref(),
            Some("tripped again")
        );
        store.state_delete("breaker").unwrap();
        assert!(store.state_get("breaker").unwrap().is_none());

        let p = store
            .insert_proposal(
                1,
                "ai",
                None,
                &serde_json::json!({"id": "LOCAL-x"}),
                ProposalStatus::Pending,
                None,
            )
            .unwrap();
        assert!(store
            .decide_proposal(p, ProposalStatus::Approved, "root", None, 2)
            .unwrap());
        assert!(
            !store
                .decide_proposal(p, ProposalStatus::Rejected, "root", None, 3)
                .unwrap(),
            "decided once"
        );
        assert_eq!(
            store.proposals(10).unwrap()[0].status,
            ProposalStatus::Approved
        );
    }

    #[test]
    fn hashes_trust_cache_and_alert_reads() {
        let mut store = Store::open_in_memory().unwrap();
        let sha = Sha256([7; 32]);
        assert!(store.hash_class(&sha).unwrap().is_none());
        store
            .put_hash(&sha, HashClass::Bad, Some("eicar"), "test", 1)
            .unwrap();
        assert_eq!(
            store.hash_class(&sha).unwrap(),
            Some((HashClass::Bad, Some("eicar".to_owned())))
        );

        let e = TrustEntry {
            path: b"/usr/bin/bash".to_vec(),
            sha256: sha,
            package: "bash".into(),
            size: 10,
            mtime_ns: 1_000_000_000,
            verified_ns: 0,
        };
        let other = TrustEntry {
            path: b"/usr/bin/old".to_vec(),
            ..e.clone()
        };
        assert_eq!(
            store
                .trust_replace_package("bash", &[e.clone(), other])
                .unwrap(),
            2
        );
        // an upgrade that dropped a file removes it from the cache
        assert_eq!(
            store
                .trust_replace_package("bash", std::slice::from_ref(&e))
                .unwrap(),
            1
        );
        assert!(store.trust_get(b"/usr/bin/old").unwrap().is_none());
        store.trust_mark_verified(b"/usr/bin/bash", 5).unwrap();
        assert_eq!(
            store
                .trust_get(b"/usr/bin/bash")
                .unwrap()
                .map(|t| t.verified_ns),
            Some(5)
        );
        assert_eq!(
            store.trust_packages().unwrap(),
            vec![("bash".to_owned(), 1)]
        );
        assert_eq!(store.trust_entries("bash").unwrap().len(), 1);

        for i in 0..3u64 {
            store
                .insert_alert(&NewAlert {
                    ts_ns: i,
                    rule_id: format!("AV-B-000{i}"),
                    severity: Severity::High,
                    confidence: 0.5,
                    title: "t".into(),
                    proc_key: Some(ProcKey {
                        pid: 9,
                        start_ns: 3,
                    }),
                    event_id: None,
                    detail: serde_json::json!({"k": i}),
                })
                .unwrap();
        }
        let a = store.recent_alerts(2).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].rule_id, "AV-B-0001");
        assert_eq!(a[1].detail["k"], 2);
        assert_eq!(
            a[1].proc_key,
            Some(ProcKey {
                pid: 9,
                start_ns: 3
            })
        );
    }
    use crate::event::BootId;
    use crate::model::{ActionStatus, HashClass, ProposalStatus, Verdict};
    use crate::testutil::{all_event_variants, sample_envelope};
    use rusqlite::Connection;
    use std::os::unix::fs::symlink;

    const DAY: u64 = NS_PER_DAY;
    const NOW: u64 = 1_800_000_000_000_000_000;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn pragma(store: &Store, name: &str) -> i64 {
        store.pragma_i64(name).unwrap()
    }

    fn alert(event_id: Option<i64>) -> NewAlert {
        NewAlert {
            ts_ns: NOW,
            rule_id: "AV-B-0001".to_owned(),
            severity: Severity::High,
            confidence: 0.9,
            title: "Shell with a socket as stdin".to_owned(),
            proc_key: Some(ProcKey {
                pid: 7,
                start_ns: 70,
            }),
            event_id,
            detail: serde_json::json!({"fd0": "socket:[1234]"}),
        }
    }

    #[test]
    fn alerts_can_be_acknowledged_and_counted() {
        let store = Store::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for (i, sev) in [
            Severity::High,
            Severity::Low,
            Severity::High,
            Severity::Critical,
        ]
        .into_iter()
        .enumerate()
        {
            let mut a = alert(None);
            a.severity = sev;
            a.ts_ns = NOW + i as u64;
            ids.push(store.insert_alert(&a).unwrap());
        }
        let (counts, unacked) = store.alert_counts(0).unwrap();
        assert_eq!(unacked, 4);
        assert!(counts.contains(&(Severity::High, 2)));
        assert!(counts.contains(&(Severity::Medium, 0)));
        // only the newer ones fall in a later window
        let (later, _) = store.alert_counts(NOW + 2).unwrap();
        assert_eq!(later.iter().map(|c| c.1).sum::<u64>(), 2);

        assert_eq!(store.ack_alerts(&[ids[0], ids[0], 9999]).unwrap(), 1);
        assert!(store.get_alert(ids[0]).unwrap().unwrap().acknowledged);
        let open: Vec<i64> = store
            .unacked_alerts(10)
            .unwrap()
            .iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(open, ids[1..].to_vec());
        assert_eq!(store.ack_all_alerts().unwrap(), 3);
        assert_eq!(store.alert_counts(0).unwrap().1, 0);
        assert!(store.unacked_alerts(10).unwrap().is_empty());
    }

    #[test]
    fn open_creates_secure_wal_database_with_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.db");
        let mut store = Store::open(&path).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(pragma(&store, "auto_vacuum"), 2, "incremental auto_vacuum");
        assert_eq!(pragma(&store, "foreign_keys"), 1);

        store.insert_event(&sample_envelope(1, NOW)).unwrap();
        for suffix in ["-wal", "-shm"] {
            let side = dir.path().join(format!("ai-antivirus.db{suffix}"));
            if side.exists() {
                assert_eq!(
                    mode_of(&side) & 0o077,
                    0,
                    "{suffix} must not be group/world accessible"
                );
            }
        }
    }

    #[test]
    fn open_tightens_existing_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.db");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        Store::open(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn open_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.db");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("ai-antivirus.db");
        symlink(&target, &link).unwrap();
        assert!(matches!(Store::open(&link), Err(Error::Io { .. })));
    }

    #[test]
    fn reopen_keeps_data_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.db");
        {
            let mut store = Store::open(&path).unwrap();
            store.insert_event(&sample_envelope(1, NOW)).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.stats().unwrap().events, 1);
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 99;").unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(Error::SchemaTooNew { found: 99, .. })
        ));
    }

    #[test]
    fn batch_insert_and_recent_events() {
        let mut store = Store::open_in_memory().unwrap();
        let batch: Vec<_> = (0..5).map(|i| sample_envelope(i, NOW + i)).collect();
        assert_eq!(store.insert_events(&batch).unwrap(), 5);

        let recent = store.recent_events(3).unwrap();
        assert_eq!(recent, batch[2..].to_vec(), "newest three, oldest first");
        assert_eq!(store.recent_events(100).unwrap(), batch);
        assert!(store.recent_events(0).unwrap().is_empty());
    }

    #[test]
    fn indexed_columns_are_populated() {
        let mut store = Store::open_in_memory().unwrap();
        let events = all_event_variants();
        let batch: Vec<_> = events
            .iter()
            .enumerate()
            .map(|(i, e)| Envelope {
                seq: i as u64,
                ts_ns: NOW,
                boot_id: BootId(1),
                event: e.clone(),
            })
            .collect();
        store.insert_events(&batch).unwrap();

        let (kind, pid): (String, Option<i64>) = store
            .conn
            .query_row(
                "SELECT kind, pid FROM events WHERE kind = 'exec'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((kind.as_str(), pid), ("exec", Some(100)));

        let tamper_pid: Option<i64> = store
            .conn
            .query_row("SELECT pid FROM events WHERE kind = 'tamper'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(tamper_pid, None);
    }

    #[test]
    fn failed_batch_rolls_back_entirely() {
        let mut store = Store::open_in_memory().unwrap();
        let good = sample_envelope(1, NOW);
        let bad = sample_envelope(2, u64::MAX);
        assert!(matches!(
            store.insert_events(&[good, bad]),
            Err(Error::OutOfRange(_))
        ));
        assert_eq!(store.stats().unwrap().events, 0);
    }

    #[test]
    fn alerts_validate_and_link_to_events() {
        let mut store = Store::open_in_memory().unwrap();
        let event_id = store.insert_event(&sample_envelope(1, NOW)).unwrap();
        let alert_id = store.insert_alert(&alert(Some(event_id))).unwrap();
        assert!(alert_id > 0);

        let (sev, linked): (String, Option<i64>) = store
            .conn
            .query_row(
                "SELECT severity, event_id FROM alerts WHERE id = ?1",
                [alert_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((sev.as_str(), linked), ("high", Some(event_id)));

        for bad in [-0.1, 1.5, f64::NAN] {
            let mut a = alert(None);
            a.confidence = bad;
            assert!(
                matches!(store.insert_alert(&a), Err(Error::OutOfRange(_))),
                "{bad}"
            );
        }
        // Foreign keys are enforced.
        assert!(store.insert_alert(&alert(Some(99_999))).is_err());
    }

    #[test]
    fn cleanup_by_age_keeps_alerts_and_nulls_their_link() {
        let mut store = Store::open_in_memory().unwrap();
        let old_ts = NOW - 20 * DAY;
        let old_id = store.insert_event(&sample_envelope(1, old_ts)).unwrap();
        store.insert_event(&sample_envelope(2, NOW - DAY)).unwrap();
        store.insert_alert(&alert(Some(old_id))).unwrap();

        let report = store.cleanup(14, u64::MAX, NOW).unwrap();
        assert_eq!(report.deleted_by_age, 1);
        assert_eq!(report.deleted_by_size, 0);

        let stats = store.stats().unwrap();
        assert_eq!((stats.events, stats.alerts), (1, 1));
        let link: Option<i64> = store
            .conn
            .query_row("SELECT event_id FROM alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(link, None);
    }

    #[test]
    fn cleanup_by_size_drops_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("ai-antivirus.db")).unwrap();
        let batch: Vec<_> = (0..3000).map(|i| sample_envelope(i, NOW + i)).collect();
        store.insert_events(&batch).unwrap();

        let before = store.stats().unwrap();
        let cap = before.used_bytes / 2;
        let report = store.cleanup(365, cap, NOW + 4000).unwrap();

        assert_eq!(report.deleted_by_age, 0);
        assert!(report.deleted_by_size > 0);
        assert!(
            report.used_bytes_after <= cap,
            "{} > {cap}",
            report.used_bytes_after
        );

        let remaining = store.recent_events(10_000).unwrap();
        assert!(!remaining.is_empty(), "should not wipe everything");
        assert_eq!(
            remaining.last().map(|e| e.seq),
            Some(2999),
            "newest survives"
        );
        assert_ne!(
            remaining.first().map(|e| e.seq),
            Some(0),
            "oldest was pruned"
        );
        assert!(
            store.stats().unwrap().file_bytes < before.file_bytes,
            "file shrank"
        );
    }

    #[test]
    fn cleanup_stops_when_only_schema_remains() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert_event(&sample_envelope(1, NOW)).unwrap();
        let report = store.cleanup(365, 0, NOW).unwrap();
        assert_eq!(report.deleted_by_size, 1);
        assert_eq!(store.stats().unwrap().events, 0);
    }

    #[test]
    fn stats_count_every_table() {
        let mut store = Store::open_in_memory().unwrap();
        let id = store.insert_event(&sample_envelope(1, NOW)).unwrap();
        store.insert_alert(&alert(Some(id))).unwrap();
        let s = store.stats().unwrap();
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert_eq!((s.events, s.alerts, s.verdicts, s.actions), (1, 1, 0, 0));
        assert_eq!(
            (s.proposals, s.hashes, s.baselines, s.trust_cache),
            (0, 0, 0, 0)
        );
        assert!(s.file_bytes >= s.used_bytes && s.used_bytes > 0);
    }

    /// The Rust enums and the SQL CHECK constraints must agree.
    #[test]
    fn enum_strings_match_check_constraints() {
        let store = Store::open_in_memory().unwrap();
        let c = &store.conn;

        for s in Severity::ALL {
            c.execute(
                "INSERT INTO alerts (ts_ns, rule_id, severity, confidence, title) VALUES (0,'r',?1,0.5,'t')",
                [s.as_str()],
            )
            .unwrap();
        }
        for v in Verdict::ALL {
            c.execute(
                "INSERT INTO verdicts (ts_ns, rule_id, verdict, score, confidence) VALUES (0,'r',?1,1.0,0.5)",
                [v.as_str()],
            )
            .unwrap();
        }
        for a in ActionStatus::ALL {
            c.execute(
                "INSERT INTO actions (ts_ns, action, level, target, status) VALUES (0,'freeze',2,'{}',?1)",
                [a.as_str()],
            )
            .unwrap();
        }
        for p in ProposalStatus::ALL {
            c.execute(
                "INSERT INTO proposals (ts_ns, source, rule, status) VALUES (0,'ai','{}',?1)",
                [p.as_str()],
            )
            .unwrap();
        }
        for (i, h) in HashClass::ALL.iter().enumerate() {
            let digest = vec![u8::try_from(i).unwrap(); 32];
            c.execute(
                "INSERT INTO hashes (sha256, class, source, added_ts_ns) VALUES (?1,?2,'test',0)",
                params![digest, h.as_str()],
            )
            .unwrap();
        }

        // And the constraints really exist.
        let rejects = [
            "INSERT INTO alerts (ts_ns, rule_id, severity, confidence, title) VALUES (0,'r','bogus',0.5,'t')",
            "INSERT INTO verdicts (ts_ns, rule_id, verdict, score, confidence) VALUES (0,'r','bogus',1.0,0.5)",
            "INSERT INTO actions (ts_ns, action, level, target, status) VALUES (0,'x',7,'{}','executed')",
            "INSERT INTO actions (ts_ns, action, level, target, status) VALUES (0,'x',1,'{}','bogus')",
            "INSERT INTO proposals (ts_ns, source, rule, status) VALUES (0,'ai','{}','bogus')",
            "INSERT INTO hashes (sha256, class, source, added_ts_ns) VALUES (x'00','bad','t',0)",
        ];
        for sql in rejects {
            assert!(c.execute(sql, []).is_err(), "should be rejected: {sql}");
        }
    }

    #[test]
    fn trust_cache_accepts_non_utf8_paths() {
        let store = Store::open_in_memory().unwrap();
        let path: Vec<u8> = vec![b'/', b'u', 0xff, 0xfe];
        store
            .conn
            .execute(
                "INSERT INTO trust_cache (path, sha256, package, size, mtime_ns, verified_ns)
                 VALUES (?1, ?2, 'pkg', 1, 1, 1)",
                params![path, vec![0u8; 32]],
            )
            .unwrap();
        assert_eq!(store.stats().unwrap().trust_cache, 1);
    }
}
