-- AI Antivirus store, schema version 1.
-- Timestamps are integer nanoseconds since the Unix epoch (fits i64 until 2262).
-- Process identity is (pid, proc_start_ns); see event.rs for its caveats.

-- Rolling raw telemetry. `body` is the full Envelope as JSON.
-- (boot_id, seq) is indexed but NOT unique: seq restarts when the sensor restarts.
CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    boot_id       TEXT    NOT NULL,
    seq           INTEGER NOT NULL,
    ts_ns         INTEGER NOT NULL,
    kind          TEXT    NOT NULL,
    pid           INTEGER,
    proc_start_ns INTEGER,
    body          TEXT    NOT NULL
);
CREATE INDEX events_ts   ON events(ts_ns);
CREATE INDEX events_boot ON events(boot_id, seq);
CREATE INDEX events_proc ON events(pid, proc_start_ns);

-- Alerts outlive the events that caused them: deleting the event nulls the link.
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    ts_ns         INTEGER NOT NULL,
    rule_id       TEXT    NOT NULL,
    severity      TEXT    NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    confidence    REAL    NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    title         TEXT    NOT NULL,
    pid           INTEGER,
    proc_start_ns INTEGER,
    event_id      INTEGER REFERENCES events(id) ON DELETE SET NULL,
    detail        TEXT    NOT NULL DEFAULT '{}',
    acknowledged  INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0,1))
);
CREATE INDEX alerts_ts   ON alerts(ts_ns);
CREATE INDEX alerts_rule ON alerts(rule_id);

CREATE TABLE verdicts (
    id            INTEGER PRIMARY KEY,
    ts_ns         INTEGER NOT NULL,
    alert_id      INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    rule_id       TEXT    NOT NULL,
    verdict       TEXT    NOT NULL CHECK (verdict IN ('benign','suspicious','malicious')),
    score         REAL    NOT NULL,
    confidence    REAL    NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    pid           INTEGER,
    proc_start_ns INTEGER
);
CREATE INDEX verdicts_ts ON verdicts(ts_ns);

-- One row per response action, with the data needed to undo it.
CREATE TABLE actions (
    id         INTEGER PRIMARY KEY,
    ts_ns      INTEGER NOT NULL,
    verdict_id INTEGER REFERENCES verdicts(id) ON DELETE SET NULL,
    action     TEXT    NOT NULL,
    level      INTEGER NOT NULL CHECK (level BETWEEN 0 AND 6),
    target     TEXT    NOT NULL,                 -- JSON, typed per action
    status     TEXT    NOT NULL CHECK (status IN ('dry_run','executed','failed','undone','skipped')),
    undo       TEXT,                             -- JSON, NULL when nothing to undo
    error      TEXT
);
CREATE INDEX actions_ts ON actions(ts_ns);

-- AI rule proposals awaiting a human decision.
CREATE TABLE proposals (
    id            INTEGER PRIMARY KEY,
    ts_ns         INTEGER NOT NULL,
    source        TEXT    NOT NULL,
    alert_id      INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    rule          TEXT    NOT NULL,              -- JSON using the TOML rule schema
    status        TEXT    NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','approved','rejected','auto_rejected')),
    decided_ts_ns INTEGER,
    decided_by    TEXT,
    reason        TEXT
);
CREATE INDEX proposals_status ON proposals(status);

CREATE TABLE hashes (
    sha256      BLOB    PRIMARY KEY CHECK (length(sha256) = 32),
    class       TEXT    NOT NULL CHECK (class IN ('bad','good')),
    label       TEXT,
    source      TEXT    NOT NULL,
    added_ts_ns INTEGER NOT NULL
) WITHOUT ROWID;

-- First-seen tracking for anomaly rules, e.g. kind='exec_parent', subject=parent exe, value=child exe.
CREATE TABLE baselines (
    kind          TEXT    NOT NULL,
    subject       TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns  INTEGER NOT NULL,
    count         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (kind, subject, value)
) WITHOUT ROWID;

-- Files verified against the pacman database. `path` is BLOB: Linux paths are bytes.
CREATE TABLE trust_cache (
    path        BLOB    PRIMARY KEY,
    sha256      BLOB    NOT NULL CHECK (length(sha256) = 32),
    package     TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    mtime_ns    INTEGER NOT NULL,
    verified_ns INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX trust_cache_pkg ON trust_cache(package);
