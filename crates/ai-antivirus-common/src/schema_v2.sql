-- AI Antivirus store, schema version 2 (M4): actions gain the approval states and their links, plus a small key/value table
-- for responder state (circuit breaker). SQLite cannot change a CHECK constraint in place, so the table is rebuilt.

CREATE TABLE actions_v2 (
    id          INTEGER PRIMARY KEY,
    ts_ns       INTEGER NOT NULL,
    verdict_id  INTEGER REFERENCES verdicts(id) ON DELETE SET NULL,
    alert_id    INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    rule_id     TEXT,
    action      TEXT    NOT NULL,
    level       INTEGER NOT NULL CHECK (level BETWEEN 0 AND 6),
    target      TEXT    NOT NULL,                 -- JSON, typed per action
    status      TEXT    NOT NULL CHECK (status IN ('dry_run','executed','failed','undone','skipped','pending','rejected')),
    undo        TEXT,                             -- JSON, NULL when nothing to undo
    error       TEXT,
    decided_by  TEXT,                             -- who approved, rejected or undid it
    updated_ns  INTEGER
);
INSERT INTO actions_v2 (id, ts_ns, verdict_id, action, level, target, status, undo, error)
    SELECT id, ts_ns, verdict_id, action, level, target, status, undo, error FROM actions;
DROP TABLE actions;
ALTER TABLE actions_v2 RENAME TO actions;
CREATE INDEX actions_ts     ON actions(ts_ns);
CREATE INDEX actions_status ON actions(status);

CREATE TABLE state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_ns INTEGER NOT NULL
) WITHOUT ROWID;
