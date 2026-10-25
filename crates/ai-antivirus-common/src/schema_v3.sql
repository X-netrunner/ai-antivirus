-- AI Antivirus store, schema version 3 (M5): the AI analyzer's advice about alerts. Advice only: nothing reads this table to
-- decide an action.
CREATE TABLE ai_notes (
    id                 INTEGER PRIMARY KEY,
    ts_ns              INTEGER NOT NULL,
    alert_id           INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    model              TEXT    NOT NULL,
    verdict            TEXT    NOT NULL CHECK (verdict IN ('benign','suspicious','malicious','unknown')),
    confidence         REAL    NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    summary            TEXT    NOT NULL,
    techniques         TEXT    NOT NULL DEFAULT '[]',   -- JSON array of ATT&CK ids
    indicators         TEXT    NOT NULL DEFAULT '[]',   -- JSON array of {kind, value}
    injection_suspected INTEGER NOT NULL CHECK (injection_suspected IN (0,1)),
    problems           TEXT    NOT NULL DEFAULT '[]'    -- what validation dropped
);
CREATE INDEX ai_notes_alert ON ai_notes(alert_id);
