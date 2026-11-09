-- AI Antivirus store, schema version 4: AI feedback & self-healing memory.
-- Remembers user-verified safe activity and patterns so the local LLM and engine
-- self-heal and recognize known-safe patterns on recurrence.
CREATE TABLE ai_feedback (
    id           INTEGER PRIMARY KEY,
    ts_ns        INTEGER NOT NULL,
    alert_id     INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    rule_id      TEXT    NOT NULL,
    exe          TEXT,
    sha256       TEXT,
    title        TEXT    NOT NULL DEFAULT '',
    verdict      TEXT    NOT NULL CHECK (verdict IN ('safe', 'malicious', 'suspicious')),
    user_notes   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX ai_feedback_lookup ON ai_feedback(rule_id, exe);
CREATE INDEX ai_feedback_ts     ON ai_feedback(ts_ns);
