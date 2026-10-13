-- Nightwatch SQLite schema. Raw events and alerts are kept so analysts can hunt
-- with SQL after detection runs, the way they would in a SIEM.

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT    NOT NULL,
    sources     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts      TEXT    NOT NULL,           -- ISO 8601, sorts correctly as text
    host    TEXT    NOT NULL,
    kind    TEXT    NOT NULL CHECK (kind IN ('ssh_failed', 'ssh_accepted', 'ssh_invalid_user', 'sudo')),
    user    TEXT,
    ip      TEXT,
    method  TEXT,
    raw     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_ip_ts ON auth_events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_auth_kind ON auth_events (kind);

CREATE TABLE IF NOT EXISTS web_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts          TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    status      INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    user_agent  TEXT    NOT NULL,
    raw         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web_ip_ts ON web_events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_web_status ON web_events (status);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    severity_n  INTEGER NOT NULL,       -- 1-4, for ORDER BY
    mitre_id    TEXT    NOT NULL,
    mitre_name  TEXT    NOT NULL,
    description TEXT    NOT NULL,
    ip          TEXT,
    user        TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    count       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip);
