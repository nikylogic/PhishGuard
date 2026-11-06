
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    pw_hash     TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_login  TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY,
    url          TEXT NOT NULL,
    final_url    TEXT,
    domain       TEXT NOT NULL,
    source       TEXT NOT NULL CHECK (source IN ('launcher', 'manual')),
    status       TEXT NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'done', 'partial', 'failed')),
    score        INTEGER NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
    level        TEXT NOT NULL DEFAULT 'pending'
                 CHECK (level IN ('pending', 'clear', 'caution', 'danger')),
    s_phishing   INTEGER NOT NULL DEFAULT 0,
    s_malware    INTEGER NOT NULL DEFAULT 0,
    s_tracking   INTEGER NOT NULL DEFAULT 0,
    s_abuse      INTEGER NOT NULL DEFAULT 0,
    title        TEXT,
    screenshot   TEXT,
    redirect_json TEXT,
    page_json    TEXT,
    llm_json     TEXT,
    guard_score  REAL,
    decision     TEXT NOT NULL DEFAULT 'pending'
                 CHECK (decision IN ('pending', 'opened', 'blocked', 'ignored')),
    error        TEXT,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS ix_scans_domain  ON scans(domain);
CREATE INDEX IF NOT EXISTS ix_scans_level   ON scans(level);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage     TEXT NOT NULL CHECK (stage IN ('url', 'page', 'guard', 'llm')),
    category  TEXT NOT NULL CHECK (category IN ('phishing', 'malware', 'tracking', 'abuse')),
    code      TEXT NOT NULL,
    weight    INTEGER NOT NULL,
    message   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS downloads (
    id              INTEGER PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    filename        TEXT,
    declared_type   TEXT,
    real_type       TEXT,
    size            INTEGER,
    sha256          TEXT,
    verdict         TEXT,
    quarantine_path TEXT
);

CREATE TABLE IF NOT EXISTS privacy (
    scan_id             INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    trackers_json       TEXT,
    fingerprint_json    TEXT,
    ip_logger           INTEGER NOT NULL DEFAULT 0,
    webrtc              INTEGER NOT NULL DEFAULT 0,
    params_removed_json TEXT
);

CREATE TABLE IF NOT EXISTS domain_lists (
    id         INTEGER PRIMARY KEY,
    domain     TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('allow', 'block')),
    note       TEXT,
    added_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS intel_lists (
    id     INTEGER PRIMARY KEY,
    kind   TEXT NOT NULL
           CHECK (kind IN ('ip_logger', 'tracker', 'miner', 'malware_url', 'bad_hash', 'brand')),
    value  TEXT NOT NULL,
    source TEXT,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS guard_events (
    id           INTEGER PRIMARY KEY,
    scan_id      INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    source       TEXT NOT NULL CHECK (source IN ('page', 'playground')),
    text_snippet TEXT,
    score        REAL NOT NULL,
    label        TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
