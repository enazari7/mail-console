-- BeastPing Mail Console: initial schema.
-- Timestamps are INTEGER microseconds since the Unix epoch (UTC).

CREATE TABLE messages (
    id                  INTEGER PRIMARY KEY,
    queue_id            TEXT,               -- NULL for NOQUEUE rejections
    host                TEXT,
    first_ts            INTEGER NOT NULL,
    last_ts             INTEGER NOT NULL,
    sender              TEXT,               -- NULL = not seen in logs; '' = null sender <>
    message_id          TEXT,               -- RFC 5322 Message-ID header, if logged
    subject             TEXT,               -- only if Postfix logged it (header_checks INFO)
    size                INTEGER,
    nrcpt               INTEGER,
    client              TEXT,
    sasl_username       TEXT,
    origin              TEXT NOT NULL DEFAULT 'unknown',  -- smtpd|pickup|dsn|noqueue|unknown
    orig_queue_id       TEXT,               -- pickup orig_id= (postsuper -r requeue)
    notification_qid    TEXT,               -- queue id of the DSN Postfix generated for this message
    status              TEXT NOT NULL DEFAULT 'unknown',
    has_start           INTEGER NOT NULL DEFAULT 0,
    has_qmgr            INTEGER NOT NULL DEFAULT 0,
    closed_ts           INTEGER,            -- 'removed' / 'requeued' seen
    active_count        INTEGER NOT NULL DEFAULT 0,
    event_count         INTEGER NOT NULL DEFAULT 0,
    events_truncated    INTEGER NOT NULL DEFAULT 0,
    last_dsn            TEXT,
    last_response       TEXT
);
CREATE INDEX ix_messages_qid ON messages(queue_id, first_ts);
CREATE INDEX ix_messages_first_ts ON messages(first_ts);
CREATE INDEX ix_messages_last_ts ON messages(last_ts);
CREATE INDEX ix_messages_status ON messages(status, first_ts);
CREATE INDEX ix_messages_msgid ON messages(message_id);
CREATE INDEX ix_messages_sender ON messages(sender COLLATE NOCASE);
CREATE INDEX ix_messages_notification ON messages(notification_qid);
CREATE INDEX ix_messages_orig_qid ON messages(orig_queue_id);

CREATE TABLE recipients (
    id                  INTEGER PRIMARY KEY,
    message_id          INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    address             TEXT NOT NULL,
    orig_address        TEXT,
    domain              TEXT,
    status              TEXT NOT NULL,
    dsn                 TEXT,
    relay               TEXT,
    response            TEXT,
    delay               REAL,
    delays              TEXT,
    attempts            INTEGER NOT NULL DEFAULT 0,
    deferrals           INTEGER NOT NULL DEFAULT 0,
    first_attempt_ts    INTEGER,
    last_attempt_ts     INTEGER,
    final_ts            INTEGER,
    UNIQUE (message_id, address)
);
CREATE INDEX ix_recipients_address ON recipients(address COLLATE NOCASE);
CREATE INDEX ix_recipients_domain ON recipients(domain);
CREATE INDEX ix_recipients_status ON recipients(status, final_ts);
CREATE INDEX ix_recipients_final_ts ON recipients(final_ts);

CREATE TABLE events (
    id                  INTEGER PRIMARY KEY,
    message_id          INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    ts                  INTEGER NOT NULL,
    host                TEXT,
    program             TEXT NOT NULL,
    pid                 INTEGER,
    queue_id            TEXT,
    kind                TEXT NOT NULL,
    recipient           TEXT,
    status              TEXT,
    dsn                 TEXT,
    relay               TEXT,
    delay               REAL,
    delays              TEXT,
    response            TEXT,
    detail              TEXT,               -- JSON with kind-specific fields
    raw                 TEXT,
    line_hash           BLOB NOT NULL UNIQUE
);
CREATE INDEX ix_events_message ON events(message_id, ts);
CREATE INDEX ix_events_kind_ts ON events(kind, ts);
CREATE INDEX ix_events_ts ON events(ts);

CREATE TABLE ops_events (
    id                  INTEGER PRIMARY KEY,
    ts                  INTEGER NOT NULL,
    host                TEXT,
    program             TEXT NOT NULL,
    pid                 INTEGER,
    level               TEXT NOT NULL,      -- warning|error|fatal|panic|reject|info
    message             TEXT NOT NULL,
    line_hash           BLOB NOT NULL UNIQUE
);
CREATE INDEX ix_ops_ts ON ops_events(ts);

CREATE TABLE queue_snapshots (
    id                  INTEGER PRIMARY KEY,
    ts                  INTEGER NOT NULL,
    ok                  INTEGER NOT NULL,
    error               TEXT,
    total               INTEGER,
    by_queue            TEXT,               -- JSON {queue_name: count}
    oldest_arrival_ts   INTEGER,
    entries             TEXT                -- JSON list, capped
);
CREATE INDEX ix_queue_snapshots_ts ON queue_snapshots(ts);

CREATE TABLE service_status (
    unit                TEXT PRIMARY KEY,
    label               TEXT NOT NULL,
    checked_ts          INTEGER NOT NULL,
    ok                  INTEGER NOT NULL,
    load_state          TEXT,
    active_state        TEXT,
    sub_state           TEXT,
    since               TEXT,
    main_pid            INTEGER,
    restarts            INTEGER,
    error               TEXT
);

CREATE TABLE checkpoints (
    source              TEXT PRIMARY KEY,
    path                TEXT,
    dev                 INTEGER,
    inode               INTEGER,
    offset              INTEGER,
    fingerprint         BLOB,
    fingerprint_len     INTEGER,
    cursor              TEXT,
    updated_ts          INTEGER NOT NULL
);

CREATE TABLE collector_state (
    key                 TEXT PRIMARY KEY,
    value               TEXT
);

CREATE TABLE admins (
    id                  INTEGER PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    created_ts          INTEGER NOT NULL,
    password_changed_ts INTEGER NOT NULL,
    last_login_ts       INTEGER
);

CREATE TABLE sessions (
    token_hash          BLOB PRIMARY KEY,
    admin_id            INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token          TEXT NOT NULL,
    created_ts          INTEGER NOT NULL,
    last_seen_ts        INTEGER NOT NULL,
    expires_ts          INTEGER NOT NULL,
    client_ip           TEXT,
    user_agent          TEXT
);
CREATE INDEX ix_sessions_admin ON sessions(admin_id);

CREATE TABLE login_attempts (
    id                  INTEGER PRIMARY KEY,
    ts                  INTEGER NOT NULL,
    client_ip           TEXT,
    username_hash       TEXT,
    success             INTEGER NOT NULL
);
CREATE INDEX ix_login_attempts_ts ON login_attempts(ts);

CREATE TABLE settings (
    key                 TEXT PRIMARY KEY,
    value               TEXT NOT NULL
);
