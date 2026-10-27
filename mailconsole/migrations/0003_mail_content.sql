-- MAIL-CONTENT-01: archived message content, audit log and TOTP.

-- Replaced by the tables below; nothing ever wrote to it.
DROP TABLE message_content;

-- One stored file per distinct message content (SHA-256 of the exact bytes
-- Postfix handed to the archive transport).
CREATE TABLE archive_blobs (
    sha256          TEXT PRIMARY KEY,
    path            TEXT NOT NULL,          -- relative to MC_ARCHIVE_DIR
    size            INTEGER NOT NULL,       -- original size in bytes
    stored_size     INTEGER NOT NULL,
    encrypted       INTEGER NOT NULL,
    created_ts      INTEGER NOT NULL
);

-- One row per captured copy. (queue_id, sha256) is unique, so a repeated
-- delivery of the same copy is ignored.
CREATE TABLE archives (
    id                  INTEGER PRIMARY KEY,
    queue_id            TEXT NOT NULL,
    captured_ts         INTEGER NOT NULL,
    envelope_sender     TEXT,
    sasl_username       TEXT,
    host                TEXT,
    sha256              TEXT NOT NULL REFERENCES archive_blobs(sha256),
    size                INTEGER NOT NULL,
    header_message_id   TEXT,
    subject             TEXT,
    from_header         TEXT,
    to_header           TEXT,
    cc_header           TEXT,
    reply_to_header     TEXT,
    date_header         TEXT,
    has_text            INTEGER NOT NULL DEFAULT 0,
    has_html            INTEGER NOT NULL DEFAULT 0,
    attachment_count    INTEGER NOT NULL DEFAULT 0,
    inline_count        INTEGER NOT NULL DEFAULT 0,
    structure_truncated INTEGER NOT NULL DEFAULT 0,
    message_id          INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    link_method         TEXT NOT NULL DEFAULT 'pending',   -- pending | archive-delivery | queue-lifetime | conflict
    link_note           TEXT,
    created_ts          INTEGER NOT NULL,
    UNIQUE (queue_id, sha256)
);
CREATE INDEX ix_archives_message ON archives(message_id);
CREATE INDEX ix_archives_captured ON archives(captured_ts);
CREATE INDEX ix_archives_pending ON archives(link_method, captured_ts);
CREATE INDEX ix_archives_sha ON archives(sha256);

-- MIME structure with byte offsets into the stored (decrypted) message.
CREATE TABLE archive_parts (
    archive_id          INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    part_index          INTEGER NOT NULL,
    parent_index        INTEGER,
    content_type        TEXT NOT NULL,
    charset             TEXT,
    transfer_encoding   TEXT,
    disposition         TEXT,
    filename            TEXT,
    content_id          TEXT,
    role                TEXT NOT NULL,
    body_start          INTEGER NOT NULL,
    body_end            INTEGER NOT NULL,
    decoded_size        INTEGER,
    PRIMARY KEY (archive_id, part_index)
);

-- Searchable archived content: subject, header addresses, attachment names
-- and the start of the text body.
CREATE VIRTUAL TABLE archive_search USING fts5(doc, tokenize = 'trigram');
CREATE TRIGGER archives_search_delete AFTER DELETE ON archives BEGIN
    DELETE FROM archive_search WHERE rowid = old.id;
END;

-- Who viewed or downloaded archived content, and security events.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    admin_id    INTEGER,
    username    TEXT,
    client_ip   TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    detail      TEXT
);
CREATE INDEX ix_audit_ts ON audit_log(ts);

-- Optional TOTP second factor.
ALTER TABLE admins ADD COLUMN totp_secret TEXT;
ALTER TABLE admins ADD COLUMN totp_last_counter INTEGER;

CREATE TABLE pending_logins (
    token_hash  BLOB PRIMARY KEY,
    admin_id    INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_ts  INTEGER NOT NULL,
    expires_ts  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    client_ip   TEXT
);

-- Delivery state of the archive copy (the always_bcc recipient), kept apart
-- from the real recipients.
ALTER TABLE messages ADD COLUMN archive_status TEXT;
ALTER TABLE messages ADD COLUMN archive_ts INTEGER;
ALTER TABLE messages ADD COLUMN archive_response TEXT;
