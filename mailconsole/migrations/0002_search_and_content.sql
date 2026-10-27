-- EMAILS-UX-02: indexed search and a placeholder for retained message content.

-- One search document per message: Queue ID, sender, Message-ID, subject,
-- SASL user, recipient addresses/domains and failure responses. The trigram
-- tokenizer makes case-insensitive substring search (3+ characters) indexed.
-- Documents are written by the collector (mailconsole.search); the post-
-- migration step fills it for existing messages.
CREATE VIRTUAL TABLE message_search USING fts5(doc, tokenize = 'trigram');

CREATE TRIGGER messages_search_delete AFTER DELETE ON messages BEGIN
    DELETE FROM message_search WHERE rowid = old.id;
END;

-- Message content retained by a future, separately approved capture
-- mechanism. Nothing writes this table yet; the UI shows "Content not
-- retained" while it is empty.
CREATE TABLE message_content (
    message_id      INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    captured_ts     INTEGER NOT NULL,
    source          TEXT NOT NULL,      -- name of the approved capture mechanism
    subject         TEXT,
    text_body       TEXT,
    html_body       TEXT,               -- shown only in a sandboxed, script-free frame
    attachments     TEXT                -- JSON list of {filename, content_type, size}
);

-- Sender picker support.
CREATE INDEX ix_messages_first_ts_sender ON messages(first_ts, sender);

-- Correlation re-groups all events of a touched Queue ID after every batch;
-- without this index each re-grouping scanned the whole events table, which
-- made large imports quadratic.
CREATE INDEX ix_events_qid ON events(queue_id, host);
