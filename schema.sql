-- AIngram schema, version 1
-- The schema enforces integrity (append-only, chain order, redaction shape).
-- Permissions (which voice may write what) live in policy.yaml, not here.
-- Hashes are computed by the application (SQLite has no SHA-256); verify.py
-- re-derives every hash from stored data.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '1');

-- Credentials. A key is not a voice: the voice is fixed per key, and entries
-- record both, so keys can rotate without breaking provenance.
-- secret_hash is NULL for OAuth/SIWE grants (tokens live in a later table).
CREATE TABLE IF NOT EXISTS keys (
    key_id       TEXT PRIMARY KEY,
    voice        TEXT NOT NULL CHECK (voice IN ('brain', 'code', 'admin')),
    secret_hash  TEXT UNIQUE,
    label        TEXT,
    created_at   TEXT NOT NULL,
    revoked_at   TEXT,
    last_used_at TEXT
);

CREATE TRIGGER IF NOT EXISTS keys_no_delete BEFORE DELETE ON keys
BEGIN
    SELECT RAISE(ABORT, 'keys are never deleted; revoke instead');
END;

CREATE TRIGGER IF NOT EXISTS keys_update_guard BEFORE UPDATE ON keys
WHEN NOT (
        NEW.key_id = OLD.key_id
    AND NEW.voice = OLD.voice
    AND NEW.secret_hash IS OLD.secret_hash
    AND NEW.created_at = OLD.created_at
    AND (OLD.revoked_at IS NULL OR NEW.revoked_at IS OLD.revoked_at)
)
BEGIN
    SELECT RAISE(ABORT, 'only revoked_at (once), last_used_at and label may change on a key');
END;

-- The log. seq is the rowid; id is the entry hash.
-- Header fields (hashed into id): seq, prev_hash, ts, voice, key_id, subject,
--   kind, supersedes, refs, pinned, untrusted_ctx, content_hash.
-- Content fields (hashed into content_hash): excerpt, keywords, body, salt.
-- Redaction nulls the content fields (salt included) and sets redacted_at.
CREATE TABLE IF NOT EXISTS entries (
    seq           INTEGER PRIMARY KEY,
    id            TEXT NOT NULL UNIQUE CHECK (length(id) = 64),
    prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
    ts            TEXT NOT NULL,
    voice         TEXT NOT NULL CHECK (voice IN ('brain', 'code', 'admin')),
    key_id        TEXT NOT NULL REFERENCES keys(key_id),
    subject       TEXT NOT NULL CHECK (length(subject) > 0),
    kind          TEXT NOT NULL CHECK (length(kind) > 0),
    supersedes    TEXT REFERENCES entries(id),
    refs          TEXT NOT NULL DEFAULT '[]',
    pinned        INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    untrusted_ctx TEXT,
    content_hash  TEXT NOT NULL CHECK (length(content_hash) = 64),
    excerpt       TEXT CHECK (length(excerpt) <= 300),
    keywords      TEXT,
    body          TEXT,
    salt          TEXT,
    redacted_at   TEXT,
    CHECK (
        (redacted_at IS NULL
            AND excerpt IS NOT NULL AND keywords IS NOT NULL
            AND body IS NOT NULL AND salt IS NOT NULL)
        OR
        (redacted_at IS NOT NULL
            AND excerpt IS NULL AND keywords IS NULL
            AND body IS NULL AND salt IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS entries_subject    ON entries (subject, seq);
CREATE INDEX IF NOT EXISTS entries_voice_ts   ON entries (voice, ts);
CREATE INDEX IF NOT EXISTS entries_kind       ON entries (kind, seq);
CREATE INDEX IF NOT EXISTS entries_supersedes ON entries (supersedes);
CREATE INDEX IF NOT EXISTS entries_key_ts     ON entries (key_id, ts);

-- Chain order is enforced in the database, not only in the app:
-- a new entry must be the next seq and must point at the current head.
CREATE TRIGGER IF NOT EXISTS entries_chain BEFORE INSERT ON entries
BEGIN
    SELECT RAISE(ABORT, 'seq must be the next in sequence')
        WHERE NEW.seq != COALESCE((SELECT MAX(seq) FROM entries), 0) + 1;
    SELECT RAISE(ABORT, 'prev_hash must equal the current head')
        WHERE NEW.prev_hash != COALESCE(
            (SELECT id FROM entries ORDER BY seq DESC LIMIT 1),
            '0000000000000000000000000000000000000000000000000000000000000000');
    SELECT RAISE(ABORT, 'an entry cannot be born redacted')
        WHERE NEW.redacted_at IS NOT NULL;
END;

CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
BEGIN
    SELECT RAISE(ABORT, 'entries are append-only; redact instead');
END;

-- The only permitted update: redaction. Every header field stays identical,
-- all content fields become NULL, redacted_at goes from NULL to a value.
CREATE TRIGGER IF NOT EXISTS entries_update_guard BEFORE UPDATE ON entries
WHEN NOT (
        OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL
    AND NEW.excerpt IS NULL AND NEW.keywords IS NULL
    AND NEW.body IS NULL AND NEW.salt IS NULL
    AND NEW.seq = OLD.seq AND NEW.id = OLD.id
    AND NEW.prev_hash = OLD.prev_hash AND NEW.ts = OLD.ts
    AND NEW.voice = OLD.voice AND NEW.key_id = OLD.key_id
    AND NEW.subject = OLD.subject AND NEW.kind = OLD.kind
    AND NEW.supersedes IS OLD.supersedes AND NEW.refs = OLD.refs
    AND NEW.pinned = OLD.pinned AND NEW.untrusted_ctx IS OLD.untrusted_ctx
    AND NEW.content_hash = OLD.content_hash
)
BEGIN
    SELECT RAISE(ABORT, 'entries are append-only; the only update allowed is redaction');
END;

-- Full-text search over live content. Redacted entries leave the index.
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    subject, excerpt, keywords, body,
    content = 'entries', content_rowid = 'seq'
);

CREATE TRIGGER IF NOT EXISTS entries_fts_insert AFTER INSERT ON entries
BEGIN
    INSERT INTO entries_fts (rowid, subject, excerpt, keywords, body)
    VALUES (NEW.seq, NEW.subject, NEW.excerpt, NEW.keywords, NEW.body);
END;

CREATE TRIGGER IF NOT EXISTS entries_fts_redact AFTER UPDATE ON entries
BEGIN
    INSERT INTO entries_fts (entries_fts, rowid, subject, excerpt, keywords, body)
    VALUES ('delete', OLD.seq, OLD.subject, OLD.excerpt, OLD.keywords, OLD.body);
END;

-- Redaction reasons: admin-only. Kept out of the chain on purpose,
-- because a reason can leak what was forgotten.
CREATE TABLE IF NOT EXISTS redactions (
    entry_id     TEXT PRIMARY KEY REFERENCES entries(id),
    tombstone_id TEXT NOT NULL UNIQUE REFERENCES entries(id),
    redacted_at  TEXT NOT NULL,
    by_key       TEXT NOT NULL REFERENCES keys(key_id),
    reason       TEXT NOT NULL CHECK (length(reason) > 0)
);

-- Salience: mutable decay state, deliberately outside the chain.
-- half_life_days NULL = never decays (pinned).
CREATE TABLE IF NOT EXISTS salience (
    entry_id           TEXT PRIMARY KEY REFERENCES entries(id),
    last_reinforced_at TEXT NOT NULL,
    half_life_days     REAL CHECK (half_life_days IS NULL OR half_life_days > 0),
    reinforcements     INTEGER NOT NULL DEFAULT 0
);

-- Per-voice boot bookkeeping ("since you last woke").
CREATE TABLE IF NOT EXISTS voice_state (
    voice         TEXT PRIMARY KEY CHECK (voice IN ('brain', 'code', 'admin')),
    last_boot_at  TEXT,
    last_boot_seq INTEGER
);

-- Signed admin commands. Authority is the admin wallet, not shell access:
-- every admin action needs a fresh nonce issued by the box and a signature
-- from the admin address (AINGRAM_ADMIN_ADDRESS).
CREATE TABLE IF NOT EXISTS admin_nonces (
    nonce      TEXT PRIMARY KEY,
    issued_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

-- Append-only audit trail: the exact signed message and signature are kept,
-- so every admin action is independently checkable later.
CREATE TABLE IF NOT EXISTS admin_log (
    log_id    INTEGER PRIMARY KEY,
    at        TEXT NOT NULL,
    event     TEXT NOT NULL CHECK (event IN ('authorized', 'done', 'failed')),
    nonce     TEXT NOT NULL REFERENCES admin_nonces(nonce),
    action    TEXT NOT NULL,
    signer    TEXT,
    message   TEXT,
    signature TEXT,
    detail    TEXT
);

CREATE TRIGGER IF NOT EXISTS admin_log_no_delete BEFORE DELETE ON admin_log
BEGIN
    SELECT RAISE(ABORT, 'admin_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS admin_log_no_update BEFORE UPDATE ON admin_log
BEGIN
    SELECT RAISE(ABORT, 'admin_log is append-only');
END;

-- Admin web sessions, opened by a wallet sign-in. Only the token's hash is
-- kept. A session lets the admin look; every change still needs a signed
-- command. Sessions end by stamping ended_at; rows are never deleted.
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash   TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    address      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    ended_at     TEXT
);

CREATE TRIGGER IF NOT EXISTS admin_sessions_no_delete BEFORE DELETE ON admin_sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions are ended, never deleted');
END;

-- Policy texts, keyed by the sha256 of their UTF-8 bytes. A row here is only a
-- candidate: the policy in force is the one a signed policy.approve names, and
-- the loader recomputes the hash, so a swapped body is refused.
CREATE TABLE IF NOT EXISTS policy_versions (
    sha256   TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    body     TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS policy_versions_no_delete BEFORE DELETE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy_versions is append-only');
END;

CREATE TRIGGER IF NOT EXISTS policy_versions_no_update BEFORE UPDATE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy_versions is append-only');
END;

-- OAuth clients registered dynamically (RFC 7591), such as claude.ai's connector.
-- Registration alone grants nothing: a voice is granted only when the admin
-- wallet signs an approval, which creates a key row for that grant. Anyone can
-- register, so only trimmed metadata is kept, and registrations that never led
-- to a token are pruned. A client that was ever issued a token is kept for good.
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id  TEXT PRIMARY KEY,
    info       TEXT NOT NULL,   -- the trimmed client metadata, as JSON
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_clients_created ON oauth_clients (created_at);

CREATE TRIGGER IF NOT EXISTS oauth_clients_keep_used BEFORE DELETE ON oauth_clients
WHEN EXISTS (SELECT 1 FROM oauth_tokens WHERE client_id = OLD.client_id)
BEGIN
    SELECT RAISE(ABORT, 'a client that was issued tokens is never deleted');
END;

-- OAuth access and refresh tokens. Only their hashes are kept. Each belongs to
-- a grant's key row, so revoking the key cuts every token issued under it.
-- Tokens end by stamping revoked_at; rows are never deleted.
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    key_id     TEXT NOT NULL REFERENCES keys(key_id),
    client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id),
    scopes     TEXT NOT NULL,
    resource   TEXT,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,   -- unix seconds
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS oauth_tokens_key ON oauth_tokens (key_id);
CREATE INDEX IF NOT EXISTS oauth_tokens_client ON oauth_tokens (client_id);

CREATE TRIGGER IF NOT EXISTS oauth_tokens_no_delete BEFORE DELETE ON oauth_tokens
BEGIN
    SELECT RAISE(ABORT, 'tokens are revoked, never deleted');
END;

-- Backup tokens: read-only credentials for the nightly export, used by a job
-- off the server. They reach only /backup/*, never MCP or the admin API.
-- Created and revoked by signed admin commands; only the hash is kept.
CREATE TABLE IF NOT EXISTS backup_tokens (
    token_id     TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    label        TEXT,
    created_at   TEXT NOT NULL,
    revoked_at   TEXT,
    last_used_at TEXT
);

CREATE TRIGGER IF NOT EXISTS backup_tokens_no_delete BEFORE DELETE ON backup_tokens
BEGIN
    SELECT RAISE(ABORT, 'backup tokens are revoked, never deleted');
END;

CREATE TRIGGER IF NOT EXISTS backup_tokens_update_guard BEFORE UPDATE ON backup_tokens
WHEN NOT (NEW.token_id = OLD.token_id AND NEW.token_hash = OLD.token_hash
          AND NEW.created_at = OLD.created_at
          AND (OLD.revoked_at IS NULL OR NEW.revoked_at IS OLD.revoked_at))
BEGIN
    SELECT RAISE(ABORT, 'only revoked_at (once), last_used_at and label may change on a backup token');
END;

CREATE TRIGGER IF NOT EXISTS oauth_tokens_update_guard BEFORE UPDATE ON oauth_tokens
WHEN NOT (NEW.token_hash = OLD.token_hash AND NEW.kind = OLD.kind AND NEW.key_id = OLD.key_id
          AND NEW.client_id = OLD.client_id AND NEW.expires_at = OLD.expires_at
          AND OLD.revoked_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'only revoked_at may change on a token, once');
END;
