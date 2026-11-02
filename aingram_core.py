"""AIngram core: canonical hashing, append, redact, verify.

This module is the hashing contract. The server, the admin tools and any
future reimplementation must produce byte-identical canonical encodings and
hashes; vectors.json is the proof. Change nothing here without bumping V,
regenerating vectors, and telling the brain.

No policy lives here. Who may write what is checked by the policy layer
before these functions are called. This layer enforces integrity only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

V = 1  # hashing/schema version, hashed into every header and content object
GENESIS = "0" * 64
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SALT_RE = re.compile(r"^[0-9a-f]{32}$")
EXCERPT_MAX = 300
MAX_SAFE_INT = 2**53 - 1
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class AIngramError(Exception):
    pass


class CanonicalError(AIngramError, ValueError):
    pass


# ---------------------------------------------------------------- canonical

def _norm(x, path: str = "$"):
    """Restrict to the JSON subset we hash, NFC-normalising every string.

    Allowed: null, bool, int within +/-(2^53-1), str, list, dict with ASCII
    string keys. Floats are refused: they have no single canonical spelling.
    """
    if x is None or isinstance(x, bool):
        return x
    if isinstance(x, int):
        if abs(x) > MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer outside safe range")
        return x
    if isinstance(x, str):
        return unicodedata.normalize("NFC", x)
    if isinstance(x, (list, tuple)):
        return [_norm(v, f"{path}[{i}]") for i, v in enumerate(x)]
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            if not isinstance(k, str) or not k.isascii():
                raise CanonicalError(f"{path}: keys must be ASCII strings")
            out[k] = _norm(v, f"{path}.{k}")
        return out
    raise CanonicalError(f"{path}: unsupported type {type(x).__name__}")


def canonical(obj) -> bytes:
    """UTF-8 JSON, keys sorted by code point, no whitespace, no ASCII escaping.

    For the subset _norm allows, this matches RFC 8785 (JCS) output.
    """
    return json.dumps(
        _norm(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def normalize_keywords(keywords: Iterable[str]) -> list[str]:
    """NFC, trim, drop empties, dedupe, sort. Order of input never matters."""
    return sorted({nfc(k).strip() for k in keywords if nfc(k).strip()})


def normalize_refs(refs: Iterable[str]) -> list[str]:
    out = sorted(set(refs))
    for r in out:
        if not HEX64.match(r):
            raise AIngramError(f"bad ref id: {r!r}")
    return out


def content_object(excerpt: str, keywords: list[str], body: str, salt: str) -> dict:
    return {"v": V, "excerpt": excerpt, "keywords": keywords, "body": body, "salt": salt}


def header_object(*, seq, prev_hash, ts, voice, key_id, subject, kind,
                  supersedes, refs, pinned, untrusted_ctx, content_hash) -> dict:
    return {
        "v": V,
        "seq": seq,
        "prev_hash": prev_hash,
        "ts": ts,
        "voice": voice,
        "key_id": key_id,
        "subject": subject,
        "kind": kind,
        "supersedes": supersedes,
        "refs": refs,
        "pinned": bool(pinned),
        "untrusted_ctx": untrusted_ctx,
        "content_hash": content_hash,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_salt() -> str:
    return os.urandom(16).hex()


# ---------------------------------------------------------------- storage

def connect(path: str | os.PathLike) -> sqlite3.Connection:
    """Open (and initialise) a store. Autocommit mode; we manage transactions."""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    # Freed pages are zeroed, so redacted content does not linger in the file.
    conn.execute("PRAGMA secure_delete = ON")
    # The schema script takes the write lock; run it only on a store that lacks
    # it (its last statement creates policy_versions_no_update), not on every connect.
    initialised = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'policy_versions_no_update'").fetchone()
    if initialised is None:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def add_key(conn, *, key_id: str, voice: str, secret_hash: str | None = None,
            label: str | None = None, created_at: str | None = None) -> None:
    conn.execute(
        "INSERT INTO keys (key_id, voice, secret_hash, label, created_at) VALUES (?,?,?,?,?)",
        (key_id, voice, secret_hash, label, created_at or utc_now()),
    )


def revoke_key(conn, key_id: str, at: str | None = None) -> None:
    conn.execute("UPDATE keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                 (at or utc_now(), key_id))


def _head(conn) -> tuple[int, str]:
    row = conn.execute("SELECT seq, id FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
    return (row["seq"], row["id"]) if row else (0, GENESIS)


def _voice_for(conn, key_id: str) -> str:
    row = conn.execute("SELECT voice, revoked_at FROM keys WHERE key_id = ?", (key_id,)).fetchone()
    if row is None:
        raise AIngramError(f"unknown key {key_id!r}")
    if row["revoked_at"] is not None:
        raise AIngramError(f"key {key_id!r} is revoked")
    return row["voice"]


def _append_in_tx(conn, *, key_id, subject, kind, excerpt, keywords, body,
                  supersedes=None, refs=(), pinned=False, untrusted_ctx=None,
                  ts=None, salt=None, half_life_days=None) -> dict:
    voice = _voice_for(conn, key_id)  # voice comes from the key, never the caller
    ts = ts or utc_now()
    if not TS_RE.match(ts):
        raise AIngramError(f"bad timestamp {ts!r}")
    salt = salt or new_salt()
    if not SALT_RE.match(salt):
        raise AIngramError("salt must be 32 lowercase hex characters")

    subject, kind, excerpt, body = nfc(subject), nfc(kind), nfc(excerpt), nfc(body)
    untrusted_ctx = nfc(untrusted_ctx) if untrusted_ctx is not None else None
    if not subject or not kind:
        raise AIngramError("subject and kind are required")
    if len(excerpt) > EXCERPT_MAX:
        raise AIngramError(f"excerpt is {len(excerpt)} characters; max {EXCERPT_MAX}")
    kw = normalize_keywords(keywords)
    rf = normalize_refs(refs)
    for target in rf + ([supersedes] if supersedes else []):
        if conn.execute("SELECT 1 FROM entries WHERE id = ?", (target,)).fetchone() is None:
            raise AIngramError(f"referenced entry {target} does not exist")

    content_hash = sha256_hex(canonical(content_object(excerpt, kw, body, salt)))
    last_seq, prev_hash = _head(conn)
    seq = last_seq + 1
    header = header_object(seq=seq, prev_hash=prev_hash, ts=ts, voice=voice, key_id=key_id,
                           subject=subject, kind=kind, supersedes=supersedes, refs=rf,
                           pinned=pinned, untrusted_ctx=untrusted_ctx,
                           content_hash=content_hash)
    entry_id = sha256_hex(canonical(header))

    conn.execute(
        """INSERT INTO entries (seq, id, prev_hash, ts, voice, key_id, subject, kind,
               supersedes, refs, pinned, untrusted_ctx, content_hash,
               excerpt, keywords, body, salt)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (seq, entry_id, prev_hash, ts, voice, key_id, subject, kind, supersedes,
         canonical(rf).decode(), int(bool(pinned)), untrusted_ctx, content_hash,
         excerpt, canonical(kw).decode(), body, salt),
    )
    conn.execute(
        "INSERT INTO salience (entry_id, last_reinforced_at, half_life_days) VALUES (?,?,?)",
        (entry_id, ts, None if pinned else half_life_days),
    )
    conn.execute("UPDATE keys SET last_used_at = ? WHERE key_id = ?", (ts, key_id))
    return {"id": entry_id, "seq": seq, "voice": voice, "ts": ts}


def append(conn, **kw) -> dict:
    """Append one entry. Serialised with BEGIN IMMEDIATE so concurrent writers queue."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        result = _append_in_tx(conn, **kw)
        conn.execute("COMMIT")
        return result
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def redact(conn, *, target_id: str, by_key_id: str, reason: str, ts: str | None = None,
           salt: str | None = None) -> dict:
    """Forget an entry's content. Appends a tombstone, nulls the content,
    records the reason in the admin-only table. One transaction."""
    if not reason or not reason.strip():
        raise AIngramError("a redaction needs a reason")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT redacted_at FROM entries WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            raise AIngramError(f"no entry {target_id}")
        if row["redacted_at"] is not None:
            raise AIngramError(f"entry {target_id} is already redacted")
        tomb = _append_in_tx(conn, key_id=by_key_id, subject="_redactions", kind="redaction",
                             excerpt="Redacted an entry.", keywords=[], body="",
                             refs=[target_id], ts=ts, salt=salt)
        conn.execute(
            """UPDATE entries SET excerpt = NULL, keywords = NULL, body = NULL,
                   salt = NULL, redacted_at = ? WHERE id = ?""",
            (tomb["ts"], target_id),
        )
        conn.execute(
            "INSERT INTO redactions (entry_id, tombstone_id, redacted_at, by_key, reason) VALUES (?,?,?,?,?)",
            (target_id, tomb["id"], tomb["ts"], by_key_id, reason.strip()),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    # Forgetting means gone from disk too: merge the full-text index so the old
    # terms leave its shadow tables, then fold the WAL (which still holds the
    # pre-redaction pages) back into the zeroed main file.
    conn.execute("INSERT INTO entries_fts (entries_fts) VALUES ('optimize')")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return {"tombstone": tomb["id"], "redacted": target_id}


# ---------------------------------------------------------------- verify

ENTRY_COLUMNS = ("seq", "id", "prev_hash", "ts", "voice", "key_id", "subject", "kind",
                 "supersedes", "refs", "pinned", "untrusted_ctx", "content_hash",
                 "excerpt", "keywords", "body", "salt", "redacted_at")
HEADER_COLUMNS = ENTRY_COLUMNS[:13]


def verify_records(entries: list[dict], redactions: dict[str, dict]) -> list[str]:
    """Verify a chain given as plain records (from the database or an export).

    entries: dicts with ENTRY_COLUMNS, in any order. redactions: entry_id -> record
    with at least tombstone_id. Returns a list of problems; empty means it verifies.
    """
    problems: list[str] = []
    expected_prev, expected_seq = GENESIS, 1
    by_id = {e["id"]: e for e in entries}
    for e in sorted(entries, key=lambda r: r["seq"]):
        tag = f"seq {e['seq']}"
        if e["seq"] != expected_seq:
            problems.append(f"{tag}: expected seq {expected_seq}")
        if e["prev_hash"] != expected_prev:
            problems.append(f"{tag}: prev_hash does not match previous entry")
        if e["redacted_at"] is None:
            content = content_object(e["excerpt"], json.loads(e["keywords"]), e["body"], e["salt"])
            if sha256_hex(canonical(content)) != e["content_hash"]:
                problems.append(f"{tag}: content does not match content_hash")
            if e["id"] in redactions:
                problems.append(f"{tag}: has a redaction record but content is present")
        else:
            rec = redactions.get(e["id"])
            if rec is None:
                problems.append(f"{tag}: redacted without a redaction record")
            else:
                tomb = by_id.get(rec["tombstone_id"])
                if tomb is None or tomb["kind"] != "redaction" or json.loads(tomb["refs"]) != [e["id"]]:
                    problems.append(f"{tag}: redaction record has no matching tombstone")
        header = header_object(
            seq=e["seq"], prev_hash=e["prev_hash"], ts=e["ts"], voice=e["voice"],
            key_id=e["key_id"], subject=e["subject"], kind=e["kind"],
            supersedes=e["supersedes"], refs=json.loads(e["refs"]), pinned=e["pinned"],
            untrusted_ctx=e["untrusted_ctx"], content_hash=e["content_hash"])
        if sha256_hex(canonical(header)) != e["id"]:
            problems.append(f"{tag}: header does not match id")
        expected_prev, expected_seq = e["id"], e["seq"] + 1
    return problems


def _db_records(conn) -> tuple[list[dict], dict[str, dict]]:
    entries = [dict(r) for r in conn.execute("SELECT * FROM entries ORDER BY seq")]
    redactions = {r["entry_id"]: {"entry_id": r["entry_id"], "tombstone_id": r["tombstone_id"],
                                  "redacted_at": r["redacted_at"], "by_key": r["by_key"]}
                  for r in conn.execute("SELECT * FROM redactions")}
    return entries, redactions


def verify(conn) -> list[str]:
    """Walk the whole chain in the database."""
    return verify_records(*_db_records(conn))


# ---------------------------------------------------------------- export

def export_jsonl(conn, path: str | os.PathLike) -> str:
    """Write the log as JSONL: one line per entry, then one per redaction.
    Redaction reasons are NOT exported; they stay admin-only on the box.
    Returns the chain head id. Written to a temp file and renamed, so a
    half-written export never replaces a good one."""
    conn.execute("BEGIN")  # one consistent snapshot
    try:
        entries, redactions = _db_records(conn)
    finally:
        conn.execute("COMMIT")
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps({"type": "entry", **e}, ensure_ascii=True, sort_keys=True) + "\n")
        for r in redactions.values():
            f.write(json.dumps({"type": "redaction", **r}, ensure_ascii=True, sort_keys=True) + "\n")
    os.replace(tmp, path)
    return entries[-1]["id"] if entries else GENESIS


def load_jsonl(path: str | os.PathLike) -> tuple[list[dict], dict[str, dict]]:
    entries, redactions = [], {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            kind = rec.pop("type")
            if kind == "entry":
                entries.append(rec)
            elif kind == "redaction":
                redactions[rec["entry_id"]] = rec
            else:
                raise AIngramError(f"unknown record type {kind!r}")
    return entries, redactions


def check_extends(old_path, new_path) -> list[str]:
    """The off-box check, run on the operator's own machine after each nightly pull.

    Passes only if the new export verifies on its own AND extends the old one:
    every old entry is still present at the same seq with an identical header,
    old content is unchanged unless it was redacted (with a tombstone) since,
    and no redaction recorded in the old export has disappeared.
    A rewritten, truncated or forked history fails.
    """
    old_entries, old_red = load_jsonl(old_path)
    new_entries, new_red = load_jsonl(new_path)
    problems = [f"new export: {p}" for p in verify_records(new_entries, new_red)]
    new_by_seq = {e["seq"]: e for e in new_entries}
    for o in old_entries:
        n = new_by_seq.get(o["seq"])
        if n is None:
            problems.append(f"seq {o['seq']}: missing from new export (history truncated)")
            continue
        if any(o[c] != n[c] for c in HEADER_COLUMNS):
            problems.append(f"seq {o['seq']}: header changed (history rewritten)")
            continue
        if o["redacted_at"] is None and n["redacted_at"] is None:
            if any(o[c] != n[c] for c in ("excerpt", "keywords", "body", "salt")):
                problems.append(f"seq {o['seq']}: content changed without redaction")
        elif o["redacted_at"] is not None and n["redacted_at"] is None:
            problems.append(f"seq {o['seq']}: redacted content reappeared")
    for entry_id in old_red:
        if entry_id not in new_red:
            problems.append(f"redaction of {entry_id[:12]}: record disappeared")
    return problems


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if len(args) == 1:
        issues = verify(connect(args[0]))
        ok_msg = "chain verifies"
    elif len(args) == 3 and args[0] == "extends":
        issues = check_extends(args[1], args[2])
        ok_msg = "new export verifies and extends the old one"
    else:
        sys.exit("usage: python aingram_core.py <store.db>              verify the store\n"
                 "       python aingram_core.py extends <old> <new>    off-box nightly check")
    print(ok_msg if not issues else "\n".join(issues))
    sys.exit(1 if issues else 0)
