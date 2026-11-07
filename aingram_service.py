"""AIngram service layer: policy-checked operations over the core.

The MCP server and the admin CLI both go through here. Every function takes
an open connection; writes run in one BEGIN IMMEDIATE transaction, so the
daily cap and the chain head are read and used atomically.

Ids may be given as a unique prefix of at least ID_PREFIX_MIN hex characters.
Responses use SHORT_ID characters, which keeps boot and recall cheap.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
from datetime import datetime, timezone

import admin_auth
import aingram_core as core
from aingram_policy import Policy, PolicyError, canonical_ctx, parse_policy

SHORT_ID = 12
ID_PREFIX_MIN = 8
PREFIX_RE = re.compile(r"^[0-9a-f]{%d,64}$" % ID_PREFIX_MIN)
SECRET_PREFIX = "aig_"
SECRET_RE = re.compile(r"^aig_[A-Za-z0-9_-]{43}$")
LAST_USED_RESOLUTION_S = 60
POLICY_APPROVE_PREFIX = '{"action":"policy.approve"'


class ServiceError(core.AIngramError):
    """A refusal or bad request. The message is safe to show the caller."""


def short(entry_id: str | None) -> str | None:
    return entry_id[:SHORT_ID] if entry_id else None


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def head(conn) -> dict:
    """The chain head, in every response. `id` is short for display; `id_full` is the exact
    entry hash, for anchoring a check (has anyone written since? is this the entry I saw?)."""
    seq, entry_id = core._head(conn)
    return {"seq": seq, "id": short(entry_id), "id_full": entry_id}


def resolve_id(conn, ref: str) -> str:
    """Full id for a full id or unique prefix."""
    if not isinstance(ref, str) or not PREFIX_RE.match(ref):
        raise ServiceError(f"ids are {ID_PREFIX_MIN}-64 lowercase hex characters")
    rows = conn.execute("SELECT id FROM entries WHERE id >= ? AND id < ? LIMIT 2",
                        (ref, ref + "g")).fetchall()
    if not rows:
        raise ServiceError(f"no entry {ref}")
    if len(rows) > 1:
        raise ServiceError(f"id prefix {ref} is ambiguous; give more characters")
    return rows[0]["id"]


def _entry(conn, entry_id: str):
    return conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()


# Live = not redacted and not retired by a later entry. Indexed (entries_supersedes).
LIVE = ("{t}.redacted_at IS NULL AND NOT EXISTS "
        "(SELECT 1 FROM entries s WHERE s.supersedes = {t}.id)")
SCAN_PAGE = 200
SCAN_MAX = 5000  # rows examined per recall, whatever the filters drop
RANK_POOL = 100  # most relevant query matches re-ranked by salience


def _visible(conn, policy: Policy, voice: str, ref: str):
    """The entry row for ref if this voice may read it. Unreadable and missing
    entries get the identical refusal, so nothing reveals what exists."""
    row = _entry(conn, resolve_id(conn, ref))
    if not policy.check_read(voice, row["subject"]):
        raise ServiceError(f"no entry {ref}")
    return row


def _readable_ids(conn, policy: Policy, voice: str, ids) -> list[str]:
    out = []
    for entry_id in ids:
        row = conn.execute("SELECT subject FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if row is not None and policy.check_read(voice, row["subject"]):
            out.append(short(entry_id))
    return out


# Imported entries carry their original date in entry_dates. Views show and order by it;
# the chain's ts (when the entry entered this log) is untouched.
DATES_JOIN = "LEFT JOIN entry_dates d ON d.entry_id = e.id"
WHEN = "COALESCE(d.dated || 'T00:00:00.000000Z', e.ts)"  # order by this, newest first


def _dated(row) -> str | None:
    return row["dated"] if "dated" in row.keys() else None


def _tail_item(row) -> dict:
    """A boot tail line. Every tail entry is the booting voice's own, so no voice field,
    and the day is enough to place it."""
    out = {"id": short(row["id"]), "subject": row["subject"], "kind": row["kind"],
           "date": _dated(row) or row["ts"][:10], "excerpt": row["excerpt"],
           "body_chars": len(row["body"] or "")}
    if row["untrusted_ctx"]:
        out["untrusted_ctx"] = row["untrusted_ctx"]
    return out


def _hit(row, faded: bool = False) -> dict:
    out = {"id": short(row["id"]), "subject": row["subject"], "kind": row["kind"],
           "ts": row["ts"][:19] + "Z", "voice": row["voice"], "excerpt": row["excerpt"]}
    if _dated(row):
        out["dated"] = _dated(row)  # originally written then; ts is when it entered this log
    if row["untrusted_ctx"]:
        out["untrusted_ctx"] = row["untrusted_ctx"]
    if faded:
        out["faded"] = True
    return out


# ---------------------------------------------------------------- keys

def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_secret(prefix: str = SECRET_PREFIX) -> str:
    return prefix + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def mint_key_in_tx(conn, voice: str, label: str) -> tuple[str, str]:
    """Create a bearer key. Returns (key_id, secret); only the secret's hash is stored."""
    if voice != "code":
        raise ServiceError("only code keys are minted here; the brain is granted by wallet sign-in")
    key_id = f"k_{voice}_{secrets.token_hex(4)}"
    secret = new_secret()
    core.add_key(conn, key_id=key_id, voice=voice, secret_hash=hash_secret(secret), label=label)
    return key_id, secret


def authenticate(conn, secret: str, now: datetime | None = None):
    """The key row for a bearer secret, or None if unknown, revoked, or not an MCP voice."""
    if not isinstance(secret, str) or not SECRET_RE.match(secret):
        return None
    row = conn.execute("SELECT * FROM keys WHERE secret_hash = ?", (hash_secret(secret),)).fetchone()
    if row is None or row["revoked_at"] is not None or row["voice"] not in ("brain", "code"):
        return None
    touch_key(conn, row["key_id"], now, row["last_used_at"])
    return row


_UNKNOWN = object()


def touch_key(conn, key_id: str, now: datetime | None = None, last=_UNKNOWN) -> None:
    """Record use, at most once per LAST_USED_RESOLUTION_S, so reads rarely take the write lock."""
    now = _now(now)
    if last is _UNKNOWN:
        row = conn.execute("SELECT last_used_at FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        last = row["last_used_at"] if row else None
    if last is None or (now - datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.%fZ")
                        .replace(tzinfo=timezone.utc)).total_seconds() > LAST_USED_RESOLUTION_S:
        conn.execute("UPDATE keys SET last_used_at = ? WHERE key_id = ?", (_iso(now), key_id))


ADMIN_KEY_ID = "k_admin"


def ensure_admin_key(conn, admin_address: str) -> str:
    """The key row admin redactions are recorded under. It has no secret, so it can never authenticate."""
    if conn.execute("SELECT 1 FROM keys WHERE key_id = ?", (ADMIN_KEY_ID,)).fetchone() is None:
        core.add_key(conn, key_id=ADMIN_KEY_ID, voice="admin", label=f"admin wallet {admin_address}")
    return ADMIN_KEY_ID


# ---------------------------------------------------------------- policy approval

def store_policy_version(conn, body: str) -> Policy:
    """Validate a policy text and keep it as a candidate for approval.
    Raises PolicyError if it is invalid; nothing is stored then."""
    if not isinstance(body, str):
        raise PolicyError("the policy must be text")
    policy = parse_policy(body.encode("utf-8"))
    conn.execute("INSERT OR IGNORE INTO policy_versions (sha256, body, added_at) VALUES (?,?,?)",
                 (policy.sha256, body, core.utc_now()))
    return policy


def policy_body(conn, sha256: str) -> str | None:
    row = conn.execute("SELECT body FROM policy_versions WHERE sha256 = ?", (sha256,)).fetchone()
    return row["body"] if row else None


def approved_policy_hash(conn, server_name: str, admin_address: str) -> str | None:
    """sha256 of the policy most recently approved by a signed policy.approve.

    Only signed rows count, and "most recent" is the signed Issued time, not row
    order: unsigned rows (done/failed events, log ids) are trivially insertable by
    anyone who can write the file, so they must not be able to pick an older
    approval. Every candidate signature is re-verified, and rows that are not signed
    by this admin for this server are ignored. None if nothing is approved."""
    best = None
    for row in conn.execute(
            "SELECT message, signature FROM admin_log WHERE event = 'authorized' AND action LIKE ?",
            (POLICY_APPROVE_PREFIX + "%",)):
        try:
            action = admin_auth.verify_logged(row["message"], row["signature"], server_name, admin_address)
        except admin_auth.AdminAuthError:
            # Signed for another server name or by another wallet (the admin address or public
            # URL changed): not an approval for this server. The server starts with none, and
            # the current admin approves again on the admin page.
            continue
        issued = admin_auth.parse_message(row["message"])["issued"]
        if best is None or issued > best[0]:
            best = (issued, action.get("sha256"))
    return best[1] if best else None


def policy_approval_marker(conn) -> int:
    """Changes whenever a new policy approval is logged; cheap to poll."""
    row = conn.execute("SELECT MAX(log_id) FROM admin_log WHERE event = 'authorized' AND action LIKE ?",
                       (POLICY_APPROVE_PREFIX + "%",)).fetchone()
    return row[0] or 0


def load_approved_policy(conn, server_name: str, admin_address: str) -> Policy | None:
    """The policy the admin wallet approved last, or None if none has been approved yet.
    Raises PolicyError if an approval does not verify or its text is missing or altered."""
    try:
        approved = approved_policy_hash(conn, server_name, admin_address)
    except admin_auth.AdminAuthError as e:
        raise PolicyError(f"policy approval in admin_log does not verify: {e}") from None
    if approved is None:
        return None
    body = policy_body(conn, approved)
    if body is None:
        raise PolicyError(f"approved policy {approved[:12]} is missing from policy_versions")
    policy = parse_policy(body.encode("utf-8"))
    if policy.sha256 != approved:
        raise PolicyError(f"stored text of policy {approved[:12]} does not match its approved hash")
    return policy


# ---------------------------------------------------------------- salience
# salience = 2^(-days since last reinforced / half-life). Entries with no
# half-life (pinned) never fade. An entry has faded once its salience is below
# policy.fade_below, which happens half-life * log2(1 / fade_below) days after
# its last reinforcement: that date is what SQL compares, so no custom
# function is needed.

def salience_of(last_reinforced_at: str | None, half_life_days: float | None, now: datetime) -> float:
    if not last_reinforced_at or half_life_days is None:
        return 1.0
    days = (now - datetime.strptime(last_reinforced_at, "%Y-%m-%dT%H:%M:%S.%fZ")
            .replace(tzinfo=timezone.utc)).total_seconds() / 86400
    return 2 ** (-max(days, 0.0) / half_life_days)


def fade_factor(policy: Policy) -> float:
    """Half-lives until an entry fades."""
    return math.log2(1 / policy.fade_below)


# Needs `LEFT JOIN salience s ON s.entry_id = e.id`; params (fade_factor, now).
NOT_FADED = ("(s.half_life_days IS NULL OR "
             "julianday(s.last_reinforced_at) + s.half_life_days * ? > julianday(?))")


def reinforce(conn, policy: Policy, entry_id: str, now: datetime | None = None) -> None:
    """Deliberate use: reset the clock and stretch the half-life, up to the cap."""
    conn.execute(
        """UPDATE salience SET last_reinforced_at = ?,
               half_life_days = MIN(half_life_days * ?, ?),
               reinforcements = reinforcements + 1
           WHERE entry_id = ? AND half_life_days IS NOT NULL""",
        (_iso(_now(now)), policy.reinforce_multiplier, policy.half_life_cap_days, entry_id))


# ---------------------------------------------------------------- write / redact

BODY_REQUIRED = ("Nothing written: body is required. The body is the memory and the excerpt is only "
                 "a clue to it. Put the full entry in body, then compress the excerpt from it.")
BODY_IS_EXCERPT = ("Written. Note: the body matches the excerpt exactly. That's fine for a one-line fact. "
                   "If there's more to it (ids, where to look, why it mattered), supersede this entry "
                   "with a fuller body.")
EXCERPT_TOO_LONG = ("Nothing written: excerpt is {n} characters; max {max}. Move the detail into the body. "
                    "The excerpt only needs to point at it.")

def write(conn, policy: Policy, key_id: str, *, subject: str, kind: str, excerpt: str,
          keywords=(), body: str = "", supersedes: str | None = None, refs=(),
          pinned: bool = False, untrusted_ctx: str | list[str] | None = None,
          now: datetime | None = None) -> dict:
    now = _now(now)
    keywords, refs = list(keywords or []), list(refs or [])
    untrusted_ctx, problem = canonical_ctx(untrusted_ctx)
    if problem:
        raise ServiceError(problem)
    if not isinstance(body, str) or not body.strip():
        raise ServiceError(BODY_REQUIRED)
    n = len(core.nfc(excerpt)) if isinstance(excerpt, str) else 0
    if n > core.EXCERPT_MAX:
        raise ServiceError(EXCERPT_TOO_LONG.format(n=n, max=core.EXCERPT_MAX))
    conn.execute("BEGIN IMMEDIATE")
    try:
        voice = core._voice_for(conn, key_id)
        for decision in (policy.check_write(voice, subject, kind, pinned, untrusted_ctx),
                         policy.check_content(excerpt, keywords, body, refs),
                         policy.check_cap(conn, voice, now)):
            if not decision:
                raise ServiceError(decision.reason)
        full_refs = []
        for ref in refs:
            full_refs.append(_visible(conn, policy, voice, ref)["id"])
        full_supersedes = None
        if supersedes:
            target = _visible(conn, policy, voice, supersedes)
            decision = policy.check_supersede(voice, subject, target)
            if not decision:
                raise ServiceError(decision.reason)
            full_supersedes = target["id"]
        result = core._append_in_tx(
            conn, key_id=key_id, subject=subject, kind=kind, excerpt=excerpt, keywords=keywords,
            body=body, supersedes=full_supersedes, refs=full_refs, pinned=pinned,
            untrusted_ctx=untrusted_ctx, ts=_iso(now),
            half_life_days=policy.half_life_for(kind, pinned))
        if "cited_in_refs" in policy.reinforced_by:
            for ref in set(full_refs):
                reinforce(conn, policy, ref, now)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    out = {"id": short(result["id"]), "seq": result["seq"], "head": head(conn)}
    if core.nfc(body).strip() == core.nfc(excerpt).strip():
        out["note"] = BODY_IS_EXCERPT
    return out


def redact(conn, policy: Policy, key_id: str, target: str, reason: str) -> dict:
    voice = core._voice_for(conn, key_id)
    row = _visible(conn, policy, voice, target)
    target_id = row["id"]
    decision = policy.check_redact(voice, row)
    if not decision:
        raise ServiceError(decision.reason)
    if not isinstance(reason, str) or not reason.strip():
        raise ServiceError("a redaction needs a reason")

    def within_cap(c):
        decision = policy.check_redact_cap(c, voice)
        if not decision:
            raise ServiceError(decision.reason)

    result = core.redact(conn, target_id=target_id, by_key_id=key_id, reason=reason, guard=within_cap)
    # Anything that leaned on the forgotten entry is flagged for review, never removed automatically.
    flagged = [r["id"] for r in conn.execute(
        """SELECT id FROM entries
           WHERE redacted_at IS NULL AND kind != 'redaction'
             AND (supersedes = ? OR refs LIKE ?) ORDER BY seq""",
        (target_id, f'%"{target_id}"%'))]
    return {"tombstone": short(result["tombstone"]),
            "flagged_for_review": _readable_ids(conn, policy, voice, flagged),
            "head": head(conn)}


# ---------------------------------------------------------------- read / recall

def read(conn, policy: Policy, voice: str, ref: str, now: datetime | None = None) -> dict:
    row = _visible(conn, policy, voice, ref)
    entry_id = row["id"]

    def link(target):  # shown only where it points at something this voice may read
        if target == core.GENESIS:
            return core.GENESIS  # the first entry's prev: the chain starts here, nothing is hidden
        return (_readable_ids(conn, policy, voice, [target]) or [None])[0] if target else None

    superseded_by = _readable_ids(conn, policy, voice, [r[0] for r in conn.execute(
        "SELECT id FROM entries WHERE supersedes = ? ORDER BY seq", (entry_id,))])
    out = {
        "id": entry_id, "seq": row["seq"], "ts": row["ts"], "voice": row["voice"],
        "key_id": row["key_id"], "subject": row["subject"], "kind": row["kind"],
        "pinned": bool(row["pinned"]), "untrusted_ctx": row["untrusted_ctx"],
        "dated": (conn.execute("SELECT dated FROM entry_dates WHERE entry_id = ?", (entry_id,)).fetchone() or [None])[0],
        "prev": link(row["prev_hash"]), "supersedes": link(row["supersedes"]),
        "superseded_by": superseded_by, "refs": _readable_ids(conn, policy, voice, json.loads(row["refs"])),
    }
    if row["redacted_at"] is not None:
        out.update(redacted_at=row["redacted_at"], excerpt=None, keywords=None, body=None)
    else:
        out.update(excerpt=row["excerpt"], keywords=json.loads(row["keywords"]), body=row["body"])
        s = conn.execute("SELECT * FROM salience WHERE entry_id = ?", (entry_id,)).fetchone()
        # Salience as it stood before this read; reading it is what reinforces it.
        out["salience"] = round(salience_of(s and s["last_reinforced_at"], s and s["half_life_days"],
                                            _now(now)), 2)
        if "read" in policy.reinforced_by:
            reinforce(conn, policy, entry_id, now)
    out["head"] = head(conn)
    return out


def _fts_query(query: str) -> str:
    """Treat the query as plain words: each becomes a quoted FTS5 term, so
    operators and stray quotes in user text can never be parsed as syntax."""
    words = re.findall(r"\w+", query)
    if not words:
        raise ServiceError("query has no searchable words")
    return " ".join('"' + w.replace('"', '""') + '"' for w in words[:32])


def recall(conn, policy: Policy, voice: str, *, subject: str | None = None, query: str | None = None,
           kind: str | None = None, limit: int = 10, now: datetime | None = None) -> dict:
    """Subject mode returns the folded state newest first, faded entries included
    (the fold is the truth about a subject). Query mode ranks full-text matches by
    relevance times salience, so faded entries sink. Faded hits are marked."""
    if (subject is None) == (query is None):
        raise ServiceError("give exactly one of subject or query")
    if not isinstance(limit, int) or limit < 1:
        raise ServiceError("limit must be a positive integer")
    now = _now(now)
    limit = min(limit, policy.limits["recall_max"])
    reserved = tuple(policy.reserved_kinds)
    live = f"{LIVE.format(t='e')} AND e.kind NOT IN ({','.join('?' * len(reserved))})"
    cols = "e.*, s.last_reinforced_at AS s_last, s.half_life_days AS s_hl, d.dated AS dated"
    if subject is not None:
        subtree = subject.endswith("/**")
        base = subject[:-3] if subtree else subject
        if subtree:
            where, args = "(e.subject = ? OR substr(e.subject, 1, ?) = ?)", (base, len(base) + 1, base + "/")
        else:
            where, args = "e.subject = ?", (base,)
        sql = (f"SELECT {cols} FROM entries e LEFT JOIN salience s ON s.entry_id = e.id {DATES_JOIN} "
               f"WHERE {where} AND {live}")
        order = f"{WHEN} DESC, e.seq DESC"
        mode, pool = "subject", limit
    else:
        sql = (f"SELECT {cols}, bm25(entries_fts) AS rank FROM entries_fts "
               f"JOIN entries e ON e.seq = entries_fts.rowid LEFT JOIN salience s ON s.entry_id = e.id {DATES_JOIN} "
               f"WHERE entries_fts MATCH ? AND {live}")
        args = (_fts_query(query),)
        order = "bm25(entries_fts)"
        # Rank a pool of the most relevant readable matches by relevance x salience.
        mode, pool = "query", max(limit, RANK_POOL)
    args = (*args, *reserved)
    if kind is not None:
        sql, args = sql + " AND e.kind = ?", (*args, kind)
    rows = []
    for offset in range(0, SCAN_MAX, SCAN_PAGE):
        page = conn.execute(f"{sql} ORDER BY {order} LIMIT {SCAN_PAGE} OFFSET {offset}", args).fetchall()
        rows += [r for r in page if policy.check_read(voice, r["subject"])]
        if len(rows) >= pool or len(page) < SCAN_PAGE:
            break
    scored = [(salience_of(r["s_last"], r["s_hl"], now), r) for r in rows[:pool]]
    if mode == "query":
        # bm25() is lower-is-better and negative for matches; -rank is the relevance.
        scored.sort(key=lambda sr: -sr[1]["rank"] * sr[0], reverse=True)
    hits = [_hit(r, faded=sal < policy.fade_below) for sal, r in scored[:limit]]
    return {"mode": mode, "hits": hits, "head": head(conn)}


# ---------------------------------------------------------------- boot

def boot(conn, policy: Policy, voice: str, now: datetime | None = None) -> dict:
    now = _now(now)
    tail_n = policy.boot["recent_tail"]
    reserved = tuple(policy.reserved_kinds)
    live = f"{LIVE.format(t='e')} AND e.kind NOT IN ({','.join('?' * len(reserved))})"
    out: dict = {"voice": voice}

    if voice == "brain":
        state = conn.execute("SELECT last_boot_seq FROM voice_state WHERE voice = 'brain'").fetchone()
        since = (state["last_boot_seq"] if state else None) or 0
        out["core"] = [{"id": short(r["id"]), "subject": r["subject"], "excerpt": r["excerpt"]}
                       for r in conn.execute(
                           f"SELECT e.* FROM entries e WHERE e.voice = 'brain' AND e.pinned = 1 AND {live} "
                           f"ORDER BY e.seq", reserved)]
        # Faded entries drop out of the tail; they stay in the log and in recall.
        out["recent"] = [_tail_item(r) for r in conn.execute(
            f"SELECT e.*, d.dated AS dated FROM entries e LEFT JOIN salience s ON s.entry_id = e.id {DATES_JOIN} "
            f"WHERE e.voice = 'brain' AND e.pinned = 0 AND {live} AND {NOT_FADED} "
            f"ORDER BY {WHEN} DESC, e.seq DESC LIMIT ?", (*reserved, fade_factor(policy), _iso(now), tail_n))]
        out["code_digest"] = _digest(conn, since)
        if policy.boot["redaction_notice"]:
            n = conn.execute("SELECT COUNT(*) FROM entries WHERE kind = 'redaction' AND seq > ?",
                             (since,)).fetchone()[0]
            if n:
                out["redactions"] = f"{n} entr{'y' if n == 1 else 'ies'} redacted since you last woke"
        last_seq, _ = core._head(conn)
        conn.execute(
            """INSERT INTO voice_state (voice, last_boot_at, last_boot_seq) VALUES ('brain', ?, ?)
               ON CONFLICT(voice) DO UPDATE SET last_boot_at = excluded.last_boot_at,
                                                last_boot_seq = excluded.last_boot_seq""",
            (_iso(now), last_seq))
    else:
        out["recent"] = [_tail_item(r) for r in conn.execute(
            f"SELECT e.*, d.dated AS dated FROM entries e LEFT JOIN salience s ON s.entry_id = e.id {DATES_JOIN} "
            f"WHERE e.voice = ? AND {live} AND {NOT_FADED} ORDER BY {WHEN} DESC, e.seq DESC LIMIT ?",
            (voice, *reserved, fade_factor(policy), _iso(now), tail_n))]

    out["writes_left_today"] = policy.headroom(conn, voice, now)
    out["head"] = head(conn)
    return fit_budget(out, policy.boot["token_budget"])


# The server runs no model, so tokens are estimated from the compact JSON the
# client receives. 3.5 characters per token errs on the side of a smaller boot.
CHARS_PER_TOKEN = 3.5


def estimate_tokens(obj) -> int:
    return math.ceil(len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False)) / CHARS_PER_TOKEN)


def fit_budget(out: dict, budget: int) -> dict:
    """The core is the self: boot never drops or trims any part of it. Notices (the
    redaction notice, the Code digest) always stay too. Only the recent tail gives way,
    oldest first, and it may go to zero; `shed` counts what was dropped.

    If the core and notices alone are over budget, boot returns them whole anyway, with an
    empty tail and a core_over_budget warning: a signal to consolidate pinned entries,
    not something to shed at wake-up. The response may exceed the budget then, by design."""
    dropped = 0

    def over() -> bool:
        if dropped:
            out["shed"] = {"tail_dropped": dropped}
        return estimate_tokens(out) > budget

    while over() and out.get("recent"):
        out["recent"].pop()  # newest first, so this drops the oldest
        dropped += 1
    if over():
        core = out.get("core", [])
        out["warnings"] = [{
            "code": "core_over_budget", "core_tokens": estimate_tokens(core), "budget": budget,
            "core_entries": len(core), "message": "Core exceeds boot budget; consolidate pinned entries."}]
    return out


def _digest(conn, since: int) -> str:
    """One line about the code voice's entries since the brain's last boot, counted in SQL."""
    groups = conn.execute(
        """SELECT CASE WHEN instr(subject, '/') > 0 THEN substr(subject, 1, instr(subject, '/') - 1)
                       ELSE subject END AS top, COUNT(*) AS n
           FROM entries WHERE voice = 'code' AND seq > ? GROUP BY top ORDER BY n DESC, top""",
        (since,)).fetchall()
    n = sum(g["n"] for g in groups)
    if not n:
        return "Code logged nothing since you last woke."
    parts = ", ".join(f"{g['top']} ×{g['n']}" for g in groups)
    latest = [short(r[0]) for r in conn.execute(
        "SELECT id FROM entries WHERE voice = 'code' AND seq > ? ORDER BY seq DESC LIMIT 10", (since,))]
    more = f" (latest 10 of {n})" if n > 10 else ""
    return (f"Code logged {n} entr{'y' if n == 1 else 'ies'} since you last woke: {parts}. "
            f"Ids{more}: {' '.join(reversed(latest))}")
