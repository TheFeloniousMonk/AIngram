"""AIngram admin operations, and a read-only CLI for scripts and the nightly export.

The admin works through the web page at /admin (aingram_web.py). Signing in
with the admin wallet opens a session that can look at everything. Every
change is a signed command: the page asks the server to prepare() it, the
wallet shows the admin the exact message and signs it, and confirm() checks
the signature, performs exactly the signed action and logs the outcome.
A refused signature changes nothing.

The CLI never changes anything and needs no signature:
    keys list | verify | export --out FILE | policy status
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import secrets
import sys
import threading
import unicodedata
from datetime import datetime, timedelta, timezone

import admin_auth
import aingram_core as core
import aingram_service as svc
from aingram_config import ConfigError, Settings, load_env
from aingram_policy import Policy, PolicyError, canonical_ctx

LIST_MAX = 100
SUBJECTS_MAX = 1000
LABEL_MAX = 80
REASON_MAX = 500


class Refused(Exception):
    """The admin asked for something that can't be done. Safe to show."""


class Drafts:
    """Text waiting for a signature, held in memory: one policy draft and one import.

    Unsigned text never reaches the database, so a stolen session can't fill
    append-only tables with it. Preparing a new draft of a kind replaces the old
    one, so an older, still-unsigned command can't land after a newer one."""

    def __init__(self):
        self._drafts: dict[str, tuple[str, object]] = {}  # kind -> (sha256, payload)
        self._lock = threading.Lock()

    def put(self, sha256: str, payload, kind: str = "policy.approve") -> None:
        with self._lock:
            self._drafts[kind] = (sha256, payload)

    def get(self, sha256: str, kind: str = "policy.approve"):
        with self._lock:
            d = self._drafts.get(kind)
            return d[1] if d and d[0] == sha256 else None

    def clear(self, sha256: str, kind: str = "policy.approve") -> None:
        with self._lock:
            d = self._drafts.get(kind)
            if d and d[0] == sha256:
                del self._drafts[kind]


PolicyDrafts = Drafts
DRAFTS = Drafts()
DRAFTED = ("policy.approve", "import.apply")  # commands whose signed hash names a held draft


def plain_text(value, what: str, max_len: int) -> str:
    """Labels and reasons go into the message the wallet shows. Control, format
    and line/paragraph separator characters could make that message look like
    something else, so they are refused."""
    if not isinstance(value, str) or not value.strip():
        raise Refused(f"{what} is required")
    value = value.strip()
    if len(value) > max_len:
        raise Refused(f"{what} is longer than {max_len} characters")
    if any(unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") for c in value):
        raise Refused(f"{what} may not contain control, format or line-separator characters")
    return value


# ---------------------------------------------------------------- read-only views

def keys(conn) -> list[dict]:
    return [{"key_id": r["key_id"], "voice": r["voice"], "label": r["label"],
             "created_at": r["created_at"], "revoked_at": r["revoked_at"],
             "last_used_at": r["last_used_at"], "bearer": r["secret_hash"] is not None}
            for r in conn.execute("SELECT * FROM keys ORDER BY created_at, key_id")]


def overview(conn, policy: Policy | None) -> dict:
    counts = {r["voice"]: r["n"] for r in conn.execute(
        "SELECT voice, COUNT(*) AS n FROM entries WHERE kind != 'redaction' GROUP BY voice")}
    redacted = conn.execute("SELECT COUNT(*) FROM entries WHERE redacted_at IS NOT NULL").fetchone()[0]
    # Connections: code keys, and the brain's connector grants (not import keys, not the admin row).
    active = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE revoked_at IS NULL AND (secret_hash IS NOT NULL "
        "OR (voice = 'brain' AND key_id NOT LIKE 'k\\_brain\\_imp\\_%' ESCAPE '\\'))").fetchone()[0]
    latest = {}
    for voice in ("brain", "code"):
        row = conn.execute(
            f"SELECT {SALIENCE_COLS} FROM entries e LEFT JOIN salience s ON s.entry_id = e.id "
            "WHERE e.voice = ? AND e.kind != 'redaction' AND e.redacted_at IS NULL ORDER BY e.seq DESC LIMIT 1",
            (voice,)).fetchone()
        latest[voice] = {**_row(row), "id_full": row["id"]} if row else None
    out = {"head": svc.head(conn), "entries": counts, "redacted": redacted, "active_keys": active,
           "latest": latest, "policy": policy.sha256 if policy else None, "setup_needed": policy is None}
    if policy is not None:
        f = faded(conn, policy, limit=1)
        out.update(fade_below=policy.fade_below, faded=f["total"], faded_this_week=f["this_week"])
    return out


SALIENCE_COLS = "e.*, s.last_reinforced_at AS s_last, s.half_life_days AS s_hl"


def _row(r, now: datetime | None = None) -> dict:
    out = {"id": svc.short(r["id"]), "seq": r["seq"], "ts": r["ts"][:19] + "Z", "voice": r["voice"],
           "subject": r["subject"], "kind": r["kind"], "pinned": bool(r["pinned"]),
           "excerpt": r["excerpt"], "redacted": r["redacted_at"] is not None,
           "untrusted_ctx": r["untrusted_ctx"]}
    if r["redacted_at"] is None and "s_last" in r.keys():
        out["salience"] = round(svc.salience_of(r["s_last"], r["s_hl"], now or datetime.now(timezone.utc)), 2)
    return out


def faded(conn, policy: Policy, now: datetime | None = None, limit: int = LIST_MAX) -> dict:
    """Live entries below the fade line, most recently faded first, with when each crossed it:
    the weekly 'what fell below the line' the half-lives are tuned from."""
    now = now or datetime.now(timezone.utc)
    k = svc.fade_factor(policy)
    base = (f"FROM entries e JOIN salience s ON s.entry_id = e.id "
            f"WHERE {svc.LIVE.format(t='e')} AND e.kind != 'redaction' AND s.half_life_days IS NOT NULL "
            f"AND julianday(s.last_reinforced_at) + s.half_life_days * ? <= julianday(?)")
    rows = conn.execute(
        f"SELECT {SALIENCE_COLS}, strftime('%Y-%m-%dT%H:%M:%SZ', "
        f"julianday(s.last_reinforced_at) + s.half_life_days * ?) AS faded_at "
        f"{base} ORDER BY julianday(s.last_reinforced_at) + s.half_life_days * ? DESC LIMIT ?",
        (k, k, svc._iso(now), k, max(1, min(int(limit), LIST_MAX)))).fetchall()
    total = conn.execute(f"SELECT COUNT(*) {base}", (k, svc._iso(now))).fetchone()[0]
    week = conn.execute(f"SELECT COUNT(*) {base} AND julianday(s.last_reinforced_at) + s.half_life_days * ? "
                        f"> julianday(?)", (k, svc._iso(now), k, svc._iso(now - timedelta(days=7)))).fetchone()[0]
    return {"entries": [{**_row(r, now), "faded_at": r["faded_at"]} for r in rows],
            "total": total, "this_week": week}


def subjects(conn) -> list[dict]:
    return [{"subject": r["subject"], "count": r["n"], "latest": r["latest"][:19] + "Z"}
            for r in conn.execute(
                "SELECT subject, COUNT(*) AS n, MAX(ts) AS latest FROM entries WHERE kind != 'redaction' "
                "GROUP BY subject ORDER BY subject LIMIT ?", (SUBJECTS_MAX,))]


def entries(conn, *, subject: str | None = None, query: str | None = None,
            before: int | None = None, limit: int = 50) -> dict:
    """Newest first. The admin sees every entry, redacted ones included (without content).
    Admin browsing is not deliberate use by a voice, so it never reinforces salience."""
    limit = max(1, min(int(limit), LIST_MAX))
    where, args = ["1 = 1"], []
    if subject:
        if subject.endswith("/**"):
            base = subject[:-3]
            where.append("(e.subject = ? OR substr(e.subject, 1, ?) = ?)")
            args += [base, len(base) + 1, base + "/"]
        else:
            where.append("e.subject = ?")
            args.append(subject)
    if before is not None:
        where.append("e.seq < ?")
        args.append(int(before))
    joined = "LEFT JOIN salience s ON s.entry_id = e.id"
    if query:
        # Search as you type: every word matches as a prefix ("lisb" finds Lisbon), quoted
        # so nothing the admin types is parsed as FTS syntax.
        words = re.findall(r"\w+", query)[:32]
        if not words:
            return {"entries": [], "next_before": None}
        sql = (f"SELECT {SALIENCE_COLS} FROM entries_fts JOIN entries e ON e.seq = entries_fts.rowid {joined} "
               f"WHERE entries_fts MATCH ? AND {' AND '.join(where)} ORDER BY e.seq DESC LIMIT ?")
        args = [" ".join('"' + w.replace('"', '""') + '"*' for w in words), *args]
    else:
        sql = f"SELECT {SALIENCE_COLS} FROM entries e {joined} WHERE {' AND '.join(where)} ORDER BY e.seq DESC LIMIT ?"
    rows = conn.execute(sql, (*args, limit + 1)).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    return {"entries": [_row(r) for r in rows], "next_before": rows[-1]["seq"] if more else None}


def entry(conn, ref: str) -> dict:
    row = conn.execute(f"SELECT {SALIENCE_COLS} FROM entries e LEFT JOIN salience s ON s.entry_id = e.id "
                       "WHERE e.id = ?", (svc.resolve_id(conn, ref),)).fetchone()
    entry_id = row["id"]
    out = _row(row)
    out.update(id=entry_id, key_id=row["key_id"], prev=svc.short(row["prev_hash"]),
               supersedes=svc.short(row["supersedes"]),
               refs=[svc.short(x) for x in json.loads(row["refs"])],
               superseded_by=[svc.short(r[0]) for r in conn.execute(
                   "SELECT id FROM entries WHERE supersedes = ? ORDER BY seq", (entry_id,))],
               cited_by=[svc.short(r[0]) for r in conn.execute(
                   "SELECT id FROM entries WHERE refs LIKE ? AND kind != 'redaction' ORDER BY seq LIMIT ?",
                   (f'%"{entry_id}"%', LIST_MAX))])
    if row["redacted_at"] is None:
        out.update(keywords=json.loads(row["keywords"]), body=row["body"])
    else:
        rec = conn.execute("SELECT * FROM redactions WHERE entry_id = ?", (entry_id,)).fetchone()
        out.update(redacted_at=row["redacted_at"],
                   redaction={"reason": rec["reason"], "tombstone": svc.short(rec["tombstone_id"])}
                   if rec else None)
    return out


def admin_log(conn, limit: int = LIST_MAX) -> list[dict]:
    return [{"at": r["at"][:19] + "Z", "event": r["event"], "action": json.loads(r["action"]),
             "signer": r["signer"], "detail": r["detail"]}
            for r in conn.execute("SELECT * FROM admin_log ORDER BY log_id DESC LIMIT ?",
                                  (max(1, min(int(limit), LIST_MAX)),))]


def policy_state(conn, settings: Settings, policy: Policy | None) -> dict:
    """The approved policy text, or the first draft to start from when none is approved."""
    if policy is not None:
        row = conn.execute("SELECT at FROM admin_log WHERE event = 'done' AND action = ? ORDER BY log_id DESC LIMIT 1",
                           (core.canonical({"action": "policy.approve", "sha256": policy.sha256}).decode(),)).fetchone()
        return {"approved": {"sha256": policy.sha256, "body": svc.policy_body(conn, policy.sha256),
                             "approved_at": row["at"] if row else None}}
    # An approved policy that no longer loads (say, after an upgrade added a setting) is the
    # best starting point for fixing it.
    approved = svc.approved_policy_hash(conn, settings.server_name, settings.admin_address)
    draft = svc.policy_body(conn, approved) if approved else None
    if draft is None:
        try:
            with open(settings.policy_path, encoding="utf-8") as f:
                draft = f.read()
        except OSError:
            draft = ""
    return {"approved": None, "draft": draft}


def policy_check(conn, body, policy: Policy | None) -> dict:
    """Validate a policy text without storing it, and show what would change."""
    if not isinstance(body, str):
        raise Refused("the policy must be text")
    try:
        candidate = svc.parse_policy(body.encode("utf-8"))
    except PolicyError as e:
        return {"valid": False, "error": str(e)}
    diff = ""  # with nothing approved yet, the whole text is the change; no diff to show
    if policy is not None:
        current = svc.policy_body(conn, policy.sha256)
        diff = "".join(difflib.unified_diff(current.splitlines(keepends=True), body.splitlines(keepends=True),
                                            "approved", "proposed"))
    return {"valid": True, "sha256": candidate.sha256,
            "unchanged": policy is not None and candidate.sha256 == policy.sha256, "diff": diff}


def verify(conn) -> list[str]:
    return core.verify(conn)


# ---------------------------------------------------------------- signed commands

def _active_key(conn, key_id, *, grants: bool = False):
    """An unrevoked bearer key; with grants=True, also a brain grant (a key row with
    no secret, whose OAuth tokens stop working once it is revoked)."""
    row = conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone() \
        if isinstance(key_id, str) else None
    if row is None:
        raise Refused(f"no key {key_id}")
    if row["revoked_at"] is not None:
        raise Refused(f"key {key_id} is already revoked")
    if row["secret_hash"] is None and not (grants and row["voice"] == "brain"):
        raise Refused(f"key {key_id} is not a bearer key")
    return row


def _active_backup(conn, token_id):
    row = conn.execute("SELECT * FROM backup_tokens WHERE token_id = ?", (token_id,)).fetchone() \
        if isinstance(token_id, str) else None
    if row is None:
        raise Refused(f"no backup token {token_id}")
    if row["revoked_at"] is not None:
        raise Refused(f"backup token {token_id} is already revoked")
    return row


def _redact_target(conn, policy: Policy | None, ref):
    if policy is None:
        raise Refused("approve a policy first")
    try:
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (svc.resolve_id(conn, ref),)).fetchone()
    except svc.ServiceError as e:
        raise Refused(str(e)) from None
    decision = policy.check_redact("admin", row)
    if not decision:
        raise Refused(decision.reason)
    return row


def prepare(conn, settings: Settings, policy: Policy | None, request: dict,
            drafts: PolicyDrafts = DRAFTS) -> str:
    """Turn the admin's request into the exact message their wallet will sign.
    Everything that can be checked now is checked now, so the admin never signs
    something that is bound to fail."""
    if not isinstance(request, dict):
        raise Refused("bad request")
    kind = request.get("action")
    if kind == "keys.mint":
        if request.get("voice", "code") != "code":
            raise Refused("only code keys are minted here; the brain is granted by wallet sign-in")
        action = {"action": "keys.mint", "voice": "code",
                  "label": plain_text(request.get("label"), "a key label", LABEL_MAX)}
    elif kind == "keys.revoke":
        action = {"action": "keys.revoke",
                  "key_id": _active_key(conn, request.get("key_id"), grants=True)["key_id"]}
    elif kind == "keys.rotate":
        old = _active_key(conn, request.get("key_id"))
        label = request.get("label") or old["label"] or f"rotated from {old['key_id']}"
        action = {"action": "keys.rotate", "key_id": old["key_id"],
                  "label": plain_text(label, "a key label", LABEL_MAX)}
    elif kind == "redact":
        row = _redact_target(conn, policy, request.get("id"))
        action = {"action": "redact", "id": row["id"],
                  "reason": plain_text(request.get("reason"), "a reason", REASON_MAX)}
    elif kind == "policy.approve":
        body = request.get("body")
        if not isinstance(body, str):
            raise Refused("the policy must be text")
        try:
            candidate = svc.parse_policy(body.encode("utf-8"))
        except PolicyError as e:
            raise Refused(f"the policy is not valid: {e}") from None
        if policy is not None and candidate.sha256 == policy.sha256:
            raise Refused("that is already the approved policy")
        drafts.put(candidate.sha256, body)
        action = {"action": "policy.approve", "sha256": candidate.sha256}
    elif kind == "import.apply":
        if policy is None:
            raise Refused("approve a policy first")
        records, problems = parse_import(request.get("body"), policy)
        if problems:
            raise Refused(f"the import has {len(problems)} problem(s); check it first")
        sha = hashlib.sha256(request["body"].encode("utf-8")).hexdigest()
        drafts.put(sha, records, "import.apply")
        action = {"action": "import.apply", "sha256": sha, "entries": len(records)}
    elif kind == "backup.mint":
        action = {"action": "backup.mint", "label": plain_text(request.get("label"), "a label", LABEL_MAX)}
    elif kind == "backup.revoke":
        action = {"action": "backup.revoke", "token_id": _active_backup(conn, request.get("token_id"))["token_id"]}
    else:
        raise Refused(f"unknown action {kind!r}")
    ttl = policy.command_ttl_seconds if policy else admin_auth.TTL_SECONDS
    return admin_auth.prepare(conn, settings.server_name, action, ttl_seconds=ttl)


def confirm(conn, settings: Settings, policy: Policy | None, message: str, signature: str,
            drafts: PolicyDrafts = DRAFTS) -> dict:
    """Check the signature, perform exactly the signed action, log the outcome."""
    if not isinstance(message, str) or not isinstance(signature, str):
        raise Refused("bad request")
    draft = None
    try:
        signed = admin_auth.parse_message(message)["action"]
        if signed.get("action") in DRAFTED:
            # Checked before the nonce is spent: an approval is only ever logged for text we hold.
            draft = drafts.get(signed.get("sha256"), signed["action"])
            if draft is None:
                raise Refused("this draft was replaced or has expired; check it and approve it again")
        action = admin_auth.authorize(conn, settings.server_name, settings.admin_address, message, signature)
    except (admin_auth.AdminAuthError, ValueError) as e:
        raise Refused(f"refused: {e}. Nothing was changed.") from None
    try:
        if action["action"] == "policy.approve":
            svc.store_policy_version(conn, draft)
        if draft is not None:
            drafts.clear(action["sha256"], action["action"])
        result, detail = _perform(conn, settings, policy, action, draft)
    except Exception as e:
        admin_auth.log_outcome(conn, message, ok=False, detail=str(e))
        if isinstance(e, (Refused, svc.ServiceError, PolicyError, core.AIngramError)):
            raise Refused(f"failed: {e}") from None
        raise
    admin_auth.log_outcome(conn, message, ok=True, detail=detail)
    return result


def _in_tx(conn, fn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        out = fn()
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return out


def _perform(conn, settings: Settings, policy: Policy | None, a: dict, draft=None) -> tuple[dict, str]:
    kind = a["action"]
    if kind == "import.apply":
        return apply_import(conn, policy, draft, a)
    if kind == "keys.mint":
        key_id, secret = _in_tx(conn, lambda: svc.mint_key_in_tx(conn, a["voice"], a["label"]))
        return {"key_id": key_id, "secret": secret}, f"minted {key_id}"
    if kind == "keys.revoke":
        _active_key(conn, a["key_id"], grants=True)
        core.revoke_key(conn, a["key_id"])
        # A grant's tokens already fail once its key is revoked; ending them too keeps the record plain.
        conn.execute("UPDATE oauth_tokens SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                     (core.utc_now(), a["key_id"]))
        return {"revoked": a["key_id"]}, f"revoked {a['key_id']}"
    if kind == "keys.rotate":
        def rotate():
            row = _active_key(conn, a["key_id"])
            minted = svc.mint_key_in_tx(conn, row["voice"], a["label"])
            core.revoke_key(conn, a["key_id"])
            return minted
        key_id, secret = _in_tx(conn, rotate)
        return ({"revoked": a["key_id"], "key_id": key_id, "secret": secret},
                f"rotated {a['key_id']} -> {key_id}")
    if kind == "redact":
        _redact_target(conn, policy, a["id"])
        key_id = svc.ensure_admin_key(conn, settings.admin_address)
        result = svc.redact(conn, policy, key_id, a["id"], a["reason"])
        return result, f"redacted {a['id']}, tombstone {result['tombstone']}"
    if kind == "policy.approve":
        body = svc.policy_body(conn, a["sha256"])
        if body is None:
            raise Refused("that policy text is not on this server")
        svc.parse_policy(body.encode("utf-8"))
        return {"approved": a["sha256"]}, f"approved policy {a['sha256']}"
    if kind == "backup.mint":
        token_id, secret = f"b_{secrets.token_hex(4)}", svc.new_secret(BACKUP_PREFIX)
        conn.execute("INSERT INTO backup_tokens (token_id, token_hash, label, created_at) VALUES (?,?,?,?)",
                     (token_id, svc.hash_secret(secret), a["label"], core.utc_now()))
        return {"token_id": token_id, "secret": secret}, f"created backup token {token_id}"
    if kind == "backup.revoke":
        _active_backup(conn, a["token_id"])
        conn.execute("UPDATE backup_tokens SET revoked_at = ? WHERE token_id = ?", (core.utc_now(), a["token_id"]))
        return {"revoked": a["token_id"]}, f"revoked backup token {a['token_id']}"
    raise Refused(f"unknown action {kind!r}")


# ---------------------------------------------------------------- backup

BACKUP_PREFIX = "aigb_"
BACKUP_RE = re.compile(r"^aigb_[A-Za-z0-9_-]{43}$")
BACKUP_FORMAT = 1


def backup_tokens(conn) -> list[dict]:
    return [{k: r[k] for k in ("token_id", "label", "created_at", "revoked_at", "last_used_at")}
            for r in conn.execute("SELECT * FROM backup_tokens ORDER BY created_at")]


def backup_token_valid(conn, secret) -> bool:
    """True for an unrevoked backup token. Records its use (at most once a minute)."""
    if not isinstance(secret, str) or not BACKUP_RE.match(secret):
        return False
    row = conn.execute("SELECT * FROM backup_tokens WHERE token_hash = ?", (svc.hash_secret(secret),)).fetchone()
    if row is None or row["revoked_at"] is not None:
        return False
    last = row["last_used_at"]
    now = datetime.now(timezone.utc)
    if last is None or (now - datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.%fZ")
                        .replace(tzinfo=timezone.utc)).total_seconds() > svc.LAST_USED_RESOLUTION_S:
        conn.execute("UPDATE backup_tokens SET last_used_at = ? WHERE token_id = ?", (svc._iso(now), row["token_id"]))
    return True


def backup_admin_record(conn, settings: Settings) -> dict:
    """What the off-server check needs besides the entries: every signed policy approval
    (message and signature, checkable against the admin address the backup trusts),
    the text of every policy version, and the key list (no secrets) so new or changed
    credentials show up in the nightly diff. Other signed commands are left out: a
    redaction's signed message carries its reason, and reasons stay on the server."""
    conn.execute("BEGIN")
    try:
        approvals = [{"message": r["message"], "signature": r["signature"]} for r in conn.execute(
            "SELECT message, signature FROM admin_log WHERE event = 'authorized' AND action LIKE ? ORDER BY log_id",
            (svc.POLICY_APPROVE_PREFIX + "%",))]
        versions = {r["sha256"]: r["body"] for r in conn.execute("SELECT sha256, body FROM policy_versions")}
        keys = [{k: r[k] for k in ("key_id", "voice", "label", "created_at", "revoked_at")}
                for r in conn.execute("SELECT * FROM keys ORDER BY created_at, key_id")]
    finally:
        conn.execute("COMMIT")
    return {"format": BACKUP_FORMAT, "server": settings.server_name, "policy_approvals": approvals,
            "policy_versions": versions, "keys": keys}


# ---------------------------------------------------------------- read-only CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aingram_admin",
        description="AIngram read-only admin CLI. Changes are made, and signed, on the /admin page.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keys").add_subparsers(dest="keys_cmd", required=True).add_parser("list")
    sub.add_parser("verify")
    export = sub.add_parser("export")
    export.add_argument("--out", required=True)
    sub.add_parser("policy").add_subparsers(dest="policy_cmd", required=True).add_parser("status")
    return p


def main(argv=None, out=print, env=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if env is None:
            load_env()
        settings = Settings.from_env(env, need_admin=args.cmd == "policy")
        conn = core.connect(settings.db_path)
    except (ConfigError, core.AIngramError) as e:
        out(str(e))
        return 1
    try:
        if args.cmd == "keys":
            rows = keys(conn)
            if not rows:
                out("no keys")
            for r in rows:
                state = f"revoked {r['revoked_at']}" if r["revoked_at"] else "active"
                out(f"{r['key_id']:<20} {r['voice']:<6} {state:<36} "
                    f"last used {r['last_used_at'] or 'never':<28} {r['label'] or ''}")
        elif args.cmd == "verify":
            problems = verify(conn)
            out("chain verifies" if not problems else "\n".join(problems))
            return 0 if not problems else 1
        elif args.cmd == "export":
            out(f"exported to {args.out}; head {core.export_jsonl(conn, args.out)}")
        elif args.cmd == "policy":
            policy = svc.load_approved_policy(conn, settings.server_name, settings.admin_address)
            if policy is None:
                out("no policy approved yet: sign in at /admin to approve one")
                return 1
            out(f"approved policy {policy.sha256}")
        return 0
    except (PolicyError, core.AIngramError) as e:
        out(str(e))
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------- import

IMPORT_MAX_BYTES = 20 * 1024 * 1024
IMPORT_MAX_ENTRIES = 20000
IMPORT_FIELDS = {"subject", "kind", "excerpt", "keywords", "body", "pinned", "untrusted_ctx", "date", "source"}
SOURCE_MAX = 50  # "migrated-from:" plus this fits the policy's 64-character keyword limit
DATE_RE = re.compile(r"^\d{4}-\d\d-\d\d$")
PROBLEMS_SHOWN = 50


def parse_import(text, policy: Policy) -> tuple[list[dict], list[str]]:
    """Read an import file (one JSON object per line) and check every line the way a
    live write by the brain is checked. Returns (records, problems); any problem means
    nothing is imported."""
    if not isinstance(text, str) or not text.strip():
        return [], ["the import file is empty"]
    if len(text.encode("utf-8")) > IMPORT_MAX_BYTES:
        return [], [f"the import file is over {IMPORT_MAX_BYTES // (1024 * 1024)} MB"]
    records, problems = [], []
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(records) >= IMPORT_MAX_ENTRIES:
            problems.append(f"more than {IMPORT_MAX_ENTRIES} entries; split the import")
            break
        try:
            raw = json.loads(line)
        except ValueError as e:
            problems.append(f"line {n}: not JSON ({e})")
            continue
        if not isinstance(raw, dict):
            problems.append(f"line {n}: expected an object")
            continue
        unknown = set(raw) - IMPORT_FIELDS
        if unknown:
            problems.append(f"line {n}: unknown field(s) {', '.join(sorted(unknown))}")
            continue
        try:
            rec = {
                "subject": raw.get("subject"), "kind": raw.get("kind"), "excerpt": raw.get("excerpt"),
                "keywords": list(raw.get("keywords") or []), "body": raw.get("body") or "",
                "pinned": raw.get("pinned", False), "untrusted_ctx": raw.get("untrusted_ctx"),
                "date": raw.get("date"), "source": raw.get("source")}
            for field in ("subject", "kind", "excerpt", "source"):
                if not isinstance(rec[field], str) or not rec[field].strip():
                    raise Refused(f"{field} is required")
            if not isinstance(rec["body"], str) or not all(isinstance(k, str) for k in rec["keywords"]):
                raise Refused("body must be text and keywords a list of text")
            if not isinstance(rec["pinned"], bool):
                raise Refused("pinned must be true or false")
            source = plain_text(rec["source"], "source", SOURCE_MAX)
            rec["untrusted_ctx"], problem = canonical_ctx(rec["untrusted_ctx"])
            if problem:
                raise Refused(problem)
            if rec["date"] is not None:
                if not isinstance(rec["date"], str) or not DATE_RE.match(rec["date"]):
                    raise Refused("date must be YYYY-MM-DD")
                datetime.strptime(rec["date"], "%Y-%m-%d")
                if rec["date"] > today:
                    raise Refused("date is in the future")
            if len(rec["excerpt"]) > core.EXCERPT_MAX:
                raise Refused(f"excerpt is {len(rec['excerpt'])} characters; max {core.EXCERPT_MAX}")
            rec["keywords"].append(f"migrated-from:{source}")
            for decision in (policy.check_write("brain", rec["subject"], rec["kind"], rec["pinned"], rec["untrusted_ctx"]),
                             policy.check_content(rec["excerpt"], rec["keywords"], rec["body"], ())):
                if not decision:
                    raise Refused(decision.reason)
        except (Refused, ValueError) as e:
            problems.append(f"line {n}: {e}")
            continue
        records.append(rec)
    if not records and not problems:
        problems.append("the import file has no entries")
    return records, problems


def import_summary(records: list[dict]) -> dict:
    top = lambda s: s.split("/", 1)[0]
    subjects, kinds = {}, {}
    for r in records:
        subjects[top(r["subject"])] = subjects.get(top(r["subject"]), 0) + 1
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    dates = sorted(r["date"] for r in records if r["date"])
    return {"entries": len(records), "pinned": sum(r["pinned"] for r in records),
            "subjects": dict(sorted(subjects.items(), key=lambda kv: -kv[1])),
            "kinds": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
            "dated": [dates[0], dates[-1]] if dates else None,
            "outside_text": sum(1 for r in records if r["untrusted_ctx"])}


def check_import(text, policy: Policy | None) -> dict:
    if policy is None:
        raise Refused("approve a policy first")
    records, problems = parse_import(text, policy)
    return {"valid": not problems, "problems": problems[:PROBLEMS_SHOWN], "problem_count": len(problems),
            "summary": import_summary(records),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None,
            "sample": records[:5]}


def apply_import(conn, policy: Policy | None, records, a: dict) -> tuple[dict, str]:
    """Write every record as the brain under a fresh import key, in one transaction:
    all of it lands or none of it does. An entry's original date sets its decay clock,
    so an old breadcrumb starts out as faded as it would be had it been written then.
    The daily cap does not apply; the admin's signature over this exact file stands in for it."""
    if policy is None:
        raise Refused("approve a policy first")
    if not records or len(records) != a["entries"]:
        raise Refused("the import draft does not match what was signed")

    def write_all():
        key_id = f"k_brain_imp_{secrets.token_hex(4)}"
        core.add_key(conn, key_id=key_id, voice="brain",
                     label=f"import of {len(records)} entries, {datetime.now(timezone.utc):%Y-%m-%d}")
        for r in records:
            done = core._append_in_tx(
                conn, key_id=key_id, subject=r["subject"], kind=r["kind"], excerpt=r["excerpt"],
                keywords=r["keywords"], body=r["body"], pinned=r["pinned"], untrusted_ctx=r["untrusted_ctx"],
                half_life_days=policy.half_life_for(r["kind"], r["pinned"]))
            if r["date"]:
                conn.execute("UPDATE salience SET last_reinforced_at = ? WHERE entry_id = ?",
                             (f"{r['date']}T00:00:00.000000Z", done["id"]))
        return key_id
    key_id = _in_tx(conn, write_all)
    return {"imported": len(records), "key_id": key_id, "head": svc.head(conn)}, \
        f"imported {len(records)} entries as {key_id}"
