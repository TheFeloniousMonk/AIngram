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
import json
import sys
import threading
import unicodedata
from datetime import datetime, timedelta, timezone

import admin_auth
import aingram_core as core
import aingram_service as svc
from aingram_config import ConfigError, Settings, load_env
from aingram_policy import Policy, PolicyError

LIST_MAX = 100
SUBJECTS_MAX = 1000
LABEL_MAX = 80
REASON_MAX = 500


class Refused(Exception):
    """The admin asked for something that can't be done. Safe to show."""


class PolicyDrafts:
    """The one policy text waiting for a signature, held in memory.

    Unsigned text never reaches the database, so a stolen session can't fill
    policy_versions (which is append-only). Preparing a new draft replaces the
    old one, so an older, still-unsigned approval can't land after a newer one."""

    def __init__(self):
        self._draft: tuple[str, str] | None = None  # (sha256, body)
        self._lock = threading.Lock()

    def put(self, sha256: str, body: str) -> None:
        with self._lock:
            self._draft = (sha256, body)

    def get(self, sha256: str) -> str | None:
        with self._lock:
            return self._draft[1] if self._draft and self._draft[0] == sha256 else None

    def clear(self, sha256: str) -> None:
        with self._lock:
            if self._draft and self._draft[0] == sha256:
                self._draft = None


DRAFTS = PolicyDrafts()


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
    active = conn.execute("SELECT COUNT(*) FROM keys WHERE revoked_at IS NULL AND secret_hash IS NOT NULL"
                          ).fetchone()[0]
    out = {"head": svc.head(conn), "entries": counts, "redacted": redacted, "active_keys": active,
           "policy": policy.sha256 if policy else None, "setup_needed": policy is None}
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
        sql = (f"SELECT {SALIENCE_COLS} FROM entries_fts JOIN entries e ON e.seq = entries_fts.rowid {joined} "
               f"WHERE entries_fts MATCH ? AND {' AND '.join(where)} ORDER BY e.seq DESC LIMIT ?")
        args = [svc._fts_query(query), *args]
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
        return {"approved": {"sha256": policy.sha256, "body": svc.policy_body(conn, policy.sha256)}}
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

def _active_key(conn, key_id):
    row = conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone() \
        if isinstance(key_id, str) else None
    if row is None:
        raise Refused(f"no key {key_id}")
    if row["revoked_at"] is not None:
        raise Refused(f"key {key_id} is already revoked")
    if row["secret_hash"] is None:
        raise Refused(f"key {key_id} is not a bearer key")
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
        action = {"action": "keys.revoke", "key_id": _active_key(conn, request.get("key_id"))["key_id"]}
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
    else:
        raise Refused(f"unknown action {kind!r}")
    ttl = policy.command_ttl_seconds if policy else admin_auth.TTL_SECONDS
    return admin_auth.prepare(conn, settings.server_name, action, ttl_seconds=ttl)


def confirm(conn, settings: Settings, policy: Policy | None, message: str, signature: str,
            drafts: PolicyDrafts = DRAFTS) -> dict:
    """Check the signature, perform exactly the signed action, log the outcome."""
    if not isinstance(message, str) or not isinstance(signature, str):
        raise Refused("bad request")
    body = None
    try:
        signed = admin_auth.parse_message(message)["action"]
        if signed.get("action") == "policy.approve":
            # Checked before the nonce is spent: an approval is only ever logged for text we hold.
            body = drafts.get(signed.get("sha256"))
            if body is None:
                raise Refused("this policy draft was replaced or has expired; check and approve it again")
        action = admin_auth.authorize(conn, settings.server_name, settings.admin_address, message, signature)
    except (admin_auth.AdminAuthError, ValueError) as e:
        raise Refused(f"refused: {e}. Nothing was changed.") from None
    try:
        if body is not None:
            svc.store_policy_version(conn, body)
            drafts.clear(action["sha256"])
        result, detail = _perform(conn, settings, policy, action)
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


def _perform(conn, settings: Settings, policy: Policy | None, a: dict) -> tuple[dict, str]:
    kind = a["action"]
    if kind == "keys.mint":
        key_id, secret = _in_tx(conn, lambda: svc.mint_key_in_tx(conn, a["voice"], a["label"]))
        return {"key_id": key_id, "secret": secret}, f"minted {key_id}"
    if kind == "keys.revoke":
        _active_key(conn, a["key_id"])
        core.revoke_key(conn, a["key_id"])
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
    raise Refused(f"unknown action {kind!r}")


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
