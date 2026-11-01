"""Signed admin commands for AIngram.

Shell access to the server is the way in; the admin wallet is the authority.
Flow, run by the ssh admin tool:

  1. prepare(conn, server, action)  -> a message, with a fresh nonce stored on the box
  2. The admin signs that exact message on their own machine (EIP-191 personal_sign:
     `cast wallet sign "<message>"`, or any browser wallet) and pastes the signature back
  3. authorize(conn, server, admin_address, message, signature) -> the action,
     only if: the signer is the admin address, the nonce was issued here,
     is unused and unexpired, and the server name matches.
     The nonce is spent and the authorization logged in one transaction.
  4. the tool performs the action, then log_outcome(...) records done/failed.

A shell alone can't do step 3. Neither can Code, and neither can the brain.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from eth_account import Account
from eth_account.messages import encode_defunct

import aingram_core as core

HEADER = "AIngram admin command"
TTL_SECONDS = 600
ACTIONS = {"keys.mint", "keys.revoke", "keys.rotate", "redact", "policy.reload"}


class AdminAuthError(core.AIngramError):
    pass


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def build_message(server: str, action: dict, nonce: str, issued: str, expires: str) -> str:
    """Human-readable, so the wallet shows the admin exactly what they're approving.
    The action line is canonical JSON, so the signature binds every parameter."""
    return "\n".join([
        HEADER,
        f"Server: {server}",
        f"Action: {core.canonical(action).decode()}",
        f"Nonce: {nonce}",
        f"Issued: {issued}",
        f"Expires: {expires}",
    ])


def parse_message(message: str) -> dict:
    lines = message.split("\n")
    keys = ["Server", "Action", "Nonce", "Issued", "Expires"]
    if len(lines) != 6 or lines[0] != HEADER:
        raise AdminAuthError("not an AIngram admin command")
    out = {}
    for key, line in zip(keys, lines[1:]):
        prefix = f"{key}: "
        if not line.startswith(prefix):
            raise AdminAuthError(f"malformed line, expected {key}")
        out[key.lower()] = line[len(prefix):]
    action = json.loads(out["action"])
    if core.canonical(action).decode() != out["action"]:
        raise AdminAuthError("action is not in canonical form")
    out["action"] = action
    return out


def prepare(conn, server: str, action: dict, now: datetime | None = None) -> str:
    if action.get("action") not in ACTIONS:
        raise AdminAuthError(f"unknown admin action {action.get('action')!r}")
    now = now or datetime.now(timezone.utc)
    nonce = os.urandom(16).hex()
    issued, expires = _fmt(now), _fmt(now + timedelta(seconds=TTL_SECONDS))
    conn.execute("INSERT INTO admin_nonces (nonce, issued_at, expires_at) VALUES (?,?,?)",
                 (nonce, issued, expires))
    return build_message(server, action, nonce, issued, expires)


def recover_signer(message: str, signature: str) -> str:
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception as e:  # noqa: BLE001 - any decode failure is a bad signature
        raise AdminAuthError(f"signature could not be checked: {e}") from None


def authorize(conn, server: str, admin_address: str, message: str, signature: str,
              now: datetime | None = None) -> dict:
    """Return the signed action if, and only if, every check passes."""
    now = now or datetime.now(timezone.utc)
    m = parse_message(message)
    if m["server"] != server:
        raise AdminAuthError("command was signed for a different server")
    signer = recover_signer(message, signature)
    if signer.lower() != admin_address.lower():
        raise AdminAuthError("signature is not from the admin address")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT * FROM admin_nonces WHERE nonce = ?", (m["nonce"],)).fetchone()
        if row is None:
            raise AdminAuthError("nonce was not issued by this box")
        if row["used_at"] is not None:
            raise AdminAuthError("nonce already used (replay)")
        if row["issued_at"] != m["issued"] or row["expires_at"] != m["expires"]:
            raise AdminAuthError("message times do not match the issued nonce")
        if now > _parse(row["expires_at"]):
            raise AdminAuthError("command expired; prepare a new one")
        conn.execute("UPDATE admin_nonces SET used_at = ? WHERE nonce = ?", (_fmt(now), m["nonce"]))
        conn.execute(
            """INSERT INTO admin_log (at, event, nonce, action, signer, message, signature)
               VALUES (?,?,?,?,?,?,?)""",
            (_fmt(now), "authorized", m["nonce"], core.canonical(m["action"]).decode(),
             signer, message, signature))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return m["action"]


def log_outcome(conn, message: str, ok: bool, detail: str = "") -> None:
    m = parse_message(message)
    conn.execute(
        "INSERT INTO admin_log (at, event, nonce, action, detail) VALUES (?,?,?,?,?)",
        (core.utc_now(), "done" if ok else "failed", m["nonce"],
         core.canonical(m["action"]).decode(), detail))
