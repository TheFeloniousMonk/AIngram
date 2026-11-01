"""AIngram admin CLI. Run on the server, in a shell; it never listens on the network.

Read-only commands need no signature:
    keys list | verify | export --out FILE | policy status

Every command that changes anything is signed by the admin wallet:
    keys mint --voice code --label TEXT
    keys revoke KEY_ID
    keys rotate KEY_ID [--label TEXT]
    redact ID --reason TEXT
    policy reload

For a signed command the tool prints a message, waits for the admin to sign it
with their wallet (EIP-191 personal_sign) and paste the signature, checks it,
performs exactly the action that was signed, and logs the outcome. A refused
signature changes nothing. There is no flag that skips the signature.
"""

from __future__ import annotations

import argparse
import sys
import unicodedata

import admin_auth
import aingram_core as core
import aingram_service as svc
from aingram_config import ConfigError, Settings, load_env
from aingram_policy import PolicyError, load_policy


class Refused(Exception):
    pass


def plain_text(value: str, what: str) -> str:
    """Labels and reasons go into the message the wallet shows. Control, format
    and line/paragraph separator characters could make that message look like
    something else, so they are refused."""
    value = value.strip()
    if not value:
        raise Refused(f"{what} is required")
    if any(unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") for c in value):
        raise Refused(f"{what} may not contain control, format or line-separator characters")
    return value


class Admin:
    def __init__(self, settings: Settings, ask=input, out=print):
        self.s = settings
        self.ask = ask
        self.out = out
        self.conn = core.connect(settings.db_path)

    # -- signing

    def signed(self, action: dict, perform) -> None:
        """Prepare, collect a signature, authorize, perform the signed action, log."""
        policy = load_policy(self.s.policy_path)
        message = admin_auth.prepare(self.conn, self.s.server_name, action,
                                     ttl_seconds=policy.command_ttl_seconds)
        self.out("Sign this exact message with the admin wallet (personal_sign):\n")
        self.out(message)
        self.out(f"\nAs hex: 0x{message.encode('utf-8').hex()}\n")
        signature = self.ask("Signature: ").strip()
        try:
            signed_action = admin_auth.authorize(self.conn, self.s.server_name, self.s.admin_address,
                                                 message, signature)
        except admin_auth.AdminAuthError as e:
            raise Refused(f"refused: {e}. Nothing was changed.") from None
        try:
            detail = perform(signed_action)
        except Exception as e:
            admin_auth.log_outcome(self.conn, message, ok=False, detail=str(e))
            raise Refused(f"failed: {e}") from None
        admin_auth.log_outcome(self.conn, message, ok=True, detail=detail or "")

    # -- read-only

    def keys_list(self) -> None:
        rows = self.conn.execute("SELECT * FROM keys ORDER BY created_at").fetchall()
        if not rows:
            self.out("no keys")
        for r in rows:
            state = f"revoked {r['revoked_at']}" if r["revoked_at"] else "active"
            self.out(f"{r['key_id']:<20} {r['voice']:<6} {state:<36} "
                     f"last used {r['last_used_at'] or 'never':<28} {r['label'] or ''}")

    def verify(self) -> bool:
        problems = core.verify(self.conn)
        self.out("chain verifies" if not problems else "\n".join(problems))
        return not problems

    def export(self, out_path: str) -> None:
        head_id = core.export_jsonl(self.conn, out_path)
        self.out(f"exported to {out_path}; head {head_id}")

    def policy_status(self) -> bool:
        policy = load_policy(self.s.policy_path)
        approved = svc.approved_policy_hash(self.conn, self.s.server_name, self.s.admin_address)
        self.out(f"policy file  {policy.sha256}")
        self.out(f"approved     {approved or 'none'}")
        ok = approved == policy.sha256
        self.out("the server will load this policy" if ok else
                 "the server will refuse this policy until `policy reload` is signed")
        return ok

    # -- signed

    def keys_mint(self, voice: str, label: str) -> None:
        if voice != "code":
            raise Refused("only code keys are minted here; the brain is granted by wallet sign-in")
        label = plain_text(label, "a key label")
        minted = {}

        def perform(a):
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                minted["id"], minted["secret"] = svc.mint_key_in_tx(self.conn, a["voice"], a["label"])
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            return f"minted {minted['id']}"

        self.signed({"action": "keys.mint", "voice": voice, "label": label}, perform)
        self._show_secret(minted["id"], minted["secret"])

    def keys_revoke(self, key_id: str) -> None:
        self._active_key(key_id)

        def perform(a):
            self._active_key(a["key_id"])
            core.revoke_key(self.conn, a["key_id"])
            return f"revoked {a['key_id']}"

        self.signed({"action": "keys.revoke", "key_id": key_id}, perform)
        self.out(f"revoked {key_id}")

    def keys_rotate(self, key_id: str, label: str | None) -> None:
        old = self._active_key(key_id)
        label = plain_text(label or old["label"] or f"rotated from {key_id}", "a key label")
        minted = {}

        def perform(a):
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._active_key(a["key_id"])
                minted["id"], minted["secret"] = svc.mint_key_in_tx(self.conn, row["voice"], a["label"])
                core.revoke_key(self.conn, a["key_id"])
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            return f"rotated {a['key_id']} -> {minted['id']}"

        self.signed({"action": "keys.rotate", "key_id": key_id, "label": label}, perform)
        self.out(f"revoked {key_id}")
        self._show_secret(minted["id"], minted["secret"])

    def redact(self, ref: str, reason: str) -> None:
        reason = plain_text(reason, "a redaction reason")
        entry_id = svc.resolve_id(self.conn, ref)
        policy = load_policy(self.s.policy_path)
        row = self.conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        decision = policy.check_redact("admin", row)
        if not decision:
            raise Refused(decision.reason)
        result = {}

        def perform(a):
            key_id = svc.ensure_admin_key(self.conn, self.s.admin_address)
            result.update(svc.redact(self.conn, policy, key_id, a["id"], a["reason"]))
            return f"redacted {a['id']}, tombstone {result['tombstone']}"

        self.signed({"action": "redact", "id": entry_id, "reason": reason}, perform)
        self.out(f"redacted {entry_id}; tombstone {result['tombstone']}")
        if result["flagged_for_review"]:
            self.out("flagged for review: " + " ".join(result["flagged_for_review"]))

    def policy_reload(self) -> None:
        policy = load_policy(self.s.policy_path)  # refuses an invalid file before anything is signed
        # The signature covers a hash, so show the admin the exact bytes it stands for.
        self.out(f"Policy file {self.s.policy_path}, sha256 {policy.sha256}:\n")
        self.out(open(self.s.policy_path, encoding="utf-8").read())
        self.out("--- end of policy file ---\n")

        def perform(a):
            current = load_policy(self.s.policy_path)
            if current.sha256 != a["sha256"]:
                raise Refused("policy file changed while waiting for the signature")
            return f"approved policy {a['sha256']}"

        self.signed({"action": "policy.reload", "sha256": policy.sha256}, perform)
        self.out(f"approved policy {policy.sha256}; the running server picks it up on its next request")

    # -- helpers

    def _active_key(self, key_id: str):
        row = self.conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise Refused(f"no key {key_id}")
        if row["revoked_at"] is not None:
            raise Refused(f"key {key_id} is already revoked")
        if row["secret_hash"] is None:
            raise Refused(f"key {key_id} is not a bearer key")
        return row

    def _show_secret(self, key_id: str, secret: str) -> None:
        self.out(f"\nNew key {key_id}. The secret is shown once and is not stored:\n\n    {secret}\n")
        self.out("Put it in the client's connector configuration as `Authorization: Bearer <secret>`.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aingram_admin", description="AIngram admin CLI (run on the server)")
    sub = p.add_subparsers(dest="cmd", required=True)
    keys = sub.add_parser("keys").add_subparsers(dest="keys_cmd", required=True)
    keys.add_parser("list")
    mint = keys.add_parser("mint")
    mint.add_argument("--voice", required=True, choices=["code"])
    mint.add_argument("--label", required=True)
    revoke = keys.add_parser("revoke")
    revoke.add_argument("key_id")
    rotate = keys.add_parser("rotate")
    rotate.add_argument("key_id")
    rotate.add_argument("--label")
    sub.add_parser("verify")
    export = sub.add_parser("export")
    export.add_argument("--out", required=True)
    redact = sub.add_parser("redact")
    redact.add_argument("id")
    redact.add_argument("--reason", required=True)
    policy = sub.add_parser("policy").add_subparsers(dest="policy_cmd", required=True)
    policy.add_parser("reload")
    policy.add_parser("status")
    return p


def main(argv=None, ask=input, out=print, env=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if env is None:
            load_env()
        read_only = (args.cmd in ("verify", "export")
                     or (args.cmd == "keys" and args.keys_cmd == "list"))
        settings = Settings.from_env(env, need_admin=not read_only)
        admin = Admin(settings, ask=ask, out=out)
    except (ConfigError, core.AIngramError) as e:
        out(str(e))
        return 1
    try:
        if args.cmd == "keys":
            {"list": admin.keys_list,
             "mint": lambda: admin.keys_mint(args.voice, args.label),
             "revoke": lambda: admin.keys_revoke(args.key_id),
             "rotate": lambda: admin.keys_rotate(args.key_id, args.label)}[args.keys_cmd]()
        elif args.cmd == "verify":
            return 0 if admin.verify() else 1
        elif args.cmd == "export":
            admin.export(args.out)
        elif args.cmd == "redact":
            admin.redact(args.id, args.reason)
        elif args.cmd == "policy":
            if args.policy_cmd == "status":
                return 0 if admin.policy_status() else 1
            admin.policy_reload()
        return 0
    except (Refused, PolicyError, core.AIngramError) as e:
        out(str(e))
        return 1
    finally:
        admin.conn.close()


if __name__ == "__main__":
    sys.exit(main())
