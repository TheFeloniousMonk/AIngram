"""Run: python -m unittest test_admin_web -v

The admin page over HTTP: wallet sign-in, look-only sessions, signed changes.
"""

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from starlette.testclient import TestClient

import aingram_core as core
import aingram_server
import aingram_web as web
from aingram_config import Settings

ADMIN = Account.create()
MALLORY = Account.create()
PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"
JSON = {"Origin": BASE, "Content-Type": "application/json"}
COOKIE = "aingram_admin"


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


class Web(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.settings = Settings.from_env({
            "AINGRAM_DB": str(Path(self.dir.name) / "store.db"), "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def db(self):
        conn = core.connect(self.settings.db_path)
        self.addCleanup(conn.close)
        return conn

    def post(self, path, body, headers=JSON):
        return self.client.post(path, content=json.dumps(body), headers=headers)

    def challenge(self, acct=ADMIN):
        r = self.post("/admin/api/login/challenge", {"address": acct.address.lower()})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["message"]

    def sign_in(self, acct=ADMIN):
        message = self.challenge(acct)
        return self.post("/admin/api/login/verify", {"message": message, "signature": sign(acct, message)})

    def signed(self, request, signer=ADMIN):
        r = self.post("/admin/api/actions/prepare", request)
        self.assertEqual(r.status_code, 200, r.text)
        message = r.json()["message"]
        return self.post("/admin/api/actions/confirm", {"message": message, "signature": sign(signer, message)})

    def setup_policy(self):
        draft = self.client.get("/admin/api/policy").json()["draft"]
        r = self.signed({"action": "policy.approve", "body": draft})
        self.assertEqual(r.status_code, 200, r.text)

    def mcp(self, secret, tool, **args):
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": "2025-06-18", "Authorization": f"Bearer {secret}"}
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        return self.client.post("/mcp", headers=h, content=json.dumps(body)).json()["result"]


class Page(Web):
    def test_page_is_served_locked_down(self):
        for path in ("/admin", "/admin/admin.js", "/admin/admin.css"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("script-src 'self'", r.headers["content-security-policy"])
            self.assertEqual(r.headers["x-frame-options"], "DENY")
            self.assertEqual(r.headers["cache-control"], "no-store")

    def test_unknown_host_is_refused(self):
        self.assertEqual(self.client.get("/admin", headers={"Host": "evil.example"}).status_code, 421)
        self.assertEqual(self.client.get("/admin/api/me", headers={"Host": "evil.example"}).status_code, 421)

    def test_page_has_no_inline_script_or_handlers(self):
        html = self.client.get("/admin").text
        self.assertNotIn("<script>", html)
        self.assertNotRegex(html, r"\son[a-z]+=")


class SignIn(Web):
    def test_everything_needs_a_session(self):
        for path in ("/admin/api/me", "/admin/api/keys", "/admin/api/entries", "/admin/api/log",
                     "/admin/api/policy", "/admin/api/export"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.post("/admin/api/actions/prepare", {"action": "keys.mint"}).status_code, 401)

    def test_challenge_is_sign_in_with_ethereum_for_this_site(self):
        lines = self.challenge().split("\n")
        self.assertEqual(lines[0], f"127.0.0.1:{PORT} wants you to sign in with your Ethereum account:")
        self.assertEqual(lines[1], ADMIN.address)  # EIP-55 checksummed
        self.assertIn(f"URI: {BASE}/admin", lines)
        self.assertIn("Chain ID: 1", lines)

    def test_admin_wallet_gets_a_locked_down_cookie(self):
        r = self.sign_in()
        self.assertEqual(r.status_code, 200, r.text)
        cookie = r.headers["set-cookie"].lower()
        for flag in ("httponly", "samesite=strict", "path=/"):
            self.assertIn(flag, cookie)
        me = self.client.get("/admin/api/me").json()
        self.assertEqual(me["address"], ADMIN.address)
        self.assertTrue(me["setup_needed"])
        # Only the token's hash is stored.
        token = self.client.cookies[COOKIE]
        self.assertNotIn(token, "\n".join(self.db().iterdump()))

    def test_other_wallets_are_refused(self):
        r = self.sign_in(MALLORY)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not the admin wallet", r.json()["error"])
        self.assertNotIn(COOKIE, self.client.cookies)

    def test_signature_must_come_from_the_named_wallet(self):
        message = self.challenge(ADMIN)
        r = self.post("/admin/api/login/verify", {"message": message, "signature": sign(MALLORY, message)})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn(COOKIE, self.client.cookies)

    def test_a_challenge_works_once(self):
        message = self.challenge()
        body = {"message": message, "signature": sign(ADMIN, message)}
        self.assertEqual(self.post("/admin/api/login/verify", body).status_code, 200)
        self.client.cookies.clear()
        r = self.post("/admin/api/login/verify", body)
        self.assertEqual(r.status_code, 400)
        self.assertIn("unknown or already used", r.json()["error"])

    def test_only_messages_this_server_issued(self):
        message = self.challenge().replace("Sign in to the AIngram", "Sign in to the evil")
        r = self.post("/admin/api/login/verify", {"message": message, "signature": sign(ADMIN, message)})
        self.assertEqual(r.status_code, 400)

    def test_a_flood_of_challenges_cannot_lock_the_admin_out(self):
        signin = web.SignIn(BASE, ADMIN.address)
        mine = signin.challenge(ADMIN.address)
        for _ in range(2000):
            signin.challenge(MALLORY.address)
        self.assertEqual(signin.verify(mine, sign(ADMIN, mine)), ADMIN.address.lower())

    def test_challenges_expire(self):
        signin = web.SignIn(BASE, ADMIN.address)
        old = signin.challenge(ADMIN.address, now=web._now() - web.CHALLENGE_TTL - timedelta(seconds=5))
        with self.assertRaisesRegex(web.admin.Refused, "expired"):
            signin.verify(old, sign(ADMIN, old))

    def test_another_servers_challenge_is_refused(self):
        other = web.SignIn(BASE, ADMIN.address)  # same site, different key: e.g. before a restart
        message = other.challenge(ADMIN.address)
        r = self.post("/admin/api/login/verify", {"message": message, "signature": sign(ADMIN, message)})
        self.assertEqual(r.status_code, 400)

    def test_malformed_input_is_a_plain_refusal(self):
        self.assertEqual(self.client.post("/admin/api/login/challenge", content="[1]", headers=JSON).status_code, 400)
        r = self.client.post("/admin/api/login/verify", headers=JSON,
                             content='{"message": "\\ud800", "signature": "0x00"}')
        self.assertEqual(r.status_code, 400)
        self.sign_in()
        r = self.client.post("/admin/api/policy/check", headers=JSON, content='{"body": "a\\ud800"}')
        self.assertEqual(r.status_code, 400)

    def test_public_url_is_normalised_to_the_browser_origin(self):
        for raw, want in (("https://Example.COM:443/", "https://example.com"),
                          ("https://example.com:8443", "https://example.com:8443"),
                          ("http://LOCALHOST:80", "http://localhost")):
            s = Settings.from_env({"AINGRAM_DB": "x", "AINGRAM_PUBLIC_URL": raw})
            self.assertEqual(s.public_url, want, raw)

    def test_cross_site_and_non_json_posts_are_refused(self):
        self.sign_in()
        for headers in ({"Origin": "https://evil.example", "Content-Type": "application/json"},
                        {"Content-Type": "application/json"}):
            r = self.post("/admin/api/actions/prepare", {"action": "keys.mint", "label": "x"}, headers)
            self.assertEqual(r.status_code, 403, headers)
        r = self.post("/admin/api/actions/prepare", {"action": "keys.mint", "label": "x"},
                      {"Origin": BASE, "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 400)

    def test_sign_out_ends_the_session(self):
        self.sign_in()
        token = self.client.cookies[COOKIE]
        self.assertEqual(self.post("/admin/api/logout", {}).status_code, 200)
        self.client.cookies.set(COOKIE, token)
        self.assertEqual(self.client.get("/admin/api/me").status_code, 401)

    def test_sign_out_everywhere(self):
        self.sign_in()
        first = self.client.cookies[COOKIE]
        self.client.cookies.clear()
        self.sign_in()
        self.assertEqual(self.post("/admin/api/logout", {"everywhere": True}).status_code, 200)
        self.client.cookies.set(COOKIE, first)
        self.assertEqual(self.client.get("/admin/api/me").status_code, 401)

    def test_idle_sessions_expire(self):
        self.sign_in()
        stale = web._iso(web._now() - web.SESSION_IDLE - timedelta(minutes=1))
        self.db().execute("UPDATE admin_sessions SET last_seen_at = ?", (stale,))
        self.assertEqual(self.client.get("/admin/api/me").status_code, 401)

    def test_sessions_end_at_their_limit(self):
        self.sign_in()
        self.db().execute("UPDATE admin_sessions SET expires_at = ?", (web._iso(web._now()),))
        self.assertEqual(self.client.get("/admin/api/me").status_code, 401)


class Changes(Web):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.sign_in().status_code, 200)

    def test_first_run_approve_policy_then_mint_a_working_key(self):
        secret_less = self.client.get("/admin/api/policy").json()
        self.assertIsNone(secret_less["approved"])
        self.setup_policy()
        self.assertFalse(self.client.get("/admin/api/me").json()["setup_needed"])
        r = self.signed({"action": "keys.mint", "voice": "code", "label": "laptop"})
        self.assertEqual(r.status_code, 200, r.text)
        secret = r.json()["secret"]
        result = self.mcp(secret, "boot")
        self.assertFalse(result.get("is_error") or result.get("isError"), result)
        keys = self.client.get("/admin/api/keys").json()["keys"]
        self.assertEqual([k["label"] for k in keys], ["laptop"])
        self.assertNotIn(secret, json.dumps(keys))

    def test_a_session_alone_changes_nothing(self):
        self.setup_policy()
        r = self.signed({"action": "keys.mint", "voice": "code", "label": "x"}, signer=MALLORY)
        self.assertEqual(r.status_code, 400)
        self.assertIn("Nothing was changed", r.json()["error"])
        self.assertEqual(self.client.get("/admin/api/keys").json()["keys"], [])

    def test_the_signature_covers_the_action(self):
        self.setup_policy()
        r = self.post("/admin/api/actions/prepare", {"action": "keys.mint", "voice": "code", "label": "mine"})
        message = r.json()["message"]
        swapped = message.replace('"label":"mine"', '"label":"theirs"')
        r = self.post("/admin/api/actions/confirm", {"message": swapped, "signature": sign(ADMIN, message)})
        self.assertEqual(r.status_code, 400)

    def test_policy_check_and_bad_policy(self):
        self.setup_policy()
        body = self.client.get("/admin/api/policy").json()["approved"]["body"]
        r = self.post("/admin/api/policy/check", {"body": body.replace("recent_tail: 8", "recent_tail: 5")}).json()
        self.assertTrue(r["valid"])
        self.assertIn("+  recent_tail: 5", r["diff"])
        self.assertFalse(self.post("/admin/api/policy/check", {"body": "nope: 1"}).json()["valid"])
        r = self.post("/admin/api/actions/prepare", {"action": "policy.approve", "body": "nope: 1"})
        self.assertEqual(r.status_code, 400)

    def test_browse_forget_and_export(self):
        self.setup_policy()
        secret = self.signed({"action": "keys.mint", "voice": "code", "label": "x"}).json()["secret"]
        self.mcp(secret, "write", subject="aingram/build", kind="decision", excerpt="use sqlite", body="because")
        entries = self.client.get("/admin/api/entries").json()["entries"]
        self.assertEqual(entries[0]["excerpt"], "use sqlite")
        entry_id = entries[0]["id"]
        self.assertEqual(self.client.get(f"/admin/api/entries/{entry_id}").json()["body"], "because")
        self.assertEqual(self.client.get("/admin/api/entries?query=sqlite").json()["entries"][0]["id"], entry_id)
        r = self.signed({"action": "redact", "id": entry_id, "reason": "test"})
        self.assertEqual(r.status_code, 200, r.text)
        detail = self.client.get(f"/admin/api/entries/{entry_id}").json()
        self.assertTrue(detail["redacted"])
        self.assertEqual(detail["redaction"]["reason"], "test")
        self.assertEqual(self.post("/admin/api/verify", {}).json()["problems"], [])
        export = self.client.get("/admin/api/export")
        self.assertEqual(export.status_code, 200)
        self.assertIn("attachment", export.headers["content-disposition"])
        self.assertNotIn("because", export.text)
        log = self.client.get("/admin/api/log").json()["log"]
        self.assertEqual(log[0]["action"]["action"], "redact")


if __name__ == "__main__":
    unittest.main()
