"""Run: python -m unittest test_oauth -v

The brain's connector: OAuth with the admin wallet's approval, driven the way
claude.ai drives it (discovery, registration, authorize, token, refresh, revoke).
"""

import base64
import hashlib
import json
import secrets
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from eth_account import Account
from eth_account.messages import encode_defunct
from starlette.testclient import TestClient

import aingram_admin as admin
import aingram_core as core
import aingram_server
import aingram_service as svc
from aingram_config import Settings

ADMIN = Account.create()
MALLORY = Account.create()
PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
JSON = {"Origin": BASE, "Content-Type": "application/json"}
EXAMPLE = (Path(__file__).parent / "policy.example.yaml").read_text(encoding="utf-8")


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class OAuth(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.settings = Settings.from_env({
            "AINGRAM_DB": str(Path(self.dir.name) / "store.db"), "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        conn = core.connect(self.settings.db_path)
        self.addCleanup(conn.close)
        self.conn = conn
        drafts = admin.PolicyDrafts()
        msg = admin.prepare(conn, self.settings, None, {"action": "policy.approve", "body": EXAMPLE}, drafts)
        admin.confirm(conn, self.settings, None, msg, sign(ADMIN, msg), drafts)
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE, follow_redirects=False)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    # -- the connector's side

    def register(self, redirect=CALLBACK, name="Claude"):
        return self.client.post("/register", json={
            "redirect_uris": [redirect], "client_name": name, "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})

    def authorize(self, client_id, challenge, state="st8"):
        r = self.client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK, "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256", "resource": f"{BASE}/mcp"})
        self.assertEqual(r.status_code, 302, r.text)
        location = urlparse(r.headers["location"])
        self.assertEqual(location.path, "/oauth/grant")
        return parse_qs(location.query)["r"][0]

    def post(self, path, body):
        return self.client.post(path, content=json.dumps(body), headers=JSON)

    def approve(self, sealed, signer=ADMIN):
        message = self.post("/oauth/api/challenge", {"r": sealed, "address": signer.address}).json()["message"]
        return self.post("/oauth/api/approve", {"r": sealed, "message": message, "signature": sign(signer, message)})

    def token(self, **form):
        return self.client.post("/token", data=form)

    def connect(self):
        """The whole dance; returns (client_id, tokens)."""
        client_id = self.register().json()["client_id"]
        verifier, challenge = pkce()
        sealed = self.authorize(client_id, challenge)
        r = self.approve(sealed)
        self.assertEqual(r.status_code, 200, r.text)
        back = urlparse(r.json()["redirect"])
        self.assertEqual(f"{back.scheme}://{back.netloc}{back.path}", CALLBACK)
        q = parse_qs(back.query)
        self.assertEqual(q["state"], ["st8"])
        t = self.token(grant_type="authorization_code", code=q["code"][0], redirect_uri=CALLBACK,
                       client_id=client_id, code_verifier=verifier, resource=f"{BASE}/mcp")
        self.assertEqual(t.status_code, 200, t.text)
        return client_id, t.json()

    def mcp(self, token, tool, **args):
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": "2025-06-18", "Authorization": f"Bearer {token}"}
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        return self.client.post("/mcp", headers=h, content=json.dumps(body))


class Flow(OAuth):
    def test_discovery_points_at_this_server(self):
        prm = self.client.get("/.well-known/oauth-protected-resource/mcp").json()
        self.assertEqual(prm["resource"].rstrip("/"), f"{BASE}/mcp")
        meta = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(meta["registration_endpoint"], f"{BASE}/register")
        self.assertIn("S256", meta["code_challenge_methods_supported"])
        unauth = self.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                  headers={"Accept": "application/json, text/event-stream"})
        self.assertEqual(unauth.status_code, 401)
        self.assertIn("oauth-protected-resource", unauth.headers["www-authenticate"])

    def test_connect_and_use_memory_as_the_brain(self):
        _, tokens = self.connect()
        self.assertEqual(tokens["expires_in"], 7 * 24 * 3600)
        r = self.mcp(tokens["access_token"], "write", subject="self/first", kind="fact", excerpt="hello", pinned=True)
        self.assertFalse(r.json()["result"]["isError"], r.text)
        boot = json.loads(self.mcp(tokens["access_token"], "boot").json()["result"]["content"][0]["text"])
        self.assertEqual(boot["voice"], "brain")
        self.assertEqual(boot["core"][0]["excerpt"], "hello")
        grant = self.conn.execute("SELECT * FROM keys WHERE voice = 'brain'").fetchone()
        self.assertEqual(grant["label"], "Claude connector, via claude.ai")
        self.assertIsNone(grant["secret_hash"])
        entry = self.conn.execute("SELECT * FROM entries").fetchone()
        self.assertEqual((entry["voice"], entry["key_id"]), ("brain", grant["key_id"]))

    def test_tokens_are_stored_only_as_hashes(self):
        _, tokens = self.connect()
        dump = "\n".join(self.conn.iterdump())
        self.assertNotIn(tokens["access_token"], dump)
        self.assertNotIn(tokens["refresh_token"], dump)

    def test_refresh_rotates_and_old_refresh_dies(self):
        client_id, tokens = self.connect()
        r = self.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"], client_id=client_id)
        self.assertEqual(r.status_code, 200, r.text)
        new = r.json()
        self.assertNotEqual(new["refresh_token"], tokens["refresh_token"])
        self.assertEqual(self.mcp(new["access_token"], "boot").status_code, 200)
        again = self.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"], client_id=client_id)
        self.assertEqual(again.status_code, 400)

    def test_revoking_the_grant_on_the_admin_page_cuts_its_tokens(self):
        client_id, tokens = self.connect()
        key_id = self.conn.execute("SELECT key_id FROM keys WHERE voice = 'brain'").fetchone()[0]
        policy = svc.load_approved_policy(self.conn, self.settings.server_name, ADMIN.address)
        msg = admin.prepare(self.conn, self.settings, policy, {"action": "keys.revoke", "key_id": key_id})
        admin.confirm(self.conn, self.settings, policy, msg, sign(ADMIN, msg))
        self.assertEqual(self.mcp(tokens["access_token"], "boot").status_code, 401)
        r = self.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"], client_id=client_id)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(admin.keys(self.conn)[-1]["revoked_at"] is not None, True)

    def test_connector_disconnect_revokes_its_tokens_not_the_grant(self):
        client_id, tokens = self.connect()
        # The SDK's revocation form requires the client_secret field even for public clients.
        r = self.client.post("/revoke", data={"token": tokens["access_token"], "client_id": client_id,
                                              "client_secret": ""})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.mcp(tokens["access_token"], "boot").status_code, 401)
        self.assertIsNone(self.conn.execute("SELECT revoked_at FROM keys WHERE voice = 'brain'").fetchone()[0])

    def test_deny_returns_access_denied(self):
        client_id = self.register().json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        back = urlparse(self.post("/oauth/api/deny", {"r": sealed}).json()["redirect"])
        self.assertEqual(parse_qs(back.query)["error"], ["access_denied"])
        self.assertEqual(parse_qs(back.query)["state"], ["st8"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM keys WHERE voice = 'brain'").fetchone()[0], 0)


class Attacks(OAuth):
    def test_only_claudes_callback_may_register(self):
        r = self.register(redirect="https://evil.example/callback")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_redirect_uri")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0], 0)

    def test_only_the_admin_wallet_can_approve(self):
        client_id = self.register().json()["client_id"]
        r = self.approve(self.authorize(client_id, pkce()[1]), signer=MALLORY)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not the admin wallet", r.json()["error"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM keys WHERE voice = 'brain'").fetchone()[0], 0)

    def test_a_tampered_link_is_refused(self):
        client_id = self.register().json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        body, mac = sealed.split(".")
        req = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        req["p"] = pkce()[1]  # an attacker's own PKCE challenge
        forged = base64.urlsafe_b64encode(json.dumps(req, separators=(",", ":")).encode()).rstrip(b"=").decode()
        self.assertEqual(self.post("/oauth/api/describe", {"r": f"{forged}.{mac}"}).status_code, 400)

    def test_an_approval_signature_fits_only_its_own_request(self):
        client_id = self.register().json()["client_id"]
        first, second = self.authorize(client_id, pkce()[1]), self.authorize(client_id, pkce()[1])
        message = self.post("/oauth/api/challenge", {"r": first, "address": ADMIN.address}).json()["message"]
        r = self.post("/oauth/api/approve", {"r": second, "message": message, "signature": sign(ADMIN, message)})
        self.assertEqual(r.status_code, 400)

    def test_an_admin_sign_in_signature_cannot_approve_a_grant(self):
        client_id = self.register().json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        login = self.post("/admin/api/login/challenge", {"address": ADMIN.address}).json()["message"]
        r = self.post("/oauth/api/approve", {"r": sealed, "message": login, "signature": sign(ADMIN, login)})
        self.assertEqual(r.status_code, 400)

    def test_an_approval_works_once(self):
        client_id = self.register().json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        message = self.post("/oauth/api/challenge", {"r": sealed, "address": ADMIN.address}).json()["message"]
        body = {"r": sealed, "message": message, "signature": sign(ADMIN, message)}
        self.assertEqual(self.post("/oauth/api/approve", body).status_code, 200)
        self.assertEqual(self.post("/oauth/api/approve", body).status_code, 400)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM keys WHERE voice = 'brain'").fetchone()[0], 1)

    def test_a_code_works_once_and_needs_the_verifier(self):
        client_id = self.register().json()["client_id"]
        verifier, challenge = pkce()
        code = parse_qs(urlparse(self.approve(self.authorize(client_id, challenge)).json()["redirect"]).query)["code"][0]
        wrong = self.token(grant_type="authorization_code", code=code, redirect_uri=CALLBACK,
                           client_id=client_id, code_verifier=pkce()[0])
        self.assertEqual(wrong.status_code, 400)
        ok = self.token(grant_type="authorization_code", code=code, redirect_uri=CALLBACK,
                        client_id=client_id, code_verifier=verifier)
        self.assertEqual(ok.status_code, 200, ok.text)
        again = self.token(grant_type="authorization_code", code=code, redirect_uri=CALLBACK,
                           client_id=client_id, code_verifier=verifier)
        self.assertEqual(again.status_code, 400)

    def test_tokens_for_another_resource_are_refused(self):
        client_id = self.register().json()["client_id"]
        r = self.client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK, "state": "s",
            "code_challenge": pkce()[1], "code_challenge_method": "S256", "resource": "https://other.example/mcp"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(parse_qs(urlparse(r.headers["location"]).query)["error"], ["invalid_target"])

    def test_malformed_and_unknown_tokens_get_401(self):
        for token in ("aiga_" + "A" * 43, "aigr_" + "A" * 43, "nonsense", "aig_" + "A" * 43):
            self.assertEqual(self.mcp(token, "boot").status_code, 401, token)

    def test_registrations_keep_only_what_the_flow_needs(self):
        r = self.client.post("/register", json={
            "redirect_uris": [CALLBACK], "client_name": "C" * 500, "software_id": "x" * 10000,
            "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"]})
        self.assertEqual(r.status_code, 201, r.text)
        info = json.loads(self.conn.execute("SELECT info FROM oauth_clients").fetchone()[0])
        self.assertNotIn("software_id", info)
        self.assertEqual(len(info["client_name"]), 60)
        big = self.client.post("/register", json={"redirect_uris": [CALLBACK], "software_id": "x" * 40000})
        self.assertEqual(big.status_code, 413)

    def test_registration_limit_is_per_address(self):
        for _ in range(10):
            self.assertEqual(self.register().status_code, 201)
        self.assertEqual(self.register().status_code, 429)
        other = TestClient(self.client.app, base_url=BASE, client=("203.0.113.9", 5000))
        self.assertEqual(other.post("/register", json={
            "redirect_uris": [CALLBACK], "client_name": "Claude", "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"]}).status_code, 201)

    def test_unused_registrations_are_pruned_and_used_ones_kept(self):
        self.connect()  # one client that got tokens
        self.conn.execute("INSERT INTO oauth_clients VALUES ('stale', '{}', '2020-01-01T00:00:00.000000Z')")
        self.conn.execute("UPDATE oauth_clients SET created_at = '2020-01-01T00:00:00.000000Z'")
        self.register()
        ids = [r[0] for r in self.conn.execute("SELECT client_id FROM oauth_clients")]
        self.assertNotIn("stale", ids)
        self.assertEqual(len(ids), 2)  # the used one (despite its age) and the new one
        used = self.conn.execute("SELECT client_id FROM oauth_tokens LIMIT 1").fetchone()[0]
        with self.assertRaises(Exception):
            self.conn.execute("DELETE FROM oauth_clients WHERE client_id = ?", (used,))

    def test_the_page_shows_the_same_name_the_wallet_signs(self):
        client_id = self.register(name=chr(0x202E) + "edualC" + chr(0x202C)).json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        about = self.post("/oauth/api/describe", {"r": sealed}).json()
        self.assertEqual(about["client_name"], "edualC")
        self.assertIn("to edualC (returns to claude.ai)", about["statement"])
        self.assertLess(about["age_seconds"], 60)

    def test_a_link_has_one_spelling(self):
        client_id = self.register().json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        respelled = sealed[:10] + "!!" + sealed[10:]
        self.assertEqual(self.post("/oauth/api/describe", {"r": respelled}).status_code, 400)

    def test_connector_names_cannot_disguise_the_signed_message(self):
        client_id = self.register(name="Claude" + chr(0x202E) + "\nURI: https://evil.example").json()["client_id"]
        sealed = self.authorize(client_id, pkce()[1])
        message = self.post("/oauth/api/challenge", {"r": sealed, "address": ADMIN.address}).json()["message"]
        self.assertEqual(len(message.split("\n")), 12)
        self.assertNotIn(chr(0x202E), message)


if __name__ == "__main__":
    unittest.main()
