"""Run: python -m unittest test_server -v

Drives the real ASGI app over HTTP (Starlette's TestClient), JSON-RPC in, JSON out.
"""

import hashlib
import itertools
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml
from eth_account import Account
from eth_account.messages import encode_defunct
from starlette.testclient import TestClient

import admin_auth
import aingram_admin
import aingram_core as core
import aingram_server
import aingram_service as svc
from aingram_config import Settings

HERE = Path(__file__).parent
ADMIN = Account.create()
SERVER = "aingram.test"
PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"


class Harness(unittest.TestCase):
    code_cap = 60

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        d = Path(self.dir.name)
        self.policy_path = d / "policy.yaml"
        raw = yaml.safe_load((HERE / "policy.example.yaml").read_text(encoding="utf-8"))
        raw["voices"]["code"]["daily_write_cap"] = self.code_cap
        self.policy_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
        self.settings = Settings.from_env({
            "AINGRAM_DB": str(d / "store.db"), "AINGRAM_POLICY": str(self.policy_path),
            "AINGRAM_SERVER_NAME": SERVER, "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        self.conn = core.connect(self.settings.db_path)
        self.addCleanup(self.conn.close)
        self.approve_policy()
        self.brain = self.add_key("k_brain_t", "brain")
        self.code = self.add_key("k_code_t", "code")
        self.ids = itertools.count(1)
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def approve_policy(self):
        sha = svc.store_policy_version(self.conn, self.policy_path.read_text(encoding="utf-8")).sha256
        msg = admin_auth.prepare(self.conn, SERVER, {"action": "policy.approve", "sha256": sha})
        sig = ADMIN.sign_message(encode_defunct(text=msg)).signature.hex()
        admin_auth.authorize(self.conn, SERVER, ADMIN.address, msg, sig)
        admin_auth.log_outcome(self.conn, msg, ok=True)

    def add_key(self, key_id, voice):
        secret = svc.new_secret()
        core.add_key(self.conn, key_id=key_id, voice=voice, secret_hash=svc.hash_secret(secret))
        return secret

    def rpc(self, secret, method, params=None, headers=None):
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": "2025-06-18"}
        if secret:
            h["Authorization"] = f"Bearer {secret}"
        h.update(headers or {})
        body = {"jsonrpc": "2.0", "id": next(self.ids), "method": method, "params": params or {}}
        return self.client.post("/mcp", headers=h, content=json.dumps(body))

    def call(self, secret, tool, **args):
        """Returns (ok, payload): payload is the parsed JSON result, or the error text."""
        r = self.rpc(secret, "tools/call", {"name": tool, "arguments": args})
        self.assertEqual(r.status_code, 200, r.text)
        result = r.json()["result"]
        text = result["content"][0]["text"]
        if result.get("isError"):
            return False, text
        return True, json.loads(text)

    def ok(self, secret, tool, **args):
        ok, payload = self.call(secret, tool, **args)
        self.assertTrue(ok, payload)
        self.assertIn("head", payload)
        return payload

    def refused(self, secret, tool, fragment, **args):
        ok, payload = self.call(secret, tool, **args)
        self.assertFalse(ok, payload)
        self.assertIn(fragment, payload)

    def entry(self, short_id):
        return self.conn.execute("SELECT * FROM entries WHERE id = ?",
                                 (svc.resolve_id(self.conn, short_id),)).fetchone()


class Auth(Harness):
    def test_no_key_is_401(self):
        self.assertEqual(self.rpc(None, "tools/list").status_code, 401)

    def test_unknown_key_is_401(self):
        self.assertEqual(self.rpc(svc.new_secret(), "tools/list").status_code, 401)
        self.assertEqual(self.rpc("not-a-key", "tools/list").status_code, 401)

    def test_revoked_key_is_401(self):
        core.revoke_key(self.conn, "k_code_t")
        self.assertEqual(self.rpc(self.code, "tools/list").status_code, 401)

    def test_admin_key_row_cannot_authenticate(self):
        svc.ensure_admin_key(self.conn, ADMIN.address)
        # It has no secret at all, so there is nothing to present.
        self.assertIsNone(self.conn.execute(
            "SELECT secret_hash FROM keys WHERE key_id = ?", (svc.ADMIN_KEY_ID,)).fetchone()[0])

    def test_healthz_is_open_and_says_nothing(self):
        r = self.client.get("/healthz")
        self.assertEqual(r.json(), {"ok": True})

    def test_foreign_host_header_refused(self):
        r = self.rpc(self.code, "tools/list", headers={"Host": "evil.example"})
        self.assertIn(r.status_code, (400, 403, 421))

    def test_five_tools(self):
        r = self.rpc(self.code, "tools/list")
        names = sorted(t["name"] for t in r.json()["result"]["tools"])
        self.assertEqual(names, ["boot", "read", "recall", "redact", "write"])

    def test_last_used_recorded(self):
        self.rpc(self.code, "tools/list")
        self.assertIsNotNone(self.conn.execute(
            "SELECT last_used_at FROM keys WHERE key_id = 'k_code_t'").fetchone()[0])


class Voices(Harness):
    def test_voice_comes_from_the_key_not_the_request(self):
        ok, payload = self.call(self.code, "write", subject="aingram/build", kind="decision",
                                excerpt="e", voice="brain")
        if ok:  # extra arguments ignored: the entry must still be code's
            self.assertEqual(self.entry(payload["id"])["voice"], "code")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM entries WHERE voice = 'brain'").fetchone()[0], 0)

    def test_code_writes_its_kinds_under_its_subjects(self):
        out = self.ok(self.code, "write", subject="aingram/build", kind="gotcha",
                      excerpt="SQLite needs FTS5", keywords=["sqlite"], body="details")
        self.assertEqual(self.entry(out["id"])["key_id"], "k_code_t")

    def test_code_refusals_carry_policy_reasons(self):
        self.refused(self.code, "write", "only the brain", subject="people/sister", kind="decision", excerpt="e")
        self.refused(self.code, "write", "only these kinds", subject="aingram/x", kind="fact", excerpt="e")
        self.refused(self.code, "write", "may not pin", subject="aingram/x", kind="decision",
                     excerpt="e", pinned=True)
        self.refused(self.code, "write", "reserved", subject="_redactions", kind="decision", excerpt="e")

    def test_excerpt_cap(self):
        self.refused(self.brain, "write", "max 300", subject="misc", kind="fact", excerpt="x" * 301)


class Caps(Harness):
    code_cap = 2

    def test_daily_cap(self):
        for i in range(2):
            self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt=f"e{i}")
        self.refused(self.code, "write", "daily cap of 2", subject="aingram/x", kind="decision", excerpt="e")
        self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="brain unaffected")

    def test_cap_shared_across_code_keys(self):
        other = self.add_key("k_code_2", "code")
        self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="a")
        self.ok(other, "write", subject="aingram/x", kind="decision", excerpt="b")
        self.refused(other, "write", "daily cap", subject="aingram/x", kind="decision", excerpt="c")


class Views(Harness):
    def test_boot(self):
        self.ok(self.brain, "write", subject="identity/core", kind="fact", excerpt="who I am", pinned=True)
        self.ok(self.brain, "write", subject="misc/day", kind="breadcrumb", excerpt="did a thing")
        c1 = self.ok(self.code, "write", subject="aingram/build", kind="shipped", excerpt="step 4")
        self.ok(self.code, "write", subject="project-a/x", kind="gotcha", excerpt="g")
        b = self.ok(self.brain, "boot")
        self.assertEqual([e["excerpt"] for e in b["core"]], ["who I am"])
        self.assertEqual([e["excerpt"] for e in b["recent"]], ["did a thing"])
        self.assertIn("Code logged 2 entries", b["code_digest"])
        self.assertIn(c1["id"], b["code_digest"])
        self.assertEqual(b["writes_left_today"], 300 - 2)
        again = self.ok(self.brain, "boot")
        self.assertIn("nothing", again["code_digest"])

    def test_code_entries_never_in_brain_core_or_tail(self):
        self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="code only")
        b = self.ok(self.brain, "boot")
        self.assertEqual(b["core"], [])
        self.assertEqual(b["recent"], [])

    def test_redaction_notice_says_that_not_what(self):
        e = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="the secret thing")
        self.ok(self.brain, "boot")
        self.ok(self.brain, "redact", id=e["id"], reason="forget it")
        b = self.ok(self.brain, "boot")
        self.assertEqual(b["redactions"], "1 entry redacted since you last woke")
        self.assertNotIn("secret thing", json.dumps(b))
        self.assertNotIn("forget it", json.dumps(b))

    def test_recall_subject_is_folded(self):
        old = self.ok(self.brain, "write", subject="people/ada", kind="fact", excerpt="Ada lives in Porto")
        self.ok(self.brain, "write", subject="people/ada", kind="correction", excerpt="Ada lives in Lisbon",
                supersedes=old["id"])
        hits = self.ok(self.brain, "recall", subject="people/ada")["hits"]
        self.assertEqual([h["excerpt"] for h in hits], ["Ada lives in Lisbon"])
        self.assertNotIn("body", hits[0])

    def test_recall_subtree(self):
        self.ok(self.brain, "write", subject="projects/a", kind="fact", excerpt="a")
        self.ok(self.brain, "write", subject="projects/a/b", kind="fact", excerpt="b")
        self.ok(self.brain, "write", subject="projectsX", kind="fact", excerpt="x")
        hits = self.ok(self.brain, "recall", subject="projects/**")["hits"]
        self.assertEqual(sorted(h["excerpt"] for h in hits), ["a", "b"])

    def test_recall_query(self):
        self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="zanzibar trip", body="b")
        self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="other", body="b")
        hits = self.ok(self.brain, "recall", query="zanzibar")["hits"]
        self.assertEqual(len(hits), 1)
        # Operator characters are words, never FTS syntax.
        self.ok(self.brain, "recall", query='zanzibar" OR (NEAR body:*')

    def test_recall_needs_exactly_one_mode(self):
        self.refused(self.brain, "recall", "exactly one")
        self.refused(self.brain, "recall", "exactly one", subject="a", query="b")

    def test_read_full_entry_and_reinforce(self):
        e = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="e", body="the full body",
                    keywords=["k"])
        full = self.ok(self.brain, "read", id=e["id"])
        self.assertEqual(full["body"], "the full body")
        self.assertEqual(full["keywords"], ["k"])
        sal = self.conn.execute("SELECT * FROM salience WHERE entry_id = ?", (full["id"],)).fetchone()
        self.assertEqual(sal["reinforcements"], 1)
        self.assertEqual(sal["half_life_days"], 180 * 1.5)

    def test_the_first_entrys_prev_is_genesis_not_a_gap(self):
        first = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="first")
        second = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="second")
        self.assertEqual(self.ok(self.brain, "read", id=first["id"])["prev"], "0" * 64)
        self.assertEqual(self.ok(self.brain, "read", id=second["id"])["prev"], first["id"])

    def test_several_outside_text_sources(self):
        e = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="catch-up", untrusted_ctx=["web", "meadow"])
        self.assertEqual(self.ok(self.brain, "read", id=e["id"])["untrusted_ctx"], "meadow,web")
        same = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="again", untrusted_ctx="meadow")
        self.assertEqual(self.ok(self.brain, "read", id=same["id"])["untrusted_ctx"], "meadow")
        self.refused(self.brain, "write", "up to 4", subject="misc", kind="fact", excerpt="x",
                     untrusted_ctx=["a", "b", "c", "d", "e"])
        self.refused(self.brain, "write", "up to 4", subject="misc", kind="fact", excerpt="x", untrusted_ctx=["Web Page"])

    def test_refs_reinforce_and_link(self):
        a = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="a")
        b = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="b", refs=[a["id"]])
        self.assertEqual(self.ok(self.brain, "read", id=b["id"])["refs"], [a["id"]])
        full_a = svc.resolve_id(self.conn, a["id"])
        self.assertEqual(self.conn.execute("SELECT reinforcements FROM salience WHERE entry_id = ?",
                                           (full_a,)).fetchone()[0], 1)

    def test_head_tracks_writes(self):
        h1 = self.ok(self.brain, "boot")["head"]
        w = self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="e")
        self.assertEqual(w["head"]["seq"], h1["seq"] + 1)
        self.assertEqual(w["head"]["id"], w["id"])
        # The full hash anchors checks: it is the exact id of the newest entry in the chain.
        newest = self.conn.execute("SELECT id FROM entries ORDER BY seq DESC LIMIT 1").fetchone()[0]
        self.assertEqual(w["head"]["id_full"], newest)
        self.assertEqual(len(w["head"]["id_full"]), 64)
        self.assertTrue(newest.startswith(w["head"]["id"]))

    def test_every_tool_returns_the_full_head(self):
        e = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="x")
        for tool, args in (("boot", {}), ("recall", {"subject": "misc"}), ("read", {"id": e["id"]}),
                           ("redact", {"id": e["id"], "reason": "r"})):
            self.assertEqual(len(self.ok(self.brain, tool, **args)["head"]["id_full"]), 64, tool)


class Supersede(Harness):
    def test_code_cannot_retire_brain_entries(self):
        b = self.ok(self.brain, "write", subject="aingram/x", kind="decision", excerpt="brain's call")
        self.refused(self.code, "write", "only entries it wrote", subject="aingram/x", kind="decision",
                     excerpt="overrule", supersedes=b["id"])

    def test_cross_subject_supersede_refused(self):
        a = self.ok(self.brain, "write", subject="misc/a", kind="fact", excerpt="a")
        self.refused(self.brain, "write", "same subject", subject="misc/b", kind="fact", excerpt="b",
                     supersedes=a["id"])


class Redaction(Harness):
    def test_brain_redacts_own_and_chain_verifies(self):
        e = self.ok(self.brain, "write", subject="people/x", kind="fact", excerpt="private", body="secret")
        c = self.ok(self.brain, "write", subject="people/x", kind="correction", excerpt="fix",
                    supersedes=e["id"])
        out = self.ok(self.brain, "redact", id=e["id"], reason="asked")
        self.assertEqual(out["flagged_for_review"], [c["id"]])
        self.assertIsNone(self.ok(self.brain, "read", id=e["id"])["body"])
        self.assertEqual(core.verify(self.conn), [])
        self.assertEqual(self.ok(self.brain, "recall", query="secret")["hits"], [])

    def test_code_cannot_redact(self):
        e = self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="e")
        self.refused(self.code, "redact", "may not redact", id=e["id"], reason="r")

    def test_brain_cannot_redact_code_entries(self):
        e = self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="e")
        self.refused(self.brain, "redact", "only entries it wrote", id=e["id"], reason="r")

    def test_reason_required(self):
        e = self.ok(self.brain, "write", subject="misc", kind="fact", excerpt="e")
        self.refused(self.brain, "redact", "reason", id=e["id"], reason="  ")


class ReadLimits(Harness):
    """Code may read only its own projects: hidden entries must be indistinguishable from missing ones."""

    def setUp(self):
        super().setUp()
        raw = yaml.safe_load(self.policy_path.read_text())
        raw["voices"]["code"]["may_read_subjects"] = ["aingram/**"]
        self.policy_path.write_text(yaml.safe_dump(raw))
        self.approve_policy()
        self.hidden = self.ok(self.brain, "write", subject="self/secret", kind="fact", excerpt="private")["id"]
        self.missing = "f" * 12

    def same_refusal(self, tool, **args):
        _, a = self.call(self.code, tool, **{k: (self.hidden if v == "ID" else v) for k, v in args.items()})
        _, b = self.call(self.code, tool, **{k: (self.missing if v == "ID" else v) for k, v in args.items()})
        self.assertEqual(a.replace(self.hidden, "X"), b.replace(self.missing, "X"))

    def test_read_redact_supersede_refs_leak_nothing(self):
        self.same_refusal("read", id="ID")
        self.same_refusal("redact", id="ID", reason="r")
        self.same_refusal("write", subject="aingram/x", kind="decision", excerpt="e", supersedes="ID")
        self.same_refusal("write", subject="aingram/x", kind="decision", excerpt="e", refs=["ID"])

    def test_links_to_hidden_entries_are_not_shown(self):
        own = self.ok(self.code, "write", subject="aingram/x", kind="decision", excerpt="e")
        full = self.ok(self.code, "read", id=own["id"])
        self.assertIsNone(full["prev"])  # the previous entry is the hidden one
        self.assertNotIn(self.hidden, json.dumps(full))

    def test_recall_and_boot_hide_it(self):
        self.assertEqual(self.ok(self.code, "recall", query="private")["hits"], [])
        self.assertEqual(self.ok(self.code, "recall", subject="self/**")["hits"], [])
        boot = self.ok(self.code, "boot")
        boot.pop("head")  # the chain head is shown to every voice by design; reading it is still refused
        self.assertNotIn(self.hidden, json.dumps(boot))


class PolicyLifecycle(Harness):
    def test_new_server_starts_but_tools_wait_for_a_policy(self):
        settings = Settings.from_env({
            "AINGRAM_DB": str(Path(self.dir.name) / "fresh.db"), "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        conn = core.connect(settings.db_path)
        self.addCleanup(conn.close)
        secret = svc.new_secret()
        core.add_key(conn, key_id="k_code_f", voice="code", secret_hash=svc.hash_secret(secret))
        with TestClient(aingram_server.create_app(settings), base_url=BASE) as client:
            self.client, saved = client, self.client
            try:
                self.refused(secret, "boot", "not set up yet")
            finally:
                self.client = saved

    def test_editing_the_file_changes_nothing(self):
        raw = yaml.safe_load(self.policy_path.read_text())
        raw["voices"]["code"]["may_write_subjects"].append("newproject/**")
        self.policy_path.write_text(yaml.safe_dump(raw))
        self.refused(self.code, "write", "may not write under", subject="newproject/x",
                     kind="decision", excerpt="e")

    def test_signed_approval_applies_on_next_request(self):
        raw = yaml.safe_load(self.policy_path.read_text())
        raw["voices"]["code"]["may_write_subjects"].append("newproject/**")
        self.refused(self.code, "write", "may not write under", subject="newproject/x",
                     kind="decision", excerpt="e")
        self.policy_path.write_text(yaml.safe_dump(raw))
        self.approve_policy()
        self.ok(self.code, "write", subject="newproject/x", kind="decision", excerpt="e")

    def restart(self):
        self.client.__exit__(None, None, None)
        app = aingram_server.AIngram(self.settings)
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE)
        self.client.__enter__()
        return app

    def test_altered_policy_text_fails_closed(self):
        # Simulates someone with write access to the file: the stored text no longer matches its signed hash.
        sha = svc.approved_policy_hash(self.conn, SERVER, ADMIN.address)
        self.conn.execute("DROP TRIGGER policy_versions_no_update")
        self.conn.execute("UPDATE policy_versions SET body = body || '\n# swapped\n' WHERE sha256 = ?", (sha,))
        app = self.restart()
        self.assertIsNone(app.policy)
        self.assertIn("does not match", app.policy_problem)
        self.refused(self.code, "boot", "not set up yet")

    def test_policy_outdated_by_an_upgrade_fails_closed(self):
        # An approved policy written before a setting existed no longer validates.
        raw = yaml.safe_load(self.policy_path.read_text())
        del raw["decay"]["fade_below"]
        old = yaml.safe_dump(raw)
        self.conn.execute("INSERT INTO policy_versions VALUES (?, ?, 'x')",
                          (hashlib.sha256(old.encode()).hexdigest(), old))
        msg = admin_auth.prepare(self.conn, SERVER, {"action": "policy.approve",
                                                     "sha256": hashlib.sha256(old.encode()).hexdigest()})
        admin_auth.authorize(self.conn, SERVER, ADMIN.address, msg,
                             ADMIN.sign_message(encode_defunct(text=msg)).signature.hex())
        app = self.restart()
        self.assertIn("fade_below", app.policy_problem)
        self.refused(self.code, "boot", "not set up yet")
        # The admin page offers the outdated text to fix, not the example.
        state = aingram_admin.policy_state(self.conn, self.settings, None)
        self.assertNotIn("fade_below", state["draft"])


if __name__ == "__main__":
    unittest.main()
