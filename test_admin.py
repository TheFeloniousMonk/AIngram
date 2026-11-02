"""Run: python -m unittest test_admin -v

Admin operations (prepare a command, the wallet signs it, confirm performs it)
and the read-only CLI. The HTTP side is in test_admin_web.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

import admin_auth
import aingram_admin as admin
import aingram_core as core
import aingram_service as svc
from aingram_config import Settings

HERE = Path(__file__).parent
ADMIN = Account.create()
MALLORY = Account.create()
SERVER = "aingram.test"
EXAMPLE = (HERE / "policy.example.yaml").read_text(encoding="utf-8")


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


class Ops(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)  # registered first, so it runs after connections close
        self.env = {"AINGRAM_DB": str(Path(self.dir.name) / "store.db"),
                    "AINGRAM_SERVER_NAME": SERVER, "AINGRAM_ADMIN_ADDRESS": ADMIN.address}
        self.settings = Settings.from_env(self.env, need_admin=True)
        self.conn = core.connect(self.settings.db_path)
        self.addCleanup(self.conn.close)
        self.policy = None
        self.drafts = admin.PolicyDrafts()

    def policy_now(self):
        return svc.load_approved_policy(self.conn, SERVER, ADMIN.address)

    def do(self, request, signer=ADMIN):
        message = admin.prepare(self.conn, self.settings, self.policy, request, self.drafts)
        result = admin.confirm(self.conn, self.settings, self.policy, message, sign(signer, message), self.drafts)
        self.policy = self.policy_now()
        return result

    def approve(self, body=EXAMPLE):
        return self.do({"action": "policy.approve", "body": body})

    def mint(self, label="build bot"):
        return self.do({"action": "keys.mint", "voice": "code", "label": label})

    def count(self, table):
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class Policy(Ops):
    def test_nothing_is_approved_on_a_new_store(self):
        self.assertIsNone(self.policy_now())
        state = admin.policy_state(self.conn, self.settings, None)
        self.assertIsNone(state["approved"])
        self.assertEqual(state["draft"], EXAMPLE)  # the example is the first draft

    def test_approve_exact_text(self):
        self.approve()
        self.assertEqual(self.policy.sha256, svc.parse_policy(EXAMPLE.encode()).sha256)
        self.assertEqual(admin.policy_state(self.conn, self.settings, self.policy)["approved"]["body"], EXAMPLE)
        # Any edit, even a comment, needs a new signature.
        self.approve(EXAMPLE + "\n# edited\n")
        self.assertTrue(svc.policy_body(self.conn, self.policy.sha256).endswith("# edited\n"))

    def test_check_shows_the_diff_and_stores_nothing(self):
        self.approve()
        r = admin.policy_check(self.conn, EXAMPLE.replace("recent_tail: 8", "recent_tail: 9"), self.policy)
        self.assertTrue(r["valid"])
        self.assertIn("-  recent_tail: 8", r["diff"])
        self.assertIn("+  recent_tail: 9", r["diff"])
        self.assertEqual(self.count("policy_versions"), 1)
        self.assertTrue(admin.policy_check(self.conn, EXAMPLE, self.policy)["unchanged"])

    def test_invalid_policy_is_never_offered_for_signing(self):
        self.assertFalse(admin.policy_check(self.conn, "voices: {}\n", None)["valid"])
        with self.assertRaisesRegex(admin.Refused, "not valid"):
            admin.prepare(self.conn, self.settings, None, {"action": "policy.approve", "body": "voices: {}\n"})
        self.assertEqual(self.count("admin_nonces"), 0)

    def test_approving_the_current_policy_again_is_refused(self):
        self.approve()
        with self.assertRaisesRegex(admin.Refused, "already"):
            self.approve()

    def test_wrong_wallet_approves_nothing(self):
        with self.assertRaisesRegex(admin.Refused, "not from the admin address"):
            self.do({"action": "policy.approve", "body": EXAMPLE}, signer=MALLORY)
        self.assertIsNone(self.policy_now())
        self.assertEqual(self.count("admin_log"), 0)

    def test_forged_approval_in_admin_log_is_ignored(self):
        sha = svc.store_policy_version(self.conn, EXAMPLE).sha256
        self.conn.execute("INSERT INTO admin_nonces VALUES ('n1', 'x', 'y', 'z')")
        fake = admin_auth.build_message(SERVER, {"action": "policy.approve", "sha256": sha},
                                        "n1", "2026-11-01T00:00:00.000000Z", "2026-11-01T00:10:00.000000Z")
        self.conn.execute("INSERT INTO admin_log (at, event, nonce, action, message, signature) VALUES "
                          "('x', 'authorized', 'n1', '{\"action\":\"policy.approve\"}', ?, ?)",
                          (fake, sign(MALLORY, fake)))
        self.assertIsNone(self.policy_now())

    def test_a_new_admin_wallet_starts_without_a_policy(self):
        self.approve()
        self.assertIsNone(svc.load_approved_policy(self.conn, SERVER, MALLORY.address))
        self.assertIsNone(svc.load_approved_policy(self.conn, "other.server", ADMIN.address))

    def test_unsigned_drafts_never_reach_the_database(self):
        for i in range(5):
            admin.prepare(self.conn, self.settings, None,
                          {"action": "policy.approve", "body": EXAMPLE + f"\n# {i}\n"}, self.drafts)
        self.assertEqual(self.count("policy_versions"), 0)

    def test_an_older_draft_cannot_land_after_a_newer_one(self):
        old = admin.prepare(self.conn, self.settings, None,
                            {"action": "policy.approve", "body": EXAMPLE + "\n# old\n"}, self.drafts)
        self.approve(EXAMPLE + "\n# new\n")
        logged = self.count("admin_log")
        with self.assertRaisesRegex(admin.Refused, "replaced"):
            admin.confirm(self.conn, self.settings, self.policy, old, sign(ADMIN, old), self.drafts)
        self.assertEqual(self.count("admin_log"), logged)  # the old command was never authorized
        self.assertTrue(svc.policy_body(self.conn, self.policy.sha256).endswith("# new\n"))

    def test_unsigned_rows_cannot_roll_back_the_policy(self):
        self.approve()
        old_nonce = self.conn.execute("SELECT nonce FROM admin_log WHERE event = 'authorized'").fetchone()[0]
        self.approve(EXAMPLE + "\n# v2\n")
        v2 = self.policy.sha256
        self.conn.execute("INSERT INTO admin_log (at, event, nonce, action) VALUES "
                          "('z', 'done', ?, '{\"action\":\"policy.approve\"}')", (old_nonce,))
        self.assertEqual(svc.approved_policy_hash(self.conn, SERVER, ADMIN.address), v2)

    def test_policy_history_and_admin_log_cannot_be_edited(self):
        self.approve()
        for sql in ("UPDATE admin_log SET detail = 'x'", "DELETE FROM admin_log",
                    "UPDATE policy_versions SET body = 'x'", "DELETE FROM policy_versions"):
            with self.assertRaises(sqlite3.IntegrityError, msg=sql):
                self.conn.execute(sql)


class Keys(Ops):
    def setUp(self):
        super().setUp()
        self.approve()

    def test_mint_shows_secret_once_and_stores_only_its_hash(self):
        r = self.mint()
        self.assertRegex(r["secret"], svc.SECRET_RE)
        row = self.conn.execute("SELECT * FROM keys WHERE key_id = ?", (r["key_id"],)).fetchone()
        self.assertEqual(row["secret_hash"], svc.hash_secret(r["secret"]))
        self.assertEqual(row["label"], "build bot")
        self.assertNotIn(r["secret"], "\n".join(self.conn.iterdump()))  # not in keys, admin_log, anywhere
        self.assertEqual(svc.authenticate(self.conn, r["secret"])["key_id"], r["key_id"])

    def test_wrong_wallet_changes_nothing(self):
        before = self.count("admin_log")
        with self.assertRaisesRegex(admin.Refused, "Nothing was changed"):
            self.do({"action": "keys.mint", "voice": "code", "label": "x"}, signer=MALLORY)
        self.assertEqual(self.count("keys"), 0)
        self.assertEqual(self.count("admin_log"), before)

    def test_a_signature_cannot_be_reused(self):
        message = admin.prepare(self.conn, self.settings, self.policy,
                                {"action": "keys.mint", "voice": "code", "label": "x"})
        signature = sign(ADMIN, message)
        admin.confirm(self.conn, self.settings, self.policy, message, signature)
        with self.assertRaisesRegex(admin.Refused, "replay"):
            admin.confirm(self.conn, self.settings, self.policy, message, signature)
        self.assertEqual(self.count("keys"), 1)

    def test_brain_keys_are_not_minted_here(self):
        with self.assertRaises(admin.Refused):
            admin.prepare(self.conn, self.settings, self.policy, {"action": "keys.mint", "voice": "brain", "label": "x"})

    def test_labels_cannot_disguise_the_message(self):
        for label in ("a" + chr(0x2028) + "Server: other", "a" + chr(0x202E) + "b", "a" + chr(10) + "b",
                      "   ", None, 7, "x" * 81):
            with self.assertRaises(admin.Refused, msg=repr(label)):
                admin.prepare(self.conn, self.settings, self.policy,
                              {"action": "keys.mint", "voice": "code", "label": label})
        self.assertEqual(self.count("admin_nonces"), 1)  # only the policy approval's

    def test_revoke(self):
        r = self.mint()
        self.do({"action": "keys.revoke", "key_id": r["key_id"]})
        self.assertIsNone(svc.authenticate(self.conn, r["secret"]))
        with self.assertRaisesRegex(admin.Refused, "already revoked"):
            self.do({"action": "keys.revoke", "key_id": r["key_id"]})

    def test_rotate_keeps_the_label(self):
        old = self.mint()
        new = self.do({"action": "keys.rotate", "key_id": old["key_id"]})
        self.assertEqual(new["revoked"], old["key_id"])
        self.assertIsNone(svc.authenticate(self.conn, old["secret"]))
        row = svc.authenticate(self.conn, new["secret"])
        self.assertEqual((row["voice"], row["label"]), ("code", "build bot"))

    def test_outcomes_are_logged(self):
        self.mint()
        events = [r[0] for r in self.conn.execute("SELECT event FROM admin_log ORDER BY log_id")]
        self.assertEqual(events, ["authorized", "done", "authorized", "done"])
        self.assertEqual(admin.admin_log(self.conn)[0]["event"], "done")


class Redact(Ops):
    def setUp(self):
        super().setUp()
        self.approve()
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        self.entry = core.append(self.conn, key_id="k_brain", subject="people/x", kind="fact",
                                 excerpt="private", keywords=["k"], body="private body")["id"]

    def test_admin_redacts_any_entry_and_sees_the_reason(self):
        self.do({"action": "redact", "id": self.entry[:12], "reason": "asked to forget"})
        row = self.conn.execute("SELECT * FROM entries WHERE id = ?", (self.entry,)).fetchone()
        self.assertIsNone(row["body"])
        rec = self.conn.execute("SELECT * FROM redactions WHERE entry_id = ?", (self.entry,)).fetchone()
        self.assertEqual((rec["reason"], rec["by_key"]), ("asked to forget", svc.ADMIN_KEY_ID))
        self.assertEqual(admin.entry(self.conn, self.entry)["redaction"]["reason"], "asked to forget")
        self.assertEqual(core.verify(self.conn), [])

    def test_tombstones_cannot_be_redacted(self):
        tomb = core.redact(self.conn, target_id=self.entry, by_key_id="k_brain", reason="r")["tombstone"]
        with self.assertRaises(admin.Refused):
            admin.prepare(self.conn, self.settings, self.policy, {"action": "redact", "id": tomb, "reason": "x"})

    def test_needs_a_policy(self):
        with self.assertRaisesRegex(admin.Refused, "approve a policy"):
            admin.prepare(self.conn, self.settings, None, {"action": "redact", "id": self.entry, "reason": "x"})


class Views(Ops):
    def test_entries_subjects_and_search(self):
        self.approve()
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        for i in range(3):
            core.append(self.conn, key_id="k_brain", subject=f"projects/p{i}", kind="fact",
                        excerpt=f"note {i}", keywords=[], body=f"lisbon {i}" if i else "")
        self.assertEqual([s["subject"] for s in admin.subjects(self.conn)],
                         ["projects/p0", "projects/p1", "projects/p2"])
        page = admin.entries(self.conn, limit=2)
        self.assertEqual([e["excerpt"] for e in page["entries"]], ["note 2", "note 1"])
        rest = admin.entries(self.conn, before=page["next_before"], limit=2)
        self.assertEqual([e["excerpt"] for e in rest["entries"]], ["note 0"])
        self.assertIsNone(rest["next_before"])
        self.assertEqual(len(admin.entries(self.conn, subject="projects/**")["entries"]), 3)
        self.assertEqual(len(admin.entries(self.conn, query="lisbon")["entries"]), 2)

    def test_browsing_does_not_reinforce(self):
        self.approve()
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        e = core.append(self.conn, key_id="k_brain", subject="m", kind="fact", excerpt="x", keywords=[],
                        body="", half_life_days=30.0)["id"]
        admin.entry(self.conn, e)
        self.assertEqual(self.conn.execute("SELECT reinforcements FROM salience WHERE entry_id = ?",
                                           (e,)).fetchone()[0], 0)


class CLI(Ops):
    def run_cli(self, *argv, env=None):
        self.lines = []
        return admin.main(list(argv), out=self.lines.append, env=env or self.env)

    def test_read_only_commands_need_no_admin_settings(self):
        env = {"AINGRAM_DB": self.env["AINGRAM_DB"]}
        for argv in (["keys", "list"], ["verify"], ["export", "--out", str(Path(self.dir.name) / "x.jsonl")]):
            self.assertEqual(self.run_cli(*argv, env=env), 0, argv)

    def test_policy_status(self):
        self.assertEqual(self.run_cli("policy", "status"), 1)
        self.approve()
        self.assertEqual(self.run_cli("policy", "status"), 0)
        self.assertIn(self.policy.sha256, self.lines[0])

    def test_the_cli_cannot_change_anything(self):
        for argv in (["keys", "mint"], ["redact", "x"], ["policy", "reload"], ["policy", "approve"]):
            with self.assertRaises(SystemExit):
                self.run_cli(*argv)


if __name__ == "__main__":
    unittest.main()
