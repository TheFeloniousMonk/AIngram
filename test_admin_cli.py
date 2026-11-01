"""Run: python -m unittest test_admin_cli -v"""

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

import aingram_admin
import aingram_core as core
import aingram_service as svc
from aingram_policy import PolicyError

HERE = Path(__file__).parent
ADMIN = Account.create()
MALLORY = Account.create()
SERVER = "aingram.test"


class CLI(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)  # registered first, so it runs after connections close
        d = Path(self.dir.name)
        self.policy = d / "policy.yaml"
        shutil.copy(HERE / "policy.example.yaml", self.policy)
        self.env = {"AINGRAM_DB": str(d / "store.db"), "AINGRAM_POLICY": str(self.policy),
                    "AINGRAM_SERVER_NAME": SERVER, "AINGRAM_ADMIN_ADDRESS": ADMIN.address}
        self.signer = ADMIN
        self.lines = []
        self.asked = 0

    def out(self, text=""):
        self.lines.append(str(text))

    def ask(self, _prompt):
        self.asked += 1
        message = next(l for l in reversed(self.lines) if l.startswith(aingram_admin.admin_auth.HEADER))
        return self.signer.sign_message(encode_defunct(text=message)).signature.hex()

    def run_cli(self, *argv):
        return aingram_admin.main(list(argv), ask=self.ask, out=self.out, env=self.env)

    def db(self):
        conn = core.connect(self.env["AINGRAM_DB"])
        self.addCleanup(conn.close)
        return conn

    def secret_from_output(self):
        return next(w for l in self.lines for w in l.split() if w.startswith("aig_"))

    def mint(self):
        self.assertEqual(self.run_cli("keys", "mint", "--voice", "code", "--label", "build bot"), 0)
        return self.secret_from_output()


class ReadOnly(CLI):
    def test_need_no_signature_or_admin_settings(self):
        env = {"AINGRAM_DB": self.env["AINGRAM_DB"]}
        for argv in (["keys", "list"], ["verify"],
                     ["export", "--out", str(Path(self.dir.name) / "x.jsonl")]):
            self.assertEqual(aingram_admin.main(argv, ask=self.ask, out=self.out, env=env), 0, argv)
        self.assertEqual(self.asked, 0)

    def test_signed_commands_need_admin_settings(self):
        env = {"AINGRAM_DB": self.env["AINGRAM_DB"]}
        code = aingram_admin.main(["keys", "mint", "--voice", "code", "--label", "x"],
                                  ask=self.ask, out=self.out, env=env)
        self.assertEqual(code, 1)
        self.assertEqual(self.asked, 0)


class Keys(CLI):
    def test_mint_shows_secret_once_and_stores_only_its_hash(self):
        secret = self.mint()
        self.assertRegex(secret, svc.SECRET_RE)
        conn = self.db()
        row = conn.execute("SELECT * FROM keys WHERE voice = 'code'").fetchone()
        self.assertEqual(row["secret_hash"], svc.hash_secret(secret))
        self.assertEqual(row["label"], "build bot")
        dump = "\n".join(conn.iterdump())
        self.assertNotIn(secret, dump)  # not in keys, admin_log, anywhere
        self.assertEqual(svc.authenticate(conn, secret)["key_id"], row["key_id"])

    def test_wrong_wallet_changes_nothing(self):
        self.signer = MALLORY
        self.assertEqual(self.run_cli("keys", "mint", "--voice", "code", "--label", "x"), 1)
        self.assertTrue(any("refused" in l for l in self.lines))
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM admin_log").fetchone()[0], 0)

    def test_brain_keys_are_not_minted_here(self):
        admin = aingram_admin.Admin(aingram_admin.Settings.from_env(self.env, need_admin=True),
                                    ask=self.ask, out=self.out)
        self.addCleanup(admin.conn.close)
        with self.assertRaises(aingram_admin.Refused):
            admin.keys_mint("brain", "x")
        self.assertEqual(self.asked, 0)

    def test_labels_cannot_disguise_the_message(self):
        for label in ("a" + chr(0x2028) + "Server: other", "a" + chr(0x202E) + "b", "a" + chr(10) + "b", "   "):
            self.assertEqual(self.run_cli("keys", "mint", "--voice", "code", "--label", label), 1, repr(label))
        self.assertEqual(self.asked, 0)

    def test_reload_shows_the_policy_bytes(self):
        self.assertEqual(self.run_cli("policy", "reload"), 0)
        self.assertTrue(any("brain_only_subjects" in l for l in self.lines))

    def test_revoke(self):
        secret = self.mint()
        conn = self.db()
        key_id = svc.authenticate(conn, secret)["key_id"]
        self.assertEqual(self.run_cli("keys", "revoke", key_id), 0)
        self.assertIsNone(svc.authenticate(conn, secret))
        self.assertEqual(self.run_cli("keys", "revoke", key_id), 1)  # already revoked

    def test_rotate(self):
        old = self.mint()
        conn = self.db()
        old_id = svc.authenticate(conn, old)["key_id"]
        self.lines.clear()
        self.assertEqual(self.run_cli("keys", "rotate", old_id), 0)
        new = self.secret_from_output()
        self.assertIsNone(svc.authenticate(conn, old))
        row = svc.authenticate(conn, new)
        self.assertEqual(row["voice"], "code")
        self.assertEqual(row["label"], "build bot")

    def test_outcomes_are_logged(self):
        self.mint()
        events = [r[0] for r in self.db().execute("SELECT event FROM admin_log ORDER BY log_id")]
        self.assertEqual(events, ["authorized", "done"])


class Redact(CLI):
    def test_admin_redacts_any_entry(self):
        conn = self.db()
        core.add_key(conn, key_id="k_brain", voice="brain")
        entry = core.append(conn, key_id="k_brain", subject="people/x", kind="fact",
                            excerpt="private", keywords=["k"], body="private body")["id"]
        self.assertEqual(self.run_cli("redact", entry[:12], "--reason", "asked to forget"), 0)
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry,)).fetchone()
        self.assertIsNone(row["body"])
        rec = conn.execute("SELECT * FROM redactions WHERE entry_id = ?", (entry,)).fetchone()
        self.assertEqual(rec["reason"], "asked to forget")
        self.assertEqual(rec["by_key"], svc.ADMIN_KEY_ID)
        self.assertEqual(core.verify(conn), [])

    def test_tombstones_cannot_be_redacted(self):
        conn = self.db()
        core.add_key(conn, key_id="k_brain", voice="brain")
        entry = core.append(conn, key_id="k_brain", subject="misc", kind="fact",
                            excerpt="e", keywords=[], body="")["id"]
        tomb = core.redact(conn, target_id=entry, by_key_id="k_brain", reason="r")["tombstone"]
        self.assertEqual(self.run_cli("redact", tomb, "--reason", "x"), 1)
        self.assertEqual(self.asked, 0)


class PolicyApproval(CLI):
    def settings(self):
        return aingram_admin.Settings.from_env(self.env, need_admin=True)

    def load(self, conn):
        return svc.load_approved_policy(conn, self.policy, SERVER, ADMIN.address)

    def test_unapproved_policy_is_refused(self):
        with self.assertRaisesRegex(PolicyError, "no approved policy"):
            self.load(self.db())
        self.assertEqual(self.run_cli("policy", "status"), 1)

    def test_reload_approves_exact_bytes(self):
        self.assertEqual(self.run_cli("policy", "reload"), 0)
        conn = self.db()
        self.assertEqual(self.load(conn).sha256, svc.load_policy(self.policy).sha256)
        self.assertEqual(self.run_cli("policy", "status"), 0)
        # Any edit to the file, even a comment, needs a new signature.
        self.policy.write_text(self.policy.read_text() + "\n# edited\n")
        with self.assertRaisesRegex(PolicyError, "not the approved policy"):
            self.load(conn)

    def test_invalid_policy_is_never_offered_for_signing(self):
        self.policy.write_text("voices: {}\n")
        self.assertEqual(self.run_cli("policy", "reload"), 1)
        self.assertEqual(self.asked, 0)

    def test_forged_approval_in_admin_log_is_refused(self):
        conn = self.db()
        conn.execute("INSERT INTO admin_nonces VALUES ('n1', 'x', 'y', 'z')")
        fake = aingram_admin.admin_auth.build_message(
            SERVER, {"action": "policy.reload", "sha256": svc.load_policy(self.policy).sha256},
            "n1", "2026-11-01T00:00:00.000000Z", "2026-11-01T00:10:00.000000Z")
        sig = MALLORY.sign_message(encode_defunct(text=fake)).signature.hex()
        conn.execute("INSERT INTO admin_log (at, event, nonce, action, message, signature) VALUES "
                     "('x', 'authorized', 'n1', '{\"action\":\"policy.reload\"}', ?, ?)", (fake, sig))
        conn.execute("INSERT INTO admin_log (at, event, nonce, action) VALUES "
                     "('x', 'done', 'n1', '{\"action\":\"policy.reload\"}')")
        with self.assertRaisesRegex(PolicyError, "does not verify"):
            self.load(conn)

    def test_unsigned_rows_cannot_roll_back_the_policy(self):
        self.assertEqual(self.run_cli("policy", "reload"), 0)
        conn = self.db()
        old_nonce = conn.execute("SELECT nonce FROM admin_log WHERE event = 'authorized'").fetchone()[0]
        self.policy.write_text(self.policy.read_text() + "\n# v2\n")
        self.assertEqual(self.run_cli("policy", "reload"), 0)
        v2 = svc.load_policy(self.policy).sha256
        # A later unsigned 'done' row pointing at the old approval changes nothing.
        conn.execute("INSERT INTO admin_log (at, event, nonce, action) VALUES "
                     "('z', 'done', ?, '{\"action\":\"policy.reload\"}')", (old_nonce,))
        self.assertEqual(svc.approved_policy_hash(conn, SERVER, ADMIN.address), v2)

    def test_admin_log_cannot_be_edited(self):
        self.run_cli("policy", "reload")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db().execute("UPDATE admin_log SET detail = 'x'")


if __name__ == "__main__":
    unittest.main()
