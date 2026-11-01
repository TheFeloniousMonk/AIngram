"""Run: python3 -m unittest test_admin_auth -v"""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from eth_account import Account
from eth_account.messages import encode_defunct

import admin_auth as aa
import aingram_core as core

SERVER = "aingram.test"
ADMIN = Account.create()
MALLORY = Account.create()
REVOKE = {"action": "keys.revoke", "key_id": "k_code_02"}


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


class SignedAdmin(unittest.TestCase):
    def setUp(self):
        self.conn = core.connect(":memory:")
        self.now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)

    def auth(self, message, signature, address=None, now=None, server=SERVER):
        return aa.authorize(self.conn, server, address or ADMIN.address, message, signature,
                            now=now or self.now + timedelta(minutes=1))

    def test_admin_signed_command_is_authorized_and_logged(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        self.assertEqual(self.auth(msg, sign(ADMIN, msg)), REVOKE)
        aa.log_outcome(self.conn, msg, ok=True)
        events = [r["event"] for r in self.conn.execute("SELECT event FROM admin_log ORDER BY log_id")]
        self.assertEqual(events, ["authorized", "done"])

    def test_someone_elses_wallet_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        with self.assertRaisesRegex(aa.AdminAuthError, "not from the admin address"):
            self.auth(msg, sign(MALLORY, msg))

    def test_replay_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        sig = sign(ADMIN, msg)
        self.auth(msg, sig)
        with self.assertRaisesRegex(aa.AdminAuthError, "replay"):
            self.auth(msg, sig)

    def test_expired_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        with self.assertRaisesRegex(aa.AdminAuthError, "expired"):
            self.auth(msg, sign(ADMIN, msg), now=self.now + timedelta(minutes=11))

    def test_edited_action_after_signing_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        sig = sign(ADMIN, msg)
        swapped = msg.replace("k_code_02", "k_brain_01")
        with self.assertRaisesRegex(aa.AdminAuthError, "not from the admin address"):
            self.auth(swapped, sig)

    def test_self_made_nonce_is_refused(self):
        # Even a genuine admin signature fails if the box never issued the nonce.
        msg = aa.build_message(SERVER, REVOKE, "ab" * 16, "2026-11-01T12:00:00.000000Z",
                               "2026-11-01T12:10:00.000000Z")
        with self.assertRaisesRegex(aa.AdminAuthError, "not issued by this box"):
            self.auth(msg, sign(ADMIN, msg))

    def test_other_server_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        with self.assertRaisesRegex(aa.AdminAuthError, "different server"):
            self.auth(msg, sign(ADMIN, msg), server="aingram.elsewhere")

    def test_garbage_signature_is_refused(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        with self.assertRaises(aa.AdminAuthError):
            self.auth(msg, "0xdeadbeef")

    def test_unknown_action_cannot_be_prepared(self):
        with self.assertRaises(aa.AdminAuthError):
            aa.prepare(self.conn, SERVER, {"action": "entries.delete"}, now=self.now)

    def test_admin_log_is_append_only(self):
        msg = aa.prepare(self.conn, SERVER, REVOKE, now=self.now)
        self.auth(msg, sign(ADMIN, msg))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM admin_log")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE admin_log SET signer = 'nobody'")


if __name__ == "__main__":
    unittest.main()
