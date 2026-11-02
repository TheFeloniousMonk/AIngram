"""Run: python -m unittest test_backup -v

Step 7: the nightly backup. The server side (backup tokens, the two downloads)
and the off-server check (aingram_backup.py), wired together over the real app.
"""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from starlette.testclient import TestClient

import admin_auth
import aingram_admin as admin
import aingram_backup as backup
import aingram_core as core
import aingram_server
import aingram_service as svc
from aingram_config import Settings

ADMIN = Account.create()
MALLORY = Account.create()
PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"
SERVER = f"127.0.0.1:{PORT}"
EXAMPLE = (Path(__file__).parent / "policy.example.yaml").read_text(encoding="utf-8")


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


class Backup(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        self.settings = Settings.from_env({
            "AINGRAM_DB": str(root / "store.db"), "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        self.conn = core.connect(self.settings.db_path)
        self.addCleanup(self.conn.close)
        self.policy = None
        self.signed({"action": "policy.approve", "body": EXAMPLE})
        self.token = self.signed({"action": "backup.mint", "label": "home"})["secret"]
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.folder = root / "backup"
        self.folder.mkdir()
        self.env = {"AINGRAM_BACKUP_URL": BASE, "AINGRAM_BACKUP_TOKEN": self.token,
                    "AINGRAM_BACKUP_ADMIN": ADMIN.address}
        original = backup.download

        def via_test_client(config, name, dest):
            r = self.client.get(f"/backup/{name}", headers={"Authorization": f"Bearer {config['AINGRAM_BACKUP_TOKEN']}"})
            if r.status_code != 200:
                raise backup.BackupError(f"download of {name} failed: HTTP {r.status_code}")
            Path(dest).write_bytes(r.content)
        backup.download = via_test_client
        self.addCleanup(setattr, backup, "download", original)

    def signed(self, request, signer=ADMIN):
        drafts = admin.PolicyDrafts()
        msg = admin.prepare(self.conn, self.settings, self.policy, request, drafts)
        out = admin.confirm(self.conn, self.settings, self.policy, msg, sign(signer, msg), drafts)
        self.policy = svc.load_approved_policy(self.conn, self.settings.server_name, ADMIN.address)
        return out

    def write(self, excerpt, body="", subject="misc"):
        return core.append(self.conn, key_id="k_brain", subject=subject, kind="fact", excerpt=excerpt,
                           keywords=["k"], body=body)["id"]

    def pull(self, **env):
        return backup.pull(self.folder, use_git=shutil.which("git") is not None, env={**self.env, **env})

    def ledger(self):
        return (self.folder / "ledger" / "entries.jsonl").read_text(encoding="utf-8")


class Server(Backup):
    def test_downloads_need_a_backup_token(self):
        for headers in ({}, {"Authorization": "Bearer nonsense"}, {"Authorization": f"Bearer {svc.new_secret()}"}):
            self.assertEqual(self.client.get("/backup/entries.jsonl", headers=headers).status_code, 401)
        ok = self.client.get("/backup/admin.json", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(ok.status_code, 200)

    def test_a_backup_token_opens_nothing_else(self):
        h = {"Authorization": f"Bearer {self.token}", "Accept": "application/json, text/event-stream",
             "Content-Type": "application/json"}
        r = self.client.post("/mcp", headers=h, content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.get("/admin/api/me", headers=h).status_code, 401)

    def test_revoked_tokens_stop_working(self):
        token_id = admin.backup_tokens(self.conn)[0]["token_id"]
        self.signed({"action": "backup.revoke", "token_id": token_id})
        self.assertEqual(self.client.get("/backup/admin.json", headers={"Authorization": f"Bearer {self.token}"}).status_code, 401)

    def test_reasons_never_leave_the_server(self):
        e = self.write("private", "private body")
        self.signed({"action": "redact", "id": e, "reason": "the secret reason"})
        h = {"Authorization": f"Bearer {self.token}"}
        everything = self.client.get("/backup/entries.jsonl", headers=h).text + self.client.get("/backup/admin.json", headers=h).text
        self.assertNotIn("the secret reason", everything)
        self.assertNotIn("private body", everything)

    def test_tokens_are_stored_hashed(self):
        self.assertNotIn(self.token, "\n".join(self.conn.iterdump()))


class Nightly(Backup):
    def test_first_night_keeps_a_ledger_without_content(self):
        self.write("hello", "a body worth keeping")
        notes = self.pull()
        self.assertIn("backup checked and saved", notes[0])
        self.assertNotIn("a body worth keeping", self.ledger())
        self.assertIn("a body worth keeping", (self.folder / "latest" / "entries.jsonl").read_text(encoding="utf-8"))
        admin_json = json.loads((self.folder / "ledger" / "admin.json").read_text(encoding="utf-8"))
        self.assertEqual(len(admin_json["policy_approvals"]), 1)

    def test_next_nights_extend_and_redaction_leaves_the_backup(self):
        e = self.write("to forget", "forget this body")
        self.pull()
        self.signed({"action": "redact", "id": e, "reason": "asked"})
        self.write("later")
        self.pull()
        self.assertNotIn("forget this body", (self.folder / "latest" / "entries.jsonl").read_text(encoding="utf-8"))
        self.assertFalse((self.folder / "ALERT.txt").exists())

    def test_new_keys_are_reported(self):
        self.pull()
        core.add_key(self.conn, key_id="k_code_new", voice="code", secret_hash="0" * 64, label="laptop")
        notes = self.pull()
        self.assertTrue(any("new key k_code_new" in n for n in notes))

    @unittest.skipIf(shutil.which("git") is None, "git not installed")
    def test_the_ledger_is_committed_each_night(self):
        self.pull()
        self.write("second")
        self.pull()
        log = backup._git(self.folder, "log", "--oneline").stdout.strip().splitlines()
        self.assertEqual(len(log), 2)
        tracked = backup._git(self.folder, "ls-files").stdout.split()
        self.assertTrue(all(p.startswith("ledger/") for p in tracked))


class Tampering(Backup):
    def assert_fails(self, needle, **env):
        before = self.ledger() if (self.folder / "ledger" / "entries.jsonl").exists() else None
        with self.assertRaisesRegex(backup.BackupError, needle):
            self.pull(**env)
        self.assertTrue(any((self.folder / "failed").iterdir()))
        if before is not None:
            self.assertEqual(self.ledger(), before)  # nothing overwritten

    def test_a_rewritten_header_is_caught(self):
        e = self.write("original")
        self.pull()
        self.conn.execute("DROP TRIGGER entries_update_guard")
        self.conn.execute("UPDATE entries SET subject = 'changed' WHERE id = ?", (e,))
        self.assert_fails("seq 1")

    def test_rewritten_content_is_caught(self):
        e = self.write("original", "the true body")
        self.pull()
        self.conn.execute("DROP TRIGGER entries_update_guard")
        self.conn.execute("DROP TRIGGER entries_fts_redact")
        self.conn.execute("UPDATE entries SET body = 'a forged body' WHERE id = ?", (e,))
        self.assert_fails("content_hash")

    def test_a_forged_policy_approval_is_caught(self):
        self.pull()
        sha = svc.store_policy_version(self.conn, EXAMPLE + "\n# forged\n").sha256
        self.conn.execute("INSERT INTO admin_nonces VALUES ('nf', 'x', 'y', 'z')")
        fake = admin_auth.build_message(SERVER, {"action": "policy.approve", "sha256": sha}, "nf",
                                        "2026-12-01T00:00:00.000000Z", "2026-12-01T00:10:00.000000Z")
        self.conn.execute("INSERT INTO admin_log (at, event, nonce, action, message, signature) VALUES "
                          "('x', 'authorized', 'nf', '{\"action\":\"policy.approve\"}', ?, ?)", (fake, sign(MALLORY, fake)))
        self.assert_fails("not signed by the trusted admin")

    def test_the_backup_trusts_its_own_admin_address_not_the_servers(self):
        self.assert_fails("not signed by the trusted admin", AINGRAM_BACKUP_ADMIN=MALLORY.address)

    def test_a_vanished_key_is_caught(self):
        core.add_key(self.conn, key_id="k_code_x", voice="code", secret_hash="1" * 64)
        self.pull()
        self.conn.execute("DROP TRIGGER keys_no_delete")
        self.conn.execute("DELETE FROM keys WHERE key_id = 'k_code_x'")
        self.assert_fails("k_code_x: disappeared")

    def test_a_truncated_history_is_caught(self):
        self.write("one")
        self.write("two")
        self.pull()
        full = core.load_jsonl(self.folder / "latest" / "entries.jsonl")
        short = Path(self.dir.name) / "short.jsonl"
        backup.write_jsonl(short, [{"type": "entry", **e} for e in full[0][:1]])
        problems = backup.check_entries(self.folder / "ledger" / "entries.jsonl", short)
        self.assertTrue(any("missing" in p for p in problems), problems)

    def test_a_malformed_download_is_a_failed_check_not_a_crash(self):
        self.write("one")
        self.pull()
        original = backup.download

        def stripped(config, name, dest):
            original_bytes = self.client.get(f"/backup/{name}", headers={"Authorization": f"Bearer {self.token}"}).content
            if name == "entries.jsonl":  # content nulled but not marked redacted
                lines = [json.loads(l) for l in original_bytes.decode().splitlines()]
                for l in lines:
                    l.update(excerpt=None, keywords=None, body=None, salt=None)
                original_bytes = "\n".join(json.dumps(l) for l in lines).encode()
            Path(dest).write_bytes(original_bytes)
        backup.download = stripped
        try:
            self.assert_fails("could not be read")
        finally:
            backup.download = original

    def test_a_failure_exits_nonzero_and_leaves_an_alert(self):
        (self.folder / backup.ENV_FILE).write_text(
            "".join(f"{k}={v}\n" for k, v in self.env.items()), encoding="utf-8")
        e = self.write("x")
        self.assertEqual(backup.main(["pull", "--dir", str(self.folder), "--no-git"]), 0)
        self.conn.execute("DROP TRIGGER entries_update_guard")
        self.conn.execute("UPDATE entries SET kind = 'gotcha' WHERE id = ?", (e,))
        self.assertEqual(backup.main(["pull", "--dir", str(self.folder), "--no-git"]), 1)
        self.assertIn("header changed", (self.folder / "ALERT.txt").read_text(encoding="utf-8"))


class SchemaUpgrade(unittest.TestCase):
    def test_an_existing_store_gets_new_tables(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "old.db"
            conn = core.connect(path)
            conn.execute("DROP TABLE backup_tokens")
            conn.execute("UPDATE meta SET v = 'an older schema' WHERE k = 'schema_sha256'")
            conn.close()
            conn = core.connect(path)
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'backup_tokens'").fetchone())
            conn.close()


if __name__ == "__main__":
    unittest.main()
