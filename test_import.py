"""Run: python -m unittest test_import -v

Importing existing memory: checked line by line, approved once by the wallet,
written as the brain in one transaction.
"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
JSON = {"Origin": BASE, "Content-Type": "application/json"}
EXAMPLE = (Path(__file__).parent / "policy.example.yaml").read_text(encoding="utf-8")


def sign(acct, message):
    return acct.sign_message(encode_defunct(text=message)).signature.hex()


def jsonl(*records):
    return "\n".join(json.dumps(r) for r in records) + "\n"


GOOD = jsonl(
    {"subject": "self/name", "kind": "fact", "excerpt": "I am Qlaude", "pinned": True, "source": "overview.md"},
    {"subject": "people/ada", "kind": "fact", "excerpt": "Ada moved to Lisbon", "keywords": ["ada"],
     "body": "Long story.", "source": "people.md"},
    {"subject": "breadcrumbs", "kind": "breadcrumb", "excerpt": "Old session notes", "date": "2026-01-10",
     "untrusted_ctx": "meadow", "source": "breadcrumbs.md"},
    {"subject": "breadcrumbs", "kind": "breadcrumb", "excerpt": "Yesterday's thread",
     "date": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d"), "source": "breadcrumbs.md"},
)


class Import(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.settings = Settings.from_env({
            "AINGRAM_DB": str(Path(self.dir.name) / "store.db"), "AINGRAM_ADMIN_ADDRESS": ADMIN.address,
            "AINGRAM_PUBLIC_URL": BASE, "AINGRAM_PORT": str(PORT)}, need_server=True)
        self.conn = core.connect(self.settings.db_path)
        self.addCleanup(self.conn.close)
        self.drafts = admin.Drafts()
        self.policy = None
        self.signed({"action": "policy.approve", "body": EXAMPLE})

    def signed(self, request, signer=ADMIN):
        msg = admin.prepare(self.conn, self.settings, self.policy, request, self.drafts)
        out = admin.confirm(self.conn, self.settings, self.policy, msg, sign(signer, msg), self.drafts)
        self.policy = svc.load_approved_policy(self.conn, self.settings.server_name, ADMIN.address)
        return out

    def entries(self):
        return self.conn.execute("SELECT * FROM entries ORDER BY seq").fetchall()


class Checking(Import):
    def test_a_good_file_checks_out_with_a_summary(self):
        r = admin.check_import(GOOD, self.policy)
        self.assertTrue(r["valid"], r["problems"])
        s = r["summary"]
        self.assertEqual((s["entries"], s["pinned"], s["outside_text"]), (4, 1, 1))
        self.assertEqual(s["subjects"]["breadcrumbs"], 2)
        self.assertEqual(s["dated"][0], "2026-01-10")
        self.assertEqual(self.entries(), [])  # checking writes nothing

    def test_every_line_is_checked_like_a_brain_write(self):
        bad = jsonl(
            {"subject": "x", "kind": "fact", "excerpt": "e"},                                     # no source
            {"subject": "_redactions/x", "kind": "fact", "excerpt": "e", "source": "a"},          # reserved
            {"subject": "x", "kind": "redaction", "excerpt": "e", "source": "a"},                 # reserved kind
            {"subject": "x", "kind": "fact", "excerpt": "e" * 301, "source": "a"},                # too long
            {"subject": "x", "kind": "fact", "excerpt": "e", "source": "a", "date": "2099-01-01"},  # future
            {"subject": "x", "kind": "fact", "excerpt": "e", "source": "a", "voice": "code"},     # unknown field
            {"subject": "x", "kind": "fact", "excerpt": "e", "source": "s" * 51},                 # source too long
        ) + "not json\n"
        r = admin.check_import(bad, self.policy)
        self.assertFalse(r["valid"])
        self.assertEqual(r["problem_count"], 8)
        for n, needle in enumerate(("source is required", "reserved", "reserved", "excerpt is 301",
                                    "future", "unknown field", "longer than 50", "not JSON"), 1):
            self.assertIn(f"line {n}:", r["problems"][n - 1])
            self.assertIn(needle, r["problems"][n - 1])

    def test_a_file_with_problems_cannot_be_prepared(self):
        with self.assertRaisesRegex(admin.Refused, "problem"):
            admin.prepare(self.conn, self.settings, self.policy, {"action": "import.apply", "body": "nope\n"}, self.drafts)


class Applying(Import):
    def test_import_writes_everything_as_the_brain(self):
        r = self.signed({"action": "import.apply", "body": GOOD})
        self.assertEqual(r["imported"], 4)
        rows = self.entries()
        self.assertEqual([e["subject"] for e in rows], ["self/name", "people/ada", "breadcrumbs", "breadcrumbs"])
        self.assertTrue(all(e["voice"] == "brain" and e["key_id"] == r["key_id"] for e in rows))
        self.assertIn("migrated-from:people.md", json.loads(rows[1]["keywords"]))
        self.assertEqual(rows[2]["untrusted_ctx"], "meadow")
        self.assertEqual(core.verify(self.conn), [])
        key = self.conn.execute("SELECT * FROM keys WHERE key_id = ?", (r["key_id"],)).fetchone()
        self.assertIsNone(key["secret_hash"])  # it records the import; nothing can sign in with it

    def test_dates_set_the_decay_clock(self):
        self.signed({"action": "import.apply", "body": GOOD})
        boot = svc.boot(self.conn, self.policy, "brain")
        self.assertEqual([c["excerpt"] for c in boot["core"]], ["I am Qlaude"])
        tail = [t["excerpt"] for t in boot["recent"]]
        self.assertIn("Yesterday's thread", tail)
        self.assertNotIn("Old session notes", tail)  # ten months old: faded
        hits = svc.recall(self.conn, self.policy, "brain", query="session notes")["hits"]
        self.assertTrue(hits[0]["faded"])

    def test_the_daily_cap_does_not_apply(self):
        many = jsonl(*({"subject": "bulk", "kind": "fact", "excerpt": f"n{i}", "source": "bulk.md"}
                       for i in range(self.policy.voices["brain"].daily_write_cap + 5)))
        self.assertEqual(self.signed({"action": "import.apply", "body": many})["imported"],
                         self.policy.voices["brain"].daily_write_cap + 5)

    def test_wrong_wallet_imports_nothing(self):
        with self.assertRaisesRegex(admin.Refused, "Nothing was changed"):
            self.signed({"action": "import.apply", "body": GOOD}, signer=MALLORY)
        self.assertEqual(self.entries(), [])

    def test_a_replaced_draft_cannot_land(self):
        old = admin.prepare(self.conn, self.settings, self.policy, {"action": "import.apply", "body": GOOD}, self.drafts)
        admin.prepare(self.conn, self.settings, self.policy,
                      {"action": "import.apply", "body": jsonl({"subject": "x", "kind": "fact", "excerpt": "e", "source": "a"})},
                      self.drafts)
        with self.assertRaisesRegex(admin.Refused, "replaced"):
            admin.confirm(self.conn, self.settings, self.policy, old, sign(ADMIN, old), self.drafts)
        self.assertEqual(self.entries(), [])

    def test_all_or_nothing(self):
        # A failure partway through (here: a subject the store itself refuses) leaves nothing behind.
        records, _ = admin.parse_import(GOOD, self.policy)
        records[2]["subject"] = ""
        with self.assertRaises(core.AIngramError):
            admin.apply_import(self.conn, self.policy, records, {"entries": len(records)})
        self.assertEqual(self.entries(), [])
        self.assertIsNone(self.conn.execute("SELECT 1 FROM keys WHERE key_id LIKE 'k_brain_imp_%'").fetchone())


class OverHTTP(Import):
    def setUp(self):
        super().setUp()
        self.client = TestClient(aingram_server.create_app(self.settings), base_url=BASE)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def test_large_uploads_need_a_session_first(self):
        big = json.dumps({"body": "x" * (2 * 1024 * 1024)})
        r = self.client.post("/admin/api/import/check", content=big, headers=JSON)
        self.assertEqual(r.status_code, 401)

    def test_check_then_import_through_the_page(self):
        msg = self.client.post("/admin/api/login/challenge", content=json.dumps({"address": ADMIN.address}),
                               headers=JSON).json()["message"]
        self.client.post("/admin/api/login/verify", content=json.dumps({"message": msg, "signature": sign(ADMIN, msg)}),
                         headers=JSON)
        r = self.client.post("/admin/api/import/check", content=json.dumps({"body": GOOD}), headers=JSON).json()
        self.assertTrue(r["valid"])
        p = self.client.post("/admin/api/actions/prepare", content=json.dumps({"action": "import.apply", "body": GOOD}),
                             headers=JSON).json()
        self.assertEqual(p["action"], {"action": "import.apply", "sha256": r["sha256"], "entries": 4})
        done = self.client.post("/admin/api/actions/confirm", headers=JSON, content=json.dumps(
            {"message": p["message"], "signature": sign(ADMIN, p["message"])})).json()
        self.assertEqual(done["imported"], 4)


if __name__ == "__main__":
    unittest.main()
