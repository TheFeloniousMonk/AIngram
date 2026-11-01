"""Run: python3 -m unittest test_core -v"""

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

import aingram_core as core
import make_vectors


def fresh(path=":memory:"):
    conn = core.connect(path)
    core.add_key(conn, key_id="k_brain", voice="brain")
    core.add_key(conn, key_id="k_code", voice="code")
    core.add_key(conn, key_id="k_admin", voice="admin")
    return conn


def put(conn, n=1, key="k_brain", **kw):
    ids = []
    for i in range(n):
        args = dict(key_id=key, subject=kw.get("subject", f"test/{i % 3}"), kind="fact",
                    excerpt=f"entry {i}", keywords=["test", f"k{i}"], body=f"body of entry {i}")
        args.update({k: v for k, v in kw.items() if k != "subject"})
        ids.append(core.append(conn, **args)["id"])
    return ids


class Chain(unittest.TestCase):
    def test_twenty_entries_verify(self):
        conn = fresh()
        put(conn, 20)
        self.assertEqual(core.verify(conn), [])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 20)

    def test_voice_comes_from_key(self):
        conn = fresh()
        put(conn, 1, key="k_code")
        self.assertEqual(conn.execute("SELECT voice FROM entries").fetchone()[0], "code")

    def test_revoked_key_cannot_write(self):
        conn = fresh()
        core.revoke_key(conn, "k_code")
        with self.assertRaises(core.AIngramError):
            put(conn, 1, key="k_code")

    def test_unknown_key_cannot_write(self):
        with self.assertRaises(core.AIngramError):
            put(fresh(), 1, key="k_nobody")

    def test_excerpt_cap(self):
        conn = fresh()
        put(conn, 1, excerpt="x" * 300)
        with self.assertRaises(core.AIngramError):
            put(conn, 1, excerpt="x" * 301)

    def test_supersedes_and_refs_must_exist(self):
        conn = fresh()
        with self.assertRaises(core.AIngramError):
            put(conn, 1, supersedes="a" * 64)
        with self.assertRaises(core.AIngramError):
            put(conn, 1, refs=["b" * 64])
        first = put(conn, 1)[0]
        put(conn, 1, supersedes=first, refs=[first])
        self.assertEqual(core.verify(conn), [])

    def test_nfc_makes_spellings_equal(self):
        a, b = fresh(), fresh()
        common = dict(key_id="k_brain", subject="s", kind="fact", keywords=[], body="",
                      ts="2026-11-01T00:00:00.000000Z", salt="0" * 32)
        ida = core.append(a, excerpt="caf\u00e9", **common)["id"]
        idb = core.append(b, excerpt="cafe\u0301", **common)["id"]
        self.assertEqual(ida, idb)

    def test_keyword_order_does_not_matter(self):
        a, b = fresh(), fresh()
        common = dict(key_id="k_brain", subject="s", kind="fact", excerpt="e", body="",
                      ts="2026-11-01T00:00:00.000000Z", salt="0" * 32)
        ida = core.append(a, keywords=["b", "a", " a "], **common)["id"]
        idb = core.append(b, keywords=["a", "b"], **common)["id"]
        self.assertEqual(ida, idb)

    def test_floats_refused_in_canonical(self):
        with self.assertRaises(core.CanonicalError):
            core.canonical({"x": 1.5})


class Triggers(unittest.TestCase):
    def test_delete_blocked(self):
        conn = fresh()
        put(conn, 2)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM entries WHERE seq = 1")

    def test_content_update_blocked(self):
        conn = fresh()
        put(conn, 1)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE entries SET body = 'rewritten' WHERE seq = 1")

    def test_header_update_blocked_even_alongside_redaction(self):
        conn = fresh()
        put(conn, 1)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("""UPDATE entries SET excerpt=NULL, keywords=NULL, body=NULL, salt=NULL,
                            redacted_at='x', subject='sneaky' WHERE seq = 1""")

    def test_out_of_order_insert_blocked(self):
        conn = fresh()
        put(conn, 2)
        row = dict(conn.execute("SELECT * FROM entries WHERE seq = 2").fetchone())
        for seq, prev in ((5, row["id"]), (3, "f" * 64)):
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    """INSERT INTO entries (seq,id,prev_hash,ts,voice,key_id,subject,kind,refs,
                       pinned,content_hash,excerpt,keywords,body,salt)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (seq, "e" * 64, prev, row["ts"], "brain", "k_brain", "s", "fact", "[]", 0,
                     "d" * 64, "e", "[]", "b", "0" * 32))

    def test_key_cannot_be_deleted_or_change_voice(self):
        conn = fresh()
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM keys WHERE key_id = 'k_code'")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE keys SET voice = 'brain' WHERE key_id = 'k_code'")


class Redaction(unittest.TestCase):
    def test_redaction_keeps_chain_and_forgets_content(self):
        conn = fresh()
        ids = put(conn, 10, body="my sister's address is 12 Elm")
        res = core.redact(conn, target_id=ids[4], by_key_id="k_brain", reason="asked to forget")
        self.assertEqual(core.verify(conn), [])
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (ids[4],)).fetchone()
        self.assertIsNone(row["body"])
        self.assertIsNone(row["salt"])
        tomb = conn.execute("SELECT * FROM entries WHERE id = ?", (res["tombstone"],)).fetchone()
        self.assertEqual(json.loads(tomb["refs"]), [ids[4]])
        self.assertNotIn("forget", tomb["body"] + tomb["excerpt"])  # reason stays out of the chain
        reason = conn.execute("SELECT reason FROM redactions WHERE entry_id = ?", (ids[4],)).fetchone()[0]
        self.assertEqual(reason, "asked to forget")

    def test_redacted_content_leaves_search(self):
        conn = fresh()
        ids = put(conn, 1, body="zanzibar")
        put(conn, 1, body="other")
        hit = lambda: conn.execute("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'zanzibar'").fetchone()[0]
        self.assertEqual(hit(), 1)
        core.redact(conn, target_id=ids[0], by_key_id="k_admin", reason="test")
        self.assertEqual(hit(), 0)

    def test_cannot_redact_twice_or_without_reason(self):
        conn = fresh()
        ids = put(conn, 1)
        with self.assertRaises(core.AIngramError):
            core.redact(conn, target_id=ids[0], by_key_id="k_brain", reason="  ")
        core.redact(conn, target_id=ids[0], by_key_id="k_brain", reason="once")
        with self.assertRaises(core.AIngramError):
            core.redact(conn, target_id=ids[0], by_key_id="k_brain", reason="twice")
        self.assertEqual(core.verify(conn), [])

    def test_redacted_content_leaves_the_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.db"
            conn = fresh(path)
            ids = put(conn, 1, body="xyzzyplugh secret body", keywords=["kwsecretword"])
            put(conn, 3)
            core.redact(conn, target_id=ids[0], by_key_id="k_brain", reason="forget")
            conn.close()
            for f in Path(d).iterdir():
                data = f.read_bytes()
                self.assertNotIn(b"xyzzyplugh", data, f.name)
                self.assertNotIn(b"kwsecretword", data, f.name)

    def test_failed_redaction_rolls_back_everything(self):
        conn = fresh()
        put(conn, 1)
        before = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        with self.assertRaises(core.AIngramError):
            core.redact(conn, target_id="c" * 64, by_key_id="k_brain", reason="no such entry")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], before)


class Tamper(unittest.TestCase):
    """Someone with raw file access drops the triggers and edits rows. verify must notice."""

    def tampered(self, sql):
        conn = fresh()
        put(conn, 5)
        conn.execute("DROP TRIGGER entries_update_guard")
        conn.execute(sql)
        return core.verify(conn)

    def test_body_edit_detected(self):
        problems = self.tampered("UPDATE entries SET body = 'rewritten' WHERE seq = 3")
        self.assertTrue(any("content does not match" in p for p in problems))

    def test_subject_edit_detected(self):
        problems = self.tampered("UPDATE entries SET subject = 'elsewhere' WHERE seq = 3")
        self.assertTrue(any("header does not match" in p for p in problems))

    def test_fake_redaction_detected(self):
        problems = self.tampered("""UPDATE entries SET excerpt=NULL, keywords=NULL, body=NULL,
                                    salt=NULL, redacted_at='x' WHERE seq = 3""")
        self.assertTrue(any("without a redaction record" in p for p in problems))


class Concurrency(unittest.TestCase):
    def test_two_writers_one_chain(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.db"
            fresh(path).close()
            errors = []

            def writer(key):
                try:
                    conn = core.connect(path)
                    put(conn, 40, key=key)
                    conn.close()
                except Exception as e:  # noqa: BLE001
                    errors.append(e)

            threads = [threading.Thread(target=writer, args=(k,)) for k in ("k_brain", "k_code")]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [])
            conn = core.connect(path)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 80)
            self.assertEqual(core.verify(conn), [])
            conn.close()  # Windows cannot remove an open database file


class OffBoxCheck(unittest.TestCase):
    """The nightly pull on an off-box machine: does tonight's export extend last night's?"""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = Path(self.dir.name)
        self.conn = fresh(self.d / "store.db")
        self.ids = put(self.conn, 5)
        core.export_jsonl(self.conn, self.d / "night1.jsonl")

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def check(self):
        core.export_jsonl(self.conn, self.d / "night2.jsonl")
        return core.check_extends(self.d / "night1.jsonl", self.d / "night2.jsonl")

    def test_new_entries_extend(self):
        put(self.conn, 3)
        self.assertEqual(self.check(), [])

    def test_redaction_since_last_night_is_allowed(self):
        core.redact(self.conn, target_id=self.ids[2], by_key_id="k_brain", reason="forget")
        self.assertEqual(self.check(), [])

    def test_reasons_never_leave_the_box(self):
        core.redact(self.conn, target_id=self.ids[2], by_key_id="k_brain", reason="secret reason")
        core.export_jsonl(self.conn, self.d / "night2.jsonl")
        self.assertNotIn("secret reason", (self.d / "night2.jsonl").read_text())

    def test_rewritten_history_fails(self):
        # Root on the box builds a different chain with the same length.
        other = fresh(self.d / "forged.db")
        put(other, 5, body="forged")
        core.export_jsonl(other, self.d / "night2.jsonl")
        other.close()
        problems = core.check_extends(self.d / "night1.jsonl", self.d / "night2.jsonl")
        self.assertTrue(any("history rewritten" in p for p in problems))

    def test_truncated_history_fails(self):
        lines = (self.d / "night1.jsonl").read_text().splitlines()
        (self.d / "night2.jsonl").write_text("\n".join(lines[:3]) + "\n")
        problems = core.check_extends(self.d / "night1.jsonl", self.d / "night2.jsonl")
        self.assertTrue(any("history truncated" in p for p in problems))

    def test_silent_content_edit_fails(self):
        self.conn.execute("DROP TRIGGER entries_update_guard")
        self.conn.execute("UPDATE entries SET body = 'rewritten' WHERE seq = 2")
        problems = self.check()
        self.assertTrue(any("content does not match" in p for p in problems))
        self.assertTrue(any("content changed without redaction" in p for p in problems))

    def test_unredaction_fails(self):
        # Root restores redacted content from an old backup and hides the redaction.
        pre = {r["seq"]: r for r in core.load_jsonl(self.d / "night1.jsonl")[0]}
        core.redact(self.conn, target_id=self.ids[1], by_key_id="k_brain", reason="forget")
        core.export_jsonl(self.conn, self.d / "night1.jsonl")
        entries, _ = core.load_jsonl(self.d / "night1.jsonl")
        forged = []
        for e in entries:
            if e["id"] == self.ids[1]:
                e = {**e, **{c: pre[e["seq"]][c] for c in ("excerpt", "keywords", "body", "salt")},
                     "redacted_at": None}
            forged.append({"type": "entry", **e})
        (self.d / "night2.jsonl").write_text("".join(json.dumps(r) + "\n" for r in forged))
        problems = core.check_extends(self.d / "night1.jsonl", self.d / "night2.jsonl")
        self.assertTrue(any("redacted content reappeared" in p for p in problems))
        self.assertTrue(any("record disappeared" in p for p in problems))

class Vectors(unittest.TestCase):
    def test_vectors_file_matches_this_code(self):
        expected = json.dumps(make_vectors.build(), indent=2, ensure_ascii=True) + "\n"
        on_disk = (Path(__file__).parent / "vectors.json").read_text(encoding="utf-8")
        self.assertEqual(on_disk, expected,
                         "hashing changed: regenerate vectors only on purpose, bump V, and tell the brain")


if __name__ == "__main__":
    unittest.main()
