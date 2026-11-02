"""Run: python -m unittest test_views -v

Step 5: decay in the read path, salience ranking, and the boot budget on a seeded log.
"""

import random
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aingram_admin as admin
import aingram_core as core
import aingram_service as svc
from aingram_policy import load_policy

HERE = Path(__file__).parent
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


class Views(unittest.TestCase):
    def setUp(self):
        self.conn = core.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.policy = load_policy(HERE / "policy.example.yaml")
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        core.add_key(self.conn, key_id="k_code", voice="code")

    def write(self, key="k_brain", when=NOW, **kw):
        kw.setdefault("subject", "misc")
        kw.setdefault("kind", "fact")
        kw.setdefault("excerpt", "x")
        return svc.write(self.conn, self.policy, key, now=when, **kw)["id"]

    def boot(self, voice="brain", when=NOW):
        return svc.boot(self.conn, self.policy, voice, now=when)


class Decay(Views):
    def test_faded_entries_leave_the_tail(self):
        # Breadcrumbs have a 30-day half-life; fade_below 0.25 is two half-lives.
        old = self.write(kind="breadcrumb", excerpt="old thread", when=NOW - 61 * DAY)
        fresh = self.write(kind="breadcrumb", excerpt="new thread", when=NOW - 59 * DAY)
        tail = [h["id"] for h in self.boot()["recent"]]
        self.assertIn(fresh, tail)
        self.assertNotIn(old, tail)

    def test_pinned_entries_never_fade(self):
        core_id = self.write(subject="self/name", excerpt="who I am", pinned=True, when=NOW - 3000 * DAY)
        self.assertEqual([c["id"] for c in self.boot()["core"]], [core_id])

    def test_reading_brings_a_faded_entry_back(self):
        old = self.write(kind="breadcrumb", excerpt="old thread", when=NOW - 100 * DAY)
        self.assertNotIn(old, [h["id"] for h in self.boot()["recent"]])
        got = svc.read(self.conn, self.policy, "brain", old, now=NOW)
        self.assertLess(got["salience"], self.policy.fade_below)  # as it stood before this read
        self.assertIn(old, [h["id"] for h in self.boot()["recent"]])
        self.assertEqual(svc.read(self.conn, self.policy, "brain", old, now=NOW)["salience"], 1.0)

    def test_citing_an_entry_reinforces_it(self):
        old = self.write(kind="breadcrumb", excerpt="old thread", when=NOW - 100 * DAY)
        self.write(excerpt="builds on it", refs=[old])
        self.assertIn(old, [h["id"] for h in self.boot()["recent"]])

    def test_recall_query_ranks_by_relevance_times_salience(self):
        stale = self.write(subject="a", kind="breadcrumb", excerpt="lisbon trip notes", when=NOW - 200 * DAY)
        fresh = self.write(subject="b", kind="breadcrumb", excerpt="lisbon trip notes", when=NOW - DAY)
        hits = svc.recall(self.conn, self.policy, "brain", query="lisbon", now=NOW)["hits"]
        self.assertEqual([h["id"] for h in hits], [fresh, stale])
        self.assertTrue(hits[1]["faded"])  # faded entries sink, but are still found
        self.assertNotIn("faded", hits[0])

    def test_subject_fold_keeps_faded_entries(self):
        old = self.write(subject="people/ada", excerpt="moved to Lisbon", when=NOW - 900 * DAY)
        hits = svc.recall(self.conn, self.policy, "brain", subject="people/ada", now=NOW)["hits"]
        self.assertEqual([h["id"] for h in hits], [old])
        self.assertTrue(hits[0]["faded"])

    def test_admin_sees_what_faded_and_when(self):
        self.write(kind="breadcrumb", excerpt="faded long ago", when=NOW - 300 * DAY)
        recent = self.write(kind="breadcrumb", excerpt="faded this week", when=NOW - 63 * DAY)
        self.write(kind="breadcrumb", excerpt="still fresh", when=NOW - DAY)
        f = admin.faded(self.conn, self.policy, now=NOW)
        self.assertEqual((f["total"], f["this_week"]), (2, 1))
        self.assertEqual(f["entries"][0]["id"], recent[:12])
        self.assertEqual(f["entries"][0]["faded_at"], (NOW - 3 * DAY).strftime("%Y-%m-%dT%H:%M:%SZ"))


class Budget(Views):
    def seed(self, pinned=15, core_chars=150, breadcrumbs=300, code=100):
        """A log shaped like the planned migration: a modest core, a long breadcrumb
        history, other facts, and Code's build notes across several projects."""
        rng = random.Random(7)
        text = lambda n: ("word " * (n // 5 + 1))[:n].strip()
        for i in range(pinned):
            self.write(subject=f"self/core{i}", excerpt=text(core_chars), pinned=True, when=NOW - (900 - i) * DAY)
        for i in range(breadcrumbs):
            self.write(kind="breadcrumb", subject="breadcrumbs", excerpt=text(rng.randint(120, 300)),
                       when=NOW - (breadcrumbs - i) * DAY)
        for i in range(code):
            self.write("k_code", subject=f"aingram/n{i % 3}" if i % 2 else f"project-a/n{i % 4}",
                       kind="decision", excerpt=text(200), when=NOW - (code - i) * DAY / 4)

    def test_boot_fits_the_budget_on_a_seeded_log(self):
        # Untrimmed this boot is about 1.7k estimated tokens (core ~890, tail ~750),
        # which the example policy's 2k budget holds whole.
        self.seed()
        out = self.boot()
        self.assertLessEqual(svc.estimate_tokens(out), self.policy.boot["token_budget"])
        self.assertNotIn("trimmed", out)
        self.assertEqual(len(out["core"]), 15)
        self.assertEqual(len(out["recent"]), self.policy.boot["recent_tail"])
        self.assertIn("Code logged 100 entries", out["code_digest"])

    def test_a_tighter_budget_sheds_the_oldest_tail_first(self):
        self.seed()
        object.__setattr__(self.policy, "boot", {**self.policy.boot, "token_budget": 1500})
        out = self.boot()
        self.assertLessEqual(svc.estimate_tokens(out), 1500)
        self.assertGreater(out["trimmed"]["recent"], 0)
        self.assertNotIn("core_excerpts", out["trimmed"])
        self.assertTrue(all(c["excerpt"] for c in out["core"]))

    def test_an_oversized_core_is_trimmed_to_fit(self):
        self.seed(pinned=40, core_chars=300, breadcrumbs=20, code=0)
        out = self.boot()
        self.assertLessEqual(svc.estimate_tokens(out), self.policy.boot["token_budget"])
        trimmed = out["trimmed"]
        self.assertEqual(trimmed["recent"], self.policy.boot["recent_tail"])  # the tail goes first
        self.assertGreater(trimmed["core_excerpts"], 0)
        self.assertEqual(len(out["core"]), 40)  # every core entry stays, by id and subject
        self.assertIsNotNone(out["core"][0]["excerpt"])  # the oldest keep their excerpts
        self.assertIsNone(out["core"][-1]["excerpt"])

    def test_tail_is_trimmed_before_core(self):
        out = {"core": [{"id": "c", "subject": "s", "excerpt": "e" * 300}],
               "recent": [{"id": str(i), "excerpt": "r" * 300} for i in range(8)]}
        svc.fit_budget(out, 300)
        self.assertEqual(out["core"][0]["excerpt"], "e" * 300)
        self.assertLess(len(out["recent"]), 8)
        self.assertEqual(out["recent"][0]["id"], "0")  # the newest stay


if __name__ == "__main__":
    unittest.main()
