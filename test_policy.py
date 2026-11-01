"""Run: python -m unittest test_policy -v"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import aingram_core as core
import aingram_policy as pol

EXAMPLE = Path(__file__).with_name("policy.example.yaml")


def example_raw():
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def parse(raw):
    return pol.parse_policy(yaml.safe_dump(raw).encode())


class Fixture(unittest.TestCase):
    def setUp(self):
        self.p = pol.load_policy(EXAMPLE)

    def ok(self, d):
        self.assertTrue(d, d.reason)

    def no(self, d, fragment):
        self.assertFalse(d)
        self.assertIn(fragment, d.reason)


class BrainRow(Fixture):
    """brain: any kind, any subject, can pin, redacts its own, cap 300."""

    def test_any_kind_any_subject(self):
        for subject, kind in [("people/sister", "fact"), ("misc/poems", "poem"),
                              ("project-a/x", "breadcrumb"), ("self", "correction")]:
            self.ok(self.p.check_write("brain", subject, kind))

    def test_may_pin(self):
        self.ok(self.p.check_write("brain", "identity/core", "fact", pinned=True))

    def test_redacts_own_only(self):
        self.ok(self.p.check_redact("brain", {"voice": "brain", "kind": "fact", "redacted_at": None}))
        self.no(self.p.check_redact("brain", {"voice": "code", "kind": "gotcha", "redacted_at": None}),
                "only entries it wrote")

    def test_cap(self):
        self.assertEqual(self.p.voices["brain"].daily_write_cap, 300)


class CodeRow(Fixture):
    """code: decision/shipped/gotcha under its project subjects, no pin, no redact, cap 60."""

    def test_allowed_kinds_under_allowed_subjects(self):
        for kind in ("decision", "shipped", "gotcha"):
            self.ok(self.p.check_write("code", "aingram/build", kind))
        self.ok(self.p.check_write("code", "project-a", "decision"))  # the prefix itself

    def test_other_kinds_refused(self):
        for kind in ("fact", "breadcrumb", "poem", "correction"):
            self.no(self.p.check_write("code", "aingram/build", kind), "only these kinds")

    def test_other_subjects_refused(self):
        self.no(self.p.check_write("code", "elsewhere/x", "decision"), "may not write under")
        self.no(self.p.check_write("code", "aingram-other/x", "decision"), "may not write under")

    def test_may_not_pin(self):
        self.no(self.p.check_write("code", "aingram/x", "decision", pinned=True), "may not pin")

    def test_may_not_redact(self):
        self.no(self.p.check_redact("code", {"voice": "code", "kind": "gotcha", "redacted_at": None}),
                "may not redact")

    def test_cap(self):
        self.assertEqual(self.p.voices["code"].daily_write_cap, 60)


class AdminRow(Fixture):
    """admin: nothing through the write interface; redacts anything."""

    def test_cannot_write(self):
        self.no(self.p.check_write("admin", "_redactions", "redaction"), "may not write")
        self.no(self.p.check_write("admin", "misc", "fact"), "may not write")

    def test_redacts_anything(self):
        for voice in ("brain", "code"):
            self.ok(self.p.check_redact("admin", {"voice": voice, "kind": "fact", "redacted_at": None}))

    def test_no_cap(self):
        self.assertIsNone(self.p.voices["admin"].daily_write_cap)


class SelfAndReserved(Fixture):
    def test_brain_only_subjects(self):
        raw = example_raw()
        raw["voices"]["code"]["may_write_subjects"] = ["**"]  # even a wide-open code rule
        p = parse(raw)
        for subject in ("people/sister", "self", "self/x", "ways-of-working/a", "identity/b"):
            self.no(p.check_write("code", subject, "decision"), "only the brain")

    def test_case_cannot_dodge_brain_only(self):
        raw = example_raw()
        raw["voices"]["code"]["may_write_subjects"] = ["**"]
        p = parse(raw)
        self.no(p.check_write("code", "People/sister", "decision"), "only the brain")
        self.no(p.check_write("code", "SELF", "decision"), "only the brain")

    def test_reserved_subject_and_kind(self):
        for voice in ("brain", "code"):
            self.no(self.p.check_write(voice, "_redactions", "decision"), "reserved")
            self.no(self.p.check_write(voice, "_redactions/x", "decision"), "reserved")
        self.no(self.p.check_write("brain", "misc", "redaction"), "reserved")

    def test_tombstones_cannot_be_redacted(self):
        self.no(self.p.check_redact("admin", {"voice": "brain", "kind": "redaction", "redacted_at": None}),
                "tombstones")

    def test_already_redacted(self):
        self.no(self.p.check_redact("admin", {"voice": "brain", "kind": "fact", "redacted_at": "x"}),
                "already redacted")

    def test_unknown_voice(self):
        self.assertFalse(self.p.check_write("mallory", "misc", "fact"))
        self.assertFalse(self.p.check_redact("mallory", {"voice": "brain", "kind": "fact", "redacted_at": None}))


class InputShape(Fixture):
    def test_bad_subjects(self):
        for subject in ("", " a", "a/", "/a", "a//b", "a/../b", "a/*", "a​b", "a\nb", "x" * 201):
            self.assertFalse(self.p.check_write("brain", subject, "fact"), repr(subject))

    def test_bad_kinds(self):
        for kind in ("", "Fact", "1fact", "fact!", "x" * 33):
            self.assertFalse(self.p.check_write("brain", "misc", kind), repr(kind))

    def test_untrusted_ctx_shape(self):
        self.ok(self.p.check_write("brain", "misc", "fact", untrusted_ctx="web"))
        self.assertFalse(self.p.check_write("brain", "misc", "fact", untrusted_ctx="Web Page"))

    def test_content_limits(self):
        self.ok(self.p.check_content("e", ["a"], "body"))
        self.assertFalse(self.p.check_content("", [], ""))
        self.assertFalse(self.p.check_content("e", ["k"] * 33, ""))
        self.assertFalse(self.p.check_content("e", ["x" * 65], ""))
        self.assertFalse(self.p.check_content("e", [], "x" * 200001))
        self.assertFalse(self.p.check_content("e", [], "", refs=["a" * 64] * 33))
        self.assertFalse(self.p.check_content("e", "not a list", ""))


class Supersede(Fixture):
    def test_same_subject_only(self):
        t = {"voice": "brain", "kind": "fact", "subject": "misc/a"}
        self.ok(self.p.check_supersede("brain", "misc/a", t))
        self.no(self.p.check_supersede("brain", "misc/b", t), "same subject")

    def test_code_cannot_retire_brain_entries(self):
        t = {"voice": "brain", "kind": "decision", "subject": "aingram/x"}
        self.no(self.p.check_supersede("code", "aingram/x", t), "only entries it wrote")
        self.ok(self.p.check_supersede("code", "aingram/x", {**t, "voice": "code"}))

    def test_brain_can_retire_code_entries(self):
        t = {"voice": "code", "kind": "decision", "subject": "aingram/x"}
        self.ok(self.p.check_supersede("brain", "aingram/x", t))

    def test_tombstones_cannot_be_superseded(self):
        t = {"voice": "brain", "kind": "redaction", "subject": "_redactions"}
        self.no(self.p.check_supersede("brain", "_redactions", t), "server records")


class Reads(Fixture):
    def test_read_rules(self):
        raw = example_raw()
        raw["voices"]["code"]["may_read_subjects"] = ["aingram/**"]
        p = parse(raw)
        self.ok(p.check_read("code", "aingram/x"))
        self.no(p.check_read("code", "people/sister"), "may not read")
        self.ok(p.check_read("brain", "people/sister"))


class Caps(unittest.TestCase):
    def setUp(self):
        raw = example_raw()
        raw["voices"]["code"]["daily_write_cap"] = 3
        self.p = parse(raw)
        self.conn = core.connect(":memory:")
        for k in ("k_code_a", "k_code_b"):
            core.add_key(self.conn, key_id=k, voice="code")
        core.add_key(self.conn, key_id="k_brain", voice="brain")
        self.now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)

    def put(self, key, when):
        core.append(self.conn, key_id=key, subject="aingram/x", kind="decision", excerpt="e",
                    keywords=[], body="", ts=when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    def test_cap_is_per_voice_not_per_key(self):
        self.put("k_code_a", self.now)
        self.put("k_code_b", self.now)
        self.assertTrue(self.p.check_cap(self.conn, "code", self.now))
        self.put("k_code_a", self.now)
        d = self.p.check_cap(self.conn, "code", self.now)
        self.assertFalse(d)
        self.assertIn("daily cap of 3", d.reason)
        self.assertEqual(self.p.headroom(self.conn, "code", self.now), 0)

    def test_other_voice_unaffected(self):
        for _ in range(3):
            self.put("k_code_a", self.now)
        self.assertTrue(self.p.check_cap(self.conn, "brain", self.now))

    def test_cap_resets_at_utc_midnight(self):
        yesterday = self.now - timedelta(days=1)
        for _ in range(3):
            self.put("k_code_a", yesterday)
        self.assertTrue(self.p.check_cap(self.conn, "code", self.now))
        self.assertEqual(self.p.headroom(self.conn, "code", self.now), 3)

    def test_no_cap_for_admin(self):
        self.assertIsNone(self.p.headroom(self.conn, "admin", self.now))
        self.assertTrue(self.p.check_cap(self.conn, "admin", self.now))


class HalfLife(Fixture):
    def test_from_policy(self):
        self.assertEqual(self.p.half_life_for("breadcrumb", False), 30.0)
        self.assertEqual(self.p.half_life_for("fact", False), 180.0)
        self.assertIsNone(self.p.half_life_for("fact", True))


class InvalidFiles(unittest.TestCase):
    def bad(self, mutate, fragment):
        raw = example_raw()
        mutate(raw)
        with self.assertRaises(pol.PolicyError) as cm:
            parse(raw)
        self.assertIn(fragment, str(cm.exception))

    def test_example_is_valid(self):
        pol.load_policy(EXAMPLE)

    def test_missing_file(self):
        with self.assertRaises(pol.PolicyError):
            pol.load_policy("does-not-exist.yaml")

    def test_not_yaml(self):
        with self.assertRaises(pol.PolicyError):
            pol.parse_policy(b"voices: [unclosed")

    def test_unknown_top_key(self):
        self.bad(lambda r: r.update(extra=1), "unknown extra")

    def test_typo_in_voice_key(self):
        def m(r):
            r["voices"]["code"]["may_pinn"] = r["voices"]["code"].pop("may_pin")
        self.bad(m, "voices.code")

    def test_missing_voice(self):
        self.bad(lambda r: r["voices"].pop("code"), "missing code")

    def test_bad_redact_mode(self):
        self.bad(lambda r: r["voices"]["code"].update(may_redact="some"), "may_redact")

    def test_brain_may_not_redact_any(self):
        self.bad(lambda r: r["voices"]["brain"].update(may_redact="any"), "only the admin")

    def test_bad_cap(self):
        self.bad(lambda r: r["voices"]["code"].update(daily_write_cap=0), "daily_write_cap")
        self.bad(lambda r: r["voices"]["code"].update(daily_write_cap="60"), "daily_write_cap")

    def test_bad_pattern(self):
        self.bad(lambda r: r["voices"]["code"].update(may_write_subjects=["a/*"]), "bad pattern")
        self.bad(lambda r: r["voices"]["code"].update(may_write_subjects=["a//**"]), "bad pattern")

    def test_reserved_must_cover_redactions(self):
        self.bad(lambda r: r.update(reserved_kinds=[]), "reserved_kinds")
        self.bad(lambda r: r.update(reserved_subjects=["other"]), "reserved_subjects")

    def test_decay_needs_default(self):
        self.bad(lambda r: r["decay"]["half_life_days"].pop("default"), "default")

    def test_half_life_over_cap(self):
        self.bad(lambda r: r["decay"]["half_life_days"].update(default=10000), "half_life_cap_days")

    def test_bad_ttl(self):
        self.bad(lambda r: r["admin"].update(command_ttl_seconds=-1), "command_ttl_seconds")

    def test_hash_tracks_file_bytes(self):
        a = pol.parse_policy(EXAMPLE.read_bytes())
        b = pol.parse_policy(EXAMPLE.read_bytes() + b"\n# comment\n")
        self.assertNotEqual(a.sha256, b.sha256)


if __name__ == "__main__":
    unittest.main()
