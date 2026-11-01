"""AIngram policy layer: who may write, read and redact what.

The policy file is loaded once and validated strictly: an unknown key, a
missing section or a malformed pattern is an error, and the server refuses to
start rather than run on a policy it half understands.

This layer decides permission. It never hashes and never writes; the service
layer calls it, then calls the core.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import yaml

VOICES = ("brain", "code", "admin")
REDACT_MODES = ("own", "none", "any")
KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
CTX_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
SUBJECT_MAX = 200


class PolicyError(Exception):
    """The policy file is invalid. Nothing should run on it."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


ALLOW = Decision(True)


def refuse(reason: str) -> Decision:
    return Decision(False, reason)


# ---------------------------------------------------------------- subjects

def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def subject_problem(subject: str) -> str | None:
    """Why a subject is malformed, or None if it is fine."""
    if not isinstance(subject, str) or not subject:
        return "subject is required"
    if len(subject) > SUBJECT_MAX:
        return f"subject is longer than {SUBJECT_MAX} characters"
    if subject != subject.strip():
        return "subject has leading or trailing whitespace"
    if any(unicodedata.category(c).startswith("C") for c in subject):
        return "subject contains control or invisible characters"
    if "*" in subject:
        return "subject may not contain '*'"
    for segment in subject.split("/"):
        if segment in ("", ".", ".."):
            return "subject segments must be non-empty and not '.' or '..'"
        if segment != segment.strip():
            return "subject segments may not start or end with whitespace"
    return None


def _check_pattern(pattern, where: str) -> str:
    if not isinstance(pattern, str):
        raise PolicyError(f"{where}: pattern must be a string")
    pattern = nfc(pattern)
    if pattern == "**":
        return pattern
    base = pattern[:-3] if pattern.endswith("/**") else pattern
    problem = subject_problem(base)
    if problem:
        raise PolicyError(f"{where}: bad pattern {pattern!r}: {problem}")
    return pattern


def matches(pattern: str, subject: str) -> bool:
    """'**' matches everything; 'a/**' matches 'a' and anything below it;
    anything else matches exactly. Comparison is case-insensitive, so
    'People/x' cannot slip past a rule written for 'people/**'."""
    subject = nfc(subject).casefold()
    pattern = nfc(pattern).casefold()
    if pattern == "**":
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return subject == prefix or subject.startswith(prefix + "/")
    return subject == pattern


def matches_any(patterns, subject: str) -> bool:
    return any(matches(p, subject) for p in patterns)


# ---------------------------------------------------------------- the policy

@dataclass(frozen=True)
class VoiceRules:
    kinds: tuple[str, ...] | None          # None means any kind
    write_subjects: tuple[str, ...]
    read_subjects: tuple[str, ...]
    may_pin: bool
    may_redact: str                        # own | none | any
    daily_write_cap: int | None            # None means no cap


@dataclass(frozen=True)
class Policy:
    voices: Mapping[str, VoiceRules]
    brain_only_subjects: tuple[str, ...]
    reserved_subjects: tuple[str, ...]
    reserved_kinds: tuple[str, ...]
    half_life_days: Mapping[str, float]
    reinforce_multiplier: float
    half_life_cap_days: float
    reinforced_by: tuple[str, ...]
    boot: Mapping[str, object]
    limits: Mapping[str, int]
    command_ttl_seconds: int
    sha256: str = field(default="")

    # -- writes

    def check_write(self, voice: str, subject: str, kind: str, pinned: bool = False,
                    untrusted_ctx: str | None = None) -> Decision:
        rules = self.voices.get(voice)
        if rules is None or voice == "admin":
            return refuse(f"voice {voice!r} may not write through this interface")
        problem = subject_problem(subject)
        if problem:
            return refuse(problem)
        if not isinstance(kind, str) or not KIND_RE.match(kind):
            return refuse("kind must be 1-32 characters: lowercase letters, digits, '-' or '_', "
                          "starting with a letter")
        if untrusted_ctx is not None and not CTX_RE.match(untrusted_ctx):
            return refuse("untrusted_ctx must be a short lowercase label such as 'web', or null")
        if kind in self.reserved_kinds:
            return refuse(f"kind {kind!r} is reserved for the server")
        if matches_any(self.reserved_subjects, subject):
            return refuse(f"subject {subject!r} is reserved for the server")
        if voice != "brain" and matches_any(self.brain_only_subjects, subject):
            return refuse(f"only the brain may write under {subject!r}")
        if rules.kinds is not None and kind not in rules.kinds:
            return refuse(f"the {voice} voice may write only these kinds: {', '.join(rules.kinds)}")
        if not matches_any(rules.write_subjects, subject):
            return refuse(f"the {voice} voice may not write under {subject!r}")
        if pinned and not rules.may_pin:
            return refuse(f"the {voice} voice may not pin entries")
        return ALLOW

    def check_content(self, excerpt: str, keywords, body: str, refs=()) -> Decision:
        lim = self.limits
        if not isinstance(excerpt, str) or not excerpt.strip():
            return refuse("excerpt is required")
        if not isinstance(body, str):
            return refuse("body must be a string")
        if len(body) > lim["body_max_chars"]:
            return refuse(f"body is longer than {lim['body_max_chars']} characters")
        if not isinstance(keywords, (list, tuple)) or not all(isinstance(k, str) for k in keywords):
            return refuse("keywords must be a list of strings")
        if len(keywords) > lim["keywords_max"]:
            return refuse(f"at most {lim['keywords_max']} keywords")
        if any(len(k) > lim["keyword_max_chars"] for k in keywords):
            return refuse(f"each keyword may be at most {lim['keyword_max_chars']} characters")
        if len(refs) > lim["refs_max"]:
            return refuse(f"at most {lim['refs_max']} refs")
        return ALLOW

    def writes_today(self, conn, voice: str, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%dT00:00:00.000000Z")
        return conn.execute("SELECT COUNT(*) FROM entries WHERE voice = ? AND ts >= ?",
                            (voice, day)).fetchone()[0]

    def headroom(self, conn, voice: str, now: datetime | None = None) -> int | None:
        cap = self.voices[voice].daily_write_cap
        return None if cap is None else max(0, cap - self.writes_today(conn, voice, now))

    def check_cap(self, conn, voice: str, now: datetime | None = None) -> Decision:
        """Counted per voice and UTC day, so minting more keys never raises a cap."""
        if self.headroom(conn, voice, now) == 0:
            cap = self.voices[voice].daily_write_cap
            return refuse(f"the {voice} voice has reached its daily cap of {cap} writes (resets 00:00 UTC)")
        return ALLOW

    # -- reads and redaction

    def check_read(self, voice: str, subject: str) -> Decision:
        rules = self.voices.get(voice)
        if rules is None or not matches_any(rules.read_subjects, subject):
            return refuse(f"the {voice} voice may not read {subject!r}")
        return ALLOW

    def check_redact(self, voice: str, target: Mapping) -> Decision:
        rules = self.voices.get(voice)
        if rules is None or rules.may_redact == "none":
            return refuse(f"the {voice} voice may not redact")
        if target["kind"] in self.reserved_kinds:
            return refuse("server records such as tombstones cannot be redacted")
        if target["redacted_at"] is not None:
            return refuse("that entry is already redacted")
        if rules.may_redact == "own" and target["voice"] != voice:
            return refuse(f"the {voice} voice may redact only entries it wrote")
        return ALLOW

    def check_supersede(self, voice: str, subject: str, target: Mapping) -> Decision:
        """A correction retires its target from the subject's view, so it must
        stay inside the subject, and only the brain may retire another voice's entry."""
        if target["kind"] in self.reserved_kinds:
            return refuse("server records cannot be superseded")
        if nfc(target["subject"]).casefold() != nfc(subject).casefold():
            return refuse("an entry can only supersede an entry in the same subject")
        if voice != "brain" and target["voice"] != voice:
            return refuse(f"the {voice} voice may supersede only entries it wrote")
        return ALLOW

    def half_life_for(self, kind: str, pinned: bool) -> float | None:
        if pinned:
            return None
        return self.half_life_days.get(kind, self.half_life_days["default"])


# ---------------------------------------------------------------- loading

TOP_KEYS = {"voices", "admin", "brain_only_subjects", "reserved_subjects", "reserved_kinds",
            "decay", "boot", "limits"}
VOICE_KEYS = {"may_write_kinds", "may_write_subjects", "may_read_subjects", "may_pin",
              "may_redact", "daily_write_cap"}
LIMIT_KEYS = {"body_max_chars", "keywords_max", "keyword_max_chars", "refs_max", "recall_max"}
BOOT_KEYS = {"recent_tail", "token_budget", "code_digest", "redaction_notice"}
DECAY_KEYS = {"half_life_days", "reinforce_multiplier", "half_life_cap_days", "reinforced_by"}


def _exact_keys(obj, keys: set, where: str) -> dict:
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: must be a mapping")
    missing, extra = keys - obj.keys(), obj.keys() - keys
    if missing:
        raise PolicyError(f"{where}: missing {', '.join(sorted(missing))}")
    if extra:
        raise PolicyError(f"{where}: unknown {', '.join(sorted(map(str, extra)))}")
    return obj


def _str_list(obj, where: str) -> tuple[str, ...]:
    if not isinstance(obj, list) or not all(isinstance(x, str) and x for x in obj):
        raise PolicyError(f"{where}: must be a list of non-empty strings")
    return tuple(nfc(x) for x in obj)


def _patterns(obj, where: str) -> tuple[str, ...]:
    return tuple(_check_pattern(p, where) for p in _str_list(obj, where))


def _pos_int(obj, where: str, allow_null: bool = False) -> int | None:
    if obj is None and allow_null:
        return None
    if not isinstance(obj, int) or isinstance(obj, bool) or obj <= 0:
        raise PolicyError(f"{where}: must be a positive integer{' or null' if allow_null else ''}")
    return obj


def _pos_num(obj, where: str) -> float:
    if not isinstance(obj, (int, float)) or isinstance(obj, bool) or obj <= 0:
        raise PolicyError(f"{where}: must be a positive number")
    return float(obj)


def _voice(name: str, raw) -> VoiceRules:
    where = f"voices.{name}"
    raw = _exact_keys(raw, VOICE_KEYS, where)
    kinds = raw["may_write_kinds"]
    if kinds == "*":
        kinds = None
    else:
        kinds = _str_list(kinds, f"{where}.may_write_kinds")
        for k in kinds:
            if not KIND_RE.match(k):
                raise PolicyError(f"{where}.may_write_kinds: bad kind {k!r}")
    if not isinstance(raw["may_pin"], bool):
        raise PolicyError(f"{where}.may_pin: must be true or false")
    if raw["may_redact"] not in REDACT_MODES:
        raise PolicyError(f"{where}.may_redact: must be one of {', '.join(REDACT_MODES)}")
    return VoiceRules(
        kinds=kinds,
        write_subjects=_patterns(raw["may_write_subjects"], f"{where}.may_write_subjects"),
        read_subjects=_patterns(raw["may_read_subjects"], f"{where}.may_read_subjects"),
        may_pin=raw["may_pin"],
        may_redact=raw["may_redact"],
        daily_write_cap=_pos_int(raw["daily_write_cap"], f"{where}.daily_write_cap", allow_null=True),
    )


def parse_policy(data: bytes) -> Policy:
    try:
        raw = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as e:
        raise PolicyError(f"policy is not valid YAML: {e}") from None
    raw = _exact_keys(raw, TOP_KEYS, "policy")

    voices_raw = _exact_keys(raw["voices"], set(VOICES), "voices")
    voices = {name: _voice(name, voices_raw[name]) for name in VOICES}
    if voices["brain"].may_redact == "any" or voices["code"].may_redact == "any":
        raise PolicyError("only the admin voice may redact any entry")

    admin = _exact_keys(raw["admin"], {"command_ttl_seconds"}, "admin")
    ttl = _pos_int(admin["command_ttl_seconds"], "admin.command_ttl_seconds")

    decay = _exact_keys(raw["decay"], DECAY_KEYS, "decay")
    hl = decay["half_life_days"]
    if not isinstance(hl, dict) or "default" not in hl:
        raise PolicyError("decay.half_life_days: must be a mapping with a 'default' entry")
    half_life = {str(k): _pos_num(v, f"decay.half_life_days.{k}") for k in hl for v in [hl[k]]}
    multiplier = _pos_num(decay["reinforce_multiplier"], "decay.reinforce_multiplier")
    if multiplier < 1:
        raise PolicyError("decay.reinforce_multiplier: must be at least 1")
    cap_days = _pos_num(decay["half_life_cap_days"], "decay.half_life_cap_days")
    if any(v > cap_days for v in half_life.values()):
        raise PolicyError("decay.half_life_days: no half-life may exceed half_life_cap_days")
    reinforced_by = _str_list(decay["reinforced_by"], "decay.reinforced_by")
    if set(reinforced_by) - {"read", "cited_in_refs"}:
        raise PolicyError("decay.reinforced_by: allowed values are read and cited_in_refs")

    boot = _exact_keys(raw["boot"], BOOT_KEYS, "boot")
    _pos_int(boot["recent_tail"], "boot.recent_tail")
    _pos_int(boot["token_budget"], "boot.token_budget")
    if boot["code_digest"] != "one_line":
        raise PolicyError("boot.code_digest: only 'one_line' is supported")
    if not isinstance(boot["redaction_notice"], bool):
        raise PolicyError("boot.redaction_notice: must be true or false")

    limits = _exact_keys(raw["limits"], LIMIT_KEYS, "limits")
    limits = {k: _pos_int(v, f"limits.{k}") for k, v in limits.items()}

    reserved_kinds = _str_list(raw["reserved_kinds"], "reserved_kinds")
    if "redaction" not in reserved_kinds:
        raise PolicyError("reserved_kinds: must include 'redaction'")
    reserved_subjects = _patterns(raw["reserved_subjects"], "reserved_subjects")
    if not matches_any(reserved_subjects, "_redactions"):
        raise PolicyError("reserved_subjects: must cover '_redactions'")

    return Policy(
        voices=voices,
        brain_only_subjects=_patterns(raw["brain_only_subjects"], "brain_only_subjects"),
        reserved_subjects=reserved_subjects,
        reserved_kinds=reserved_kinds,
        half_life_days=half_life,
        reinforce_multiplier=multiplier,
        half_life_cap_days=cap_days,
        reinforced_by=reinforced_by,
        boot=dict(boot),
        limits=limits,
        command_ttl_seconds=ttl,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def load_policy(path) -> Policy:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise PolicyError(f"cannot read policy file {path}: {e.strerror}") from None
    return parse_policy(data)
