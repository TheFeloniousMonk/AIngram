# AIngram hashing contract, version 1

This is the one part of AIngram that can't be changed casually. If two implementations disagree by a single byte here, the chain stops verifying, maybe months later. `aingram_core.py` is the reference implementation and `vectors.json` is the proof: any implementation that reproduces every field of `vectors.json` conforms.

## Canonical encoding

An object is hashed as UTF-8 JSON with keys sorted by code point, no insignificant whitespace, and no escaping of non-ASCII characters. For the restricted value set below, this is identical to RFC 8785 (JCS); we checked it against an independent RFC 8785 library.

Allowed values: `null`, `true`/`false`, integers within ±(2^53 − 1), strings, arrays, and objects with ASCII string keys. Floats are refused, because they have no single canonical spelling. Every string is NFC-normalised before encoding, and stored that way, so `café` typed with a combining accent and `café` typed as one character hash identically.

## Content hash

```
content_hash = sha256_hex(canonical({"v": 1, "excerpt", "keywords", "body", "salt"}))
```

`keywords` is normalised before hashing: NFC, trimmed, empties dropped, de-duplicated, sorted. `salt` is 16 random bytes as 32 lowercase hex characters, fresh per entry.

The salt is there for the right to forget. A redacted entry keeps its `content_hash` forever. Without a salt, anyone holding the log could confirm a guess about short redacted content ("is it 'the door code is 4071'?") by hashing the guess. Redaction nulls the salt along with the content, so after redaction the hash can't be checked against guesses.

## Entry hash (the entry id)

```
id = sha256_hex(canonical({
  "v": 1, "seq", "prev_hash", "ts", "voice", "key_id", "subject", "kind",
  "supersedes", "refs", "pinned", "untrusted_ctx", "content_hash"
}))
```

`prev_hash` is the previous entry's `id`; the first entry's is 64 zeros. `ts` is set by the server as `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, microseconds). `voice` comes from the key, never from the request. `refs` is sorted and de-duplicated. `pinned` is a boolean in the hash, stored as 0/1. `supersedes` and `untrusted_ctx` are `null` when absent.

## Redaction

Redaction sets `excerpt`, `keywords`, `body` and `salt` to null and stamps `redacted_at`. Every header field, including `content_hash` and `id`, stays exactly as it was, so the chain still verifies. A tombstone entry (`kind: "redaction"`, `subject: "_redactions"`, `refs: [target]`) is appended in the same transaction. The reason goes only into the admin-only `redactions` table.

## Verification

Walk entries in `seq` order. Check that `seq` is continuous and that `prev_hash` matches the previous `id`. For unredacted entries, recompute `content_hash` from stored content. For every entry, recompute `id` from the stored header. Check that every redacted entry has a redaction record and every redaction record points at a redacted entry. `python3 aingram_core.py store.db` does all of this.

## Changing this

Don't, unless you have to. If you must: bump `V`, regenerate `vectors.json` deliberately, and write a migration note. Old entries keep the `v` they were hashed with, and verifiers dispatch on it.
