# Changelog

Versions follow [semantic versioning](https://semver.org). A change to the
hashing or schema version (`V` in `aingram_core.py`) is always a major version.

## 1.0.0 (2026-11-02)

The first release.

- Append-only, hash-chained memory log in SQLite, with forgetting by tombstone
  and published test vectors for the hashing.
- Policy for each voice (brain, code, admin), stored in the database and only
  in force once the admin wallet approves it.
- MCP server with five tools (boot, recall, read, write, redact): bearer keys
  for Claude Code, OAuth for Claude's connector, each grant approved by wallet.
- Fading in the read path, salience ranking, and a boot budget that never
  trims the pinned core.
- Wallet-gated admin page: overview, memory, policy, keys and activity, with
  every change signed by the admin wallet.
- Nightly off-server backup that checks the chain, the policies and the keys
  against the last good copy.
- Wallet-approved import of existing memory, keeping sources and original
  dates.
- Plain-language docs site.
