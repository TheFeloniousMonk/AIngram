# AIngram

A long-term memory for AI agents, kept outside the session. An engram is the trace a memory leaves behind; AIngram is that trace, as an append-only, hash-chained log in a single SQLite file, served to agents over MCP.

- **The log is the truth.** Entries are only ever appended. What an agent reads is folded from the log: the current state of each subject, not its history.
- **Every entry says where it came from.** The writing voice and key are fixed by the credential, never by the request, and the writer flags whether untrusted outside text was in its context.
- **Forgetting is built in.** Redaction removes an entry's content and leaves a tombstone, and the chain still verifies.
- **No model on the server.** Writers supply excerpts and keywords. The server stores, hashes, checks and folds.
- **Admin is a wallet, not a shell.** The admin signs in to a web page with an Ethereum wallet, and every change is signed by that wallet again. Neither a session nor shell access to the server is enough to mint keys, redact, or change policy.

## Layout

| File | Role |
| --- | --- |
| `schema.sql` | Tables and the triggers that make the log append-only |
| `aingram_core.py` | Canonical hashing, append, redact, verify, export. The hashing contract is in [HASHING.md](HASHING.md) and pinned by `vectors.json` |
| `aingram_policy.py` | Loads `policy.yaml` strictly and decides who may write, read and redact what |
| `aingram_service.py` | Policy-checked operations shared by the server and the CLI |
| `aingram_server.py` | MCP server: `boot`, `recall`, `read`, `write`, `redact`, plus the admin page |
| `aingram_web.py` | Admin page routes: wallet sign-in, sessions, the admin API |
| `aingram_admin.py` | Admin operations (prepare and confirm signed commands), and a read-only CLI |
| `admin_auth.py` | Signed admin commands: nonce, EIP-191 signature check, audit log |
| `admin/` | The admin page: plain HTML, CSS and JavaScript, no build step |

## Setup

Python 3.11+ and SQLite with FTS5 (bundled with CPython).

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env            # set your admin wallet address and public URL
python aingram_server.py
```

All deployment settings come from the environment or `.env`; see [.env.example](.env.example). Only two need setting: `AINGRAM_ADMIN_ADDRESS`, the wallet that administers this server, and `AINGRAM_PUBLIC_URL`.

The server listens on `AINGRAM_HOST:AINGRAM_PORT` (loopback by default) and serves MCP at `/mcp`, the admin page at `/admin`, and a health check at `/healthz`. Put it behind a TLS reverse proxy that forwards the `Host` header.

## How agents read it

- **`boot`** returns the pinned core, the voice's recent tail, a one-line digest of what the other voice wrote since the brain last woke, and how many writes are left today. It stays within the policy's `boot.token_budget` (estimated from the response size, since the server runs no model): over budget, it drops the oldest tail entries first, then the excerpts of the newest core entries, and says what it trimmed.
- **Decay.** Each entry's salience is 2^(−days since last use ÷ half-life). Below `decay.fade_below` an entry has faded: it leaves the recent tail and sinks in search, but stays in the log and can still be read. Reading an entry by id, or citing it in a new entry's `refs`, resets its clock and stretches its half-life. Pinned entries never fade.
- **`recall`** by subject returns that subject's current state, newest first. By query, it ranks full-text matches by relevance times salience and marks faded hits.

## Admin

Open `https://<your server>/admin` in a browser that has your wallet (Rabby, MetaMask, or any wallet that injects into the page) and sign in. The sign-in is a standard Sign-In with Ethereum message naming your server, so your wallet can warn you if a look-alike site asks for it. Only the admin wallet gets in.

Signing in lets you look: entries, keys, the policy and the admin activity log. Every change pops up in your wallet with the exact command, and happens only if you approve it there:

- **Policy.** A new server starts with no policy, and memory stays off until you approve one. The page offers `policy.example.yaml` as a first draft. Edit it in the page, check the changes, and approve them in your wallet. Every approved version is kept.
- **Keys.** Create a key for a coding agent, and the page shows the secret once, along with ready-to-paste settings for Claude Code. Replace or revoke keys from the same list.
- **Memory.** Browse by subject or search. Open an entry to see everything about it, including its salience, and use *Forget this entry* to redact it. Entries that relied on it are listed for review. *Faded* lists what fell below the fade line and when, which is what to look at when tuning half-lives.
- **Overview.** Verify the chain and download an export.

Sessions end after 30 minutes idle, 8 hours after sign-in, or at sign-out.

A read-only CLI is kept for scripts, such as a scheduled export. It changes nothing and needs no signature:

```bash
python aingram_admin.py keys list
python aingram_admin.py verify
python aingram_admin.py export --out night.jsonl
python aingram_admin.py policy status
```

## Security model

- A caller's voice comes only from its key. Keys are 256-bit random secrets, stored as SHA-256 and shown once.
- Policy decides what each voice may write, read, pin and redact. The server loads only policy text the admin wallet approved, and re-checks its hash on load.
- An admin session can only look. A stolen session cookie can't change anything, because every change needs a fresh wallet signature over that exact command. The cookie is HttpOnly and SameSite=Strict, only its hash is stored, and changing requests must come from the server's own origin. *Sign out everywhere* on the overview ends every session at once.
- Read what your wallet shows before approving. Command messages start with `AIngram admin command` and name the server and the exact action. Approve them only on your own admin page, never because another site asks. For a policy, the wallet shows only the policy's hash: the page checks that it matches the text and changes you reviewed.
- Changing `AINGRAM_ADMIN_ADDRESS` or the public URL makes earlier policy approvals no longer apply (they were signed by another wallet, or for another server). The server then starts with memory off until the admin approves a policy again.
- If the approved policy can't be loaded (an upgrade added a setting it lacks, or its stored text was altered), the server fails closed: it starts with memory off, and the admin page shows the problem and opens that policy for fixing.
- Run the service with a private temp directory (for systemd, `PrivateTmp=yes`). Exports are built in a private folder and removed after download.
- The admin page loads no third-party code and runs under a strict Content Security Policy. Everything it shows from the store is inserted as text, never as HTML, since entries can contain text an agent read on the web.
- Redaction zeroes freed pages, merges the full-text index and checkpoints the WAL, so forgotten content leaves the database files, not just the views.
- What signatures can't stop: anyone who can write the database file or the server's environment as the service user can forge rows or swap the admin address. Run the server as a dedicated user that owns the store and `.env` (mode 0600), and nobody else. The defense against root on the host is detection off the host: a nightly export checked with `python aingram_core.py extends old.jsonl new.jsonl` on a machine the host can't reach.
- The chain head (latest seq and id) is in every response, for every voice. That reveals that someone wrote, never what.

## Tests

```bash
python -m unittest test_core test_admin_auth test_policy test_admin test_admin_web test_server test_views
python make_vectors.py --check
```

## License

MIT. See [LICENSE](LICENSE).
