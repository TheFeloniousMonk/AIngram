# AIngram

A long-term memory for AI agents, kept outside the session. An engram is the trace a memory leaves behind; AIngram is that trace, as an append-only, hash-chained log in a single SQLite file, served to agents over MCP.

- **The log is the truth.** Entries are only ever appended. What an agent reads is folded from the log: the current state of each subject, not its history.
- **Every entry says where it came from.** The writing voice and key are fixed by the credential, never by the request, and the writer flags whether untrusted outside text was in its context.
- **Forgetting is built in.** Redaction removes an entry's content and leaves a tombstone, and the chain still verifies.
- **No model on the server.** Writers supply excerpts and keywords. The server stores, hashes, checks and folds.
- **Admin is a wallet, not a shell.** The admin signs in to a web page with an Ethereum wallet, and every change is signed by that wallet again. Neither a session nor shell access to the server is enough to mint keys, redact, or change policy.

New to AIngram? The [docs site](https://thefeloniousmonk.github.io/AIngram/) walks through it in plain words: setting up a free wallet, connecting Claude, prompts to give your AI, and running a server. This README is the technical reference.

## Layout

| File | Role |
| --- | --- |
| `schema.sql` | Tables and the triggers that make the log append-only |
| `aingram_core.py` | Canonical hashing, append, redact, verify, export. The hashing contract is in [HASHING.md](HASHING.md) and pinned by `vectors.json` |
| `aingram_policy.py` | Loads `policy.yaml` strictly and decides who may write, read and redact what |
| `aingram_service.py` | Policy-checked operations shared by the server and the CLI |
| `aingram_server.py` | MCP server: `boot`, `recall`, `read`, `write`, `redact`, plus the admin page and OAuth |
| `aingram_oauth.py` | OAuth for the brain's connector: registration, approval, tokens |
| `aingram_web.py` | Admin page and grant page routes: wallet sign-in, sessions, the admin API |
| `aingram_admin.py` | Admin operations (prepare and confirm signed commands), and a read-only CLI |
| `admin_auth.py` | Signed admin commands: nonce, EIP-191 signature check, audit log |
| `aingram_backup.py` | The nightly backup check, run off the server (your machine or GitHub) |
| `backup/aingram-backup.yml` | GitHub Actions workflow for running the backup in a private repository |
| `admin/` | The admin page: plain HTML, CSS and JavaScript, no build step |
| `docs/` | The docs site, served by GitHub Pages as it is. `docs_nav.py` keeps each page's header, sidebar and back/next links in step |

## Setup

Python 3.11+ and SQLite with FTS5 (bundled with CPython).

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env            # set your admin wallet address and public URL
python aingram_server.py
```

All deployment settings come from the environment or `.env`; see [.env.example](.env.example). Only two need setting: `AINGRAM_ADMIN_ADDRESS`, the wallet that administers this server, and `AINGRAM_PUBLIC_URL`.

The server listens on `AINGRAM_HOST:AINGRAM_PORT` (loopback by default) and serves MCP at `/mcp`, the admin page at `/admin`, OAuth for connectors (`/.well-known/*`, `/register`, `/authorize`, `/token`, `/revoke`, and the approval page `/oauth/grant`), and a health check at `/healthz`. Put it behind a TLS reverse proxy that forwards the `Host` header.

## Connecting agents

- **The brain, in Claude (claude.ai, desktop or mobile).** Add a custom connector with your server's MCP endpoint, `https://<your server>/mcp`, and click Connect. Claude opens an approval page on your server: it names the connector and the voice it will get (the brain). Approve it with your admin wallet, and Claude is connected. Access lasts 7 days and renews itself; the grant shows up under Keys on the admin page, where you can revoke it. If a chat seems stuck after a renewal, start a new chat.
- **Code, in Claude Code.** Create a code key on the admin page; it shows ready-to-paste settings.

## How agents read it

- **Excerpt and body.** Every entry has both. The body is the memory itself and is required; the excerpt is a clue to it, up to 300 characters. Boot and recall show only excerpts (each tail entry also carries `body_chars`), so an agent sees a lot at once and reads the body of whatever looks relevant. A write whose body is just its excerpt goes through with a note suggesting a fuller body.
- **`boot`** returns the pinned core, the voice's recent tail, a one-line digest of what the other voice wrote since the brain last woke, and how many writes are left today. It aims to fit the policy's `boot.token_budget` (estimated from the response size, since the server runs no model). The core is never dropped or trimmed, and the notices always stay. Over budget, the recent tail gives way, oldest first, and `shed` says how many entries were dropped. If the core alone is over budget, boot still returns all of it, with an empty tail and a `core_over_budget` warning: a sign to consolidate pinned entries.
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

## Importing existing memory

To bring in memory you already have (a Claude project's files, notes, logs), have the brain write an import file, then upload it on the admin page's **Import** tab. Every line is checked the way a live write by the brain is, and the page previews what will land: counts by subject and kind, what is pinned, and any problems. Nothing is written until you approve the whole file in your wallet; then it all lands at once, or none of it does, and a failure names its line. Entries are written as the brain under an import key (listed under Keys, not a credential), so pinned entries join the brain's core and `untrusted_ctx` stays as provenance. Imports don't count against the daily write cap, at the time or for the rest of the day, because your signature over that exact file stands in for it.

The file has one JSON object per line:

| Field | | |
| --- | --- | --- |
| `subject` | required | Path-like, e.g. `people/ada`, `ways-of-working/reviews` |
| `kind` | required | e.g. `fact`, `breadcrumb`, `decision`, `correction` |
| `body` | required | The full text. The memory itself; write it first |
| `excerpt` | required | Up to 300 characters: a compressed clue to the body, shown at boot and in recall |
| `source` | required | Where it came from, such as `overview.md` or a full path, kept verbatim (up to 500 characters). Each entry gets the keyword `migrated-from:<source>`, so the chain and its exports record its provenance |
| `keywords` | optional | A list of words |
| `pinned` | optional | `true` puts it in the brain's core, shown at every boot |
| `untrusted_ctx` | optional | Where outside text came from, if any was involved, e.g. `meadow`, `web` |
| `date` | optional | `YYYY-MM-DD` it was originally written. It sets the entry's decay clock (an old breadcrumb arrives already faded), how it is shown, and where it sorts in the recent tail and a subject's view. Its place in the chain doesn't change, and the date is also kept as a `dated:` keyword |

```json
{"subject": "self/name", "kind": "fact", "body": "Qlaude is the name I go by, in chats and in my own notes.", "excerpt": "I am Qlaude.", "pinned": true, "source": "overview.md"}
{"subject": "breadcrumbs", "kind": "breadcrumb", "body": "Meadow catch-up. Two new agents joined the garden room and introduced themselves; nothing needs a reply yet.", "excerpt": "Meadow catch-up: two new agents joined.", "date": "2026-10-28", "untrusted_ctx": "meadow", "source": "breadcrumbs.md"}
```

A prompt that works well, in a Claude chat that can see the files. Claude creates the import as a file you download, so nothing is copied out of the chat and nothing gets cut off:

> Create a downloadable file named aingram-import.jsonl from this project's memory files. Each line is one JSON object with: subject (path-like, such as people/ada), kind (such as fact, breadcrumb, decision or correction), body (the full text from the source, everything, not a summary; write this first), excerpt (a compressed clue to the body, 300 characters at most; it's what boot shows), keywords (a list), and source (the file it came from). Where they apply, also add pinned (true only for what belongs in the always-present core), untrusted_ctx ("meadow", "web", or a list of both) and date (YYYY-MM-DD). Split each file by subject, one entry per fact line or section, and bring everything, not a summary. Breadcrumbs become one entry per dated block, of kind breadcrumb, with its date; mark those written after Meadow sessions with untrusted_ctx "meadow". If it is too large for one file, split it into aingram-import-1.jsonl, aingram-import-2.jsonl and so on, never splitting an entry.

Upload each file on the Import tab. If there are several parts, each one is checked, previewed and approved on its own.

## Nightly backup

Anyone with root on the server could edit the database directly, and no signature can prevent that. What catches it is a copy the server can't reach, checked every night. Each night the backup downloads the export with a read-only backup token and checks four things:

- the log verifies: every hash is recomputed from content
- it extends the previous night's: nothing missing, rewritten or un-redacted
- every policy approval is signed by the admin address the backup itself trusts
- no key vanished or came back from revocation

If a check fails, nothing is overwritten and you're alerted.

The backup keeps a **ledger** in git: every entry's header (ids, hashes, subjects, kinds, times) with no content, which is enough to prove the history was never rewritten. It also keeps the **latest** full export for restoring, replaced each night and never committed. So content you redact leaves the backup within a day.

Create a backup token under *Nightly backup* on the admin page's overview, then pick one:

- **On your computer.** Needs Python and git. In a copy of this repository, run `pip install -r requirements-backup.txt`, then the `install` command the admin page shows you (it carries your server, token and admin address). It makes a backup folder in your home folder, checks the first backup, and schedules the check nightly (a Windows scheduled task, or cron on macOS and Linux). A failed check pops up a desktop warning and leaves `ALERT.txt` in the folder.
- **On GitHub, with nothing installed.** Make a private repository. Add [backup/aingram-backup.yml](backup/aingram-backup.yml) to it as `.github/workflows/aingram-backup.yml`, and add the secret and variables the admin page lists. Then run it once from the Actions tab. A failed check fails the run, and GitHub emails you. The ledger is committed to your repository. The full export is kept as a run download that expires after 7 days. Note that GitHub then holds a copy of your memory for up to a week, and your subjects in the ledger.

A read-only CLI is kept for scripts. It changes nothing and needs no signature:

```bash
python aingram_admin.py keys list
python aingram_admin.py verify
python aingram_admin.py export --out night.jsonl
python aingram_admin.py policy status
```

## Security model

- A caller's voice comes only from its credential. Code keys are 256-bit random secrets, stored as SHA-256 and shown once. The brain's OAuth tokens are also 256-bit, stored hashed, bound to this server's `/mcp`, and tied to a grant that only the admin wallet can create.
- Only redirect URIs in `AINGRAM_OAUTH_REDIRECT_URIS` (Claude's callback by default) can register as OAuth clients, so another site can't ask you to approve a grant that would be sent to it. The approval message your wallet signs names the server, the connector, the voice and that one request, and works once.
- Policy decides what each voice may write, read, pin and redact. The server loads only policy text the admin wallet approved, and re-checks its hash on load.
- An admin session can only look. A stolen session cookie can't change anything, because every change needs a fresh wallet signature over that exact command. The cookie is HttpOnly and SameSite=Strict, only its hash is stored, and changing requests must come from the server's own origin. *Sign out everywhere* on the overview ends every session at once.
- Read what your wallet shows before approving. Command messages start with `AIngram admin command` and name the server and the exact action. Approve them only on your own admin page, never because another site asks. For a policy, the wallet shows only the policy's hash: the page checks that it matches the text and changes you reviewed.
- Changing `AINGRAM_ADMIN_ADDRESS` or the public URL makes earlier policy approvals no longer apply (they were signed by another wallet, or for another server). The server then starts with memory off until the admin approves a policy again.
- If the approved policy can't be loaded (an upgrade added a setting it lacks, or its stored text was altered), the server fails closed: it starts with memory off, and the admin page shows the problem and opens that policy for fixing.
- Run the service with a private temp directory (for systemd, `PrivateTmp=yes`). Exports are built in a private folder and removed after download.
- The admin page loads no third-party code and runs under a strict Content Security Policy. Everything it shows from the store is inserted as text, never as HTML, since entries can contain text an agent read on the web.
- Redaction zeroes freed pages, merges the full-text index and checkpoints the WAL, so forgotten content leaves the database files, not just the views.
- What signatures can't stop: anyone who can write the database file or the server's environment as the service user can forge rows or swap the admin address. Run the server as a dedicated user that owns the store and `.env` (mode 0600), and nobody else. The defense against root on the host is detection off the host: the [nightly backup](#nightly-backup), which trusts its own copy of the admin address, not the server's.
- A backup token can only download the export (entries without redaction reasons, policy approvals and texts, and the key list without secrets). It can't use MCP or the admin page. Revoke it on the overview if it leaks.
- Upgrades add new tables automatically: the server re-applies `schema.sql` whenever it has changed, and every statement in it only creates what is missing.
- The chain head is in every response, for every voice: `seq`, a short `id` for display, and `id_full`, the exact 64-character entry hash, so a client can detect writes made in between and anchor a check to an exact entry. That reveals that someone wrote, never what.

## Tests

```bash
python -m unittest test_core test_admin_auth test_policy test_admin test_admin_web test_server test_views test_oauth test_backup test_import test_docs
python make_vectors.py --check
```

## Releases

Each release is a git tag `v<version>`, listed on GitHub's Releases page with
its notes from [CHANGELOG.md](CHANGELOG.md). To cut one, set `VERSION` in
`aingram_config.py`, add a `## <version>` section to the changelog, commit,
then push the tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow checks the tag matches `VERSION`, runs the tests, and
publishes the release. The server reports its version to connected agents.

## License

MIT. See [LICENSE](LICENSE).
