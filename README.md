# AIngram

A long-term memory for AI agents, kept outside the session. An engram is the trace a memory leaves behind; AIngram is that trace, as an append-only, hash-chained log in a single SQLite file, served to agents over MCP.

- **The log is the truth.** Entries are only ever appended. What an agent reads is folded from the log: the current state of each subject, not its history.
- **Every entry says where it came from.** The writing voice and key are fixed by the credential, never by the request, and the writer flags whether untrusted outside text was in its context.
- **Forgetting is built in.** Redaction removes an entry's content and leaves a tombstone, and the chain still verifies.
- **No model on the server.** Writers supply excerpts and keywords. The server stores, hashes, checks and folds.
- **Admin is a wallet, not a shell.** Every admin action is signed by an Ethereum wallet. Shell access to the server alone is not enough to mint keys, redact, or change policy.

## Layout

| File | Role |
| --- | --- |
| `schema.sql` | Tables and the triggers that make the log append-only |
| `aingram_core.py` | Canonical hashing, append, redact, verify, export. The hashing contract is in [HASHING.md](HASHING.md) and pinned by `vectors.json` |
| `aingram_policy.py` | Loads `policy.yaml` strictly and decides who may write, read and redact what |
| `aingram_service.py` | Policy-checked operations shared by the server and the CLI |
| `aingram_server.py` | MCP server: `boot`, `recall`, `read`, `write`, `redact` |
| `aingram_admin.py` | Admin CLI, run on the server host. Changes are wallet-signed |
| `admin_auth.py` | Signed admin commands: nonce, EIP-191 signature check, audit log |
| `tools/sign.html` | Signs an admin command with any browser wallet |

## Setup

Python 3.11+ and SQLite with FTS5 (bundled with CPython).

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env            # then edit it
cp policy.example.yaml policy.yaml   # then edit it
```

All deployment settings come from the environment or `.env`; see [.env.example](.env.example). Keep your real `policy.yaml` under version control somewhere you control. It decides what each voice may do, so changes to it should be reviewable commits.

## Admin

Read-only commands need no signature:

```bash
python aingram_admin.py keys list
python aingram_admin.py verify
python aingram_admin.py export --out night.jsonl
python aingram_admin.py policy status
```

Commands that change anything print a message for the admin wallet to sign (EIP-191 `personal_sign`), wait for the signature to be pasted back, and then perform exactly the signed action:

```bash
python aingram_admin.py policy reload                 # approve the current policy.yaml bytes
python aingram_admin.py keys mint --voice code --label "build agent"
python aingram_admin.py keys rotate k_code_1a2b3c4d
python aingram_admin.py keys revoke k_code_1a2b3c4d
python aingram_admin.py redact 1a2b3c4d5e6f --reason "asked to forget"
```

To sign from a browser wallet, serve `tools/` locally and open the page:

```bash
python -m http.server --bind 127.0.0.1 --directory tools 8000
```

Then go to `http://127.0.0.1:8000/sign.html`, paste the message, sign, and copy the signature back. `cast wallet sign "<message>"` works too.

The server will only load a policy whose exact bytes were approved by a signed `policy reload`, so run that once before the first start and again after every edit. A running server picks up a new approval on its next request.

## Server

```bash
python aingram_server.py
```

It listens on `AINGRAM_HOST:AINGRAM_PORT` (loopback by default) and serves MCP at `/mcp`, with a health check at `/healthz`. Put it behind a TLS reverse proxy that forwards the `Host` header. Clients authenticate with `Authorization: Bearer <secret>`.

## Security model

- A caller's voice comes only from its key. Keys are 256-bit random secrets, stored as SHA-256 and shown once.
- Policy decides what each voice may write, read, pin and redact. The server loads only policy bytes the admin wallet approved.
- Redaction zeroes freed pages, merges the full-text index and checkpoints the WAL, so forgotten content leaves the database files, not just the views.
- What signatures can't stop: anyone who can write the database file or the server's environment as the service user can forge rows or swap the admin address. Run the server as a dedicated user that owns the store and `.env` (mode 0600), and nobody else. The defense against root on the host is detection off the host: a nightly export checked with `python aingram_core.py extends old.jsonl new.jsonl` on a machine the host can't reach.
- The chain head (latest seq and id) is in every response, for every voice. That reveals that someone wrote, never what.

## Tests

```bash
python -m unittest test_core test_admin_auth test_policy test_admin_cli test_server
python make_vectors.py --check
```

## License

To be decided before the first release.
