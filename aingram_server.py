"""AIngram MCP server: five tools over streamable HTTP, the admin page at
/admin (aingram_web.py), and OAuth for the brain's claude.ai connector
(aingram_oauth.py). Code authenticates with a static bearer key; the brain
with OAuth tokens granted by the admin wallet.

Run behind a TLS reverse proxy:  python aingram_server.py
Settings come from the environment (.env.example). The policy in force is the
one the admin wallet last approved on the admin page. Until one is approved,
the tools refuse every call and only the admin page works. A new approval is
picked up on the next request. If the approved policy can't be loaded (its
text no longer validates after an upgrade, or was altered), memory stays off
and the admin page says why.

The caller's voice comes only from their key or grant. No tool argument can set it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import threading
from contextlib import contextmanager
from urllib.parse import urlparse

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

import aingram_core as core
import aingram_oauth
import aingram_service as svc
import aingram_web
from aingram_config import VERSION, ConfigError, Settings, load_env
from aingram_policy import Policy, PolicyError

log = logging.getLogger("aingram")

INSTRUCTIONS = """AIngram is a long-term memory: an append-only, hash-chained log.
Call boot first in a session: it returns the pinned core, the recent tail and a digest of other voices' entries.
recall finds entries by subject (folded current state) or by full-text query; it returns excerpts only.
read returns one full entry by id (a 12-character prefix is enough). The first entry's prev is
64 zeros, the chain's start; prev is null only when the previous entry is one you may not read.
write appends an entry. Set untrusted_ctx (for example 'web', or ['meadow', 'web']) when outside text was in your context.
Timestamps are UTC, so an entry written late in the evening can carry the next day's date.
redact forgets an entry's content, leaving a tombstone.
Every response includes the chain head: seq, a short id for display, and id_full, the exact
entry hash. If seq or id_full changed since you last looked, someone wrote in between."""


class AIngram:
    """Shared state: settings and the currently approved policy."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.Lock()
        # Why memory is off, when it is off for a reason other than "nothing approved yet".
        # Failing closed but running keeps the admin page up, so it can be fixed without a shell.
        self.policy_problem: str | None = None
        with self.connect() as conn:
            try:
                self.policy = svc.load_approved_policy(conn, settings.server_name, settings.admin_address)
            except PolicyError as e:
                self.policy, self.policy_problem = None, str(e)
                log.error("approved policy not loaded, memory is off until a policy is approved: %s", e)
            self._marker = svc.policy_approval_marker(conn)
        if self.policy is None and self.policy_problem is None:
            log.warning("no policy approved yet: sign in at %s/admin and approve one", settings.public_url)
        elif self.policy is not None:
            log.info("policy %s loaded", self.policy.sha256[:12])

    @contextmanager
    def connect(self):
        conn = core.connect(self.settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def current_policy(self, conn) -> Policy | None:
        marker = svc.policy_approval_marker(conn)
        if marker != self._marker:
            with self._lock:
                if marker != self._marker:
                    try:
                        policy = svc.load_approved_policy(conn, self.settings.server_name,
                                                          self.settings.admin_address)
                        if policy is not None:
                            self.policy, self.policy_problem = policy, None
                            log.info("policy %s approved and loaded", policy.sha256[:12])
                    except PolicyError as e:
                        self.policy_problem = f"the latest approval was not applied: {e}"
                        log.error("new policy approval not applied, keeping %s: %s",
                                  self.policy.sha256[:12] if self.policy else "none", e)
                    self._marker = marker
        return self.policy

    def lookup_key(self, secret: str):
        if not svc.SECRET_RE.match(secret or ""):
            return None  # malformed tokens never touch the database
        with self.connect() as conn:
            row = svc.authenticate(conn, secret)
            return None if row is None else (row["key_id"], row["voice"])


def _caller(ctx: Context) -> tuple[str, str]:
    """(key_id, voice) of the authenticated caller for this request. Every token the
    provider accepts (a static key or an OAuth grant) names its key as `subject`."""
    token = None
    request = getattr(ctx.request_context, "request", None)
    user = request.scope.get("user") if isinstance(request, Request) else None
    if user is not None and hasattr(user, "access_token"):
        token = user.access_token
    token = token or get_access_token()
    if token is None or not token.subject or not token.scopes or token.scopes[0] not in ("brain", "code"):
        raise ToolError("not authenticated")
    return token.subject, token.scopes[0]


def _json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def build_server(app: AIngram) -> MCPServer:
    public = app.settings.public_url
    oauth = aingram_oauth.AIngramOAuth(app)
    server = MCPServer(
        name="aingram",
        version=VERSION,
        instructions=INSTRUCTIONS,
        auth_server_provider=oauth,
        auth=AuthSettings(
            issuer_url=public, resource_server_url=f"{public}/mcp", validate_token_resource=True,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[aingram_oauth.SCOPE], default_scopes=[aingram_oauth.SCOPE]),
            revocation_options=RevocationOptions(enabled=True)),
    )

    def run(ctx: Context, fn):
        key_id, voice = _caller(ctx)
        try:
            with app.connect() as conn:
                policy = app.current_policy(conn)
                if policy is None:
                    raise ToolError("AIngram is not set up yet: the admin has not approved a policy")
                return _json(fn(conn, policy, key_id, voice))
        except (svc.ServiceError, core.AIngramError) as e:
            raise ToolError(str(e)) from None
        except sqlite3.IntegrityError as e:
            raise ToolError(f"refused by the store: {e}") from None

    readonly = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

    @server.tool(annotations=readonly, structured_output=False)
    def boot(ctx: Context) -> str:
        """Start of session. Returns the pinned core, the recent tail of your own entries,
        a one-line digest of what the other voice logged since you last woke, how many
        writes you have left today, and the chain head, within the policy's token budget.
        The core is always whole. Over budget, the tail drops its oldest entries and
        'shed' says how many; if the core alone is over budget, 'warnings' carries
        core_over_budget: consolidate pinned entries."""
        return run(ctx, lambda c, p, k, v: svc.boot(c, p, v))

    @server.tool(annotations=readonly, structured_output=False)
    def recall(ctx: Context, subject: str | None = None, query: str | None = None,
               kind: str | None = None, limit: int = 10) -> str:
        """Find entries. Give exactly one of:
        subject: a path like 'people/sister' returns that subject's current state
                 (redacted and superseded entries dropped), newest first; 'projects/**' includes everything below it.
        query: plain words, full-text matched against subject, excerpt, keywords and body.
        Optional kind filter and limit (default 10). Returns excerpts with ids; use read for a full body."""
        return run(ctx, lambda c, p, k, v: svc.recall(c, p, v, subject=subject, query=query,
                                                      kind=kind, limit=limit))

    @server.tool(annotations=readonly, structured_output=False)
    def read(ctx: Context, id: str) -> str:
        """Read one full entry by id or unique id prefix (12 characters is plenty):
        header, excerpt, keywords, body, prev, what it supersedes and what supersedes it.
        Reading counts as deliberate use and slows the entry's fading."""
        return run(ctx, lambda c, p, k, v: svc.read(c, p, v, id))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                             idempotentHint=False, openWorldHint=False),
                 structured_output=False)
    def write(ctx: Context, subject: str, kind: str, excerpt: str, keywords: list[str] | None = None,
              body: str = "", supersedes: str | None = None, refs: list[str] | None = None,
              pinned: bool = False, untrusted_ctx: str | list[str] | None = None) -> str:
        """Append an entry.
        subject: path-like retrieval key, e.g. 'aingram/build'. kind: e.g. fact, breadcrumb,
        correction, decision, shipped, gotcha. excerpt: up to 300 characters, what boot and recall show.
        keywords: free-form list. body: full text, any length within the policy limit.
        supersedes: id of the entry in the same subject this one corrects or replaces.
        refs: ids this entry cites (citing an entry reinforces it).
        pinned: always in the brain's boot core (brain only).
        untrusted_ctx: where outside text in your context came from: one label ('web') or a list of
          up to 4 (['meadow', 'web']); stored sorted, as 'meadow,web'. Omit if there was none.
        Returns the new id, seq and chain head."""
        return run(ctx, lambda c, p, k, v: svc.write(
            c, p, k, subject=subject, kind=kind, excerpt=excerpt, keywords=keywords or [],
            body=body, supersedes=supersedes, refs=refs or [], pinned=pinned, untrusted_ctx=untrusted_ctx))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                             idempotentHint=False, openWorldHint=False),
                 structured_output=False)
    def redact(ctx: Context, id: str, reason: str) -> str:
        """Forget an entry's content. Its header stays so the chain still verifies, a tombstone
        records that something was removed (never what), and the reason is kept only for the admin.
        Entries that superseded or cited it are listed for review, not removed."""
        return run(ctx, lambda c, p, k, v: svc.redact(c, p, k, id, reason))

    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    aingram_web.add_routes(server, app, oauth)
    return server


def transport_security(settings: Settings) -> TransportSecuritySettings:
    parsed = urlparse(settings.public_url)
    host = parsed.netloc
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"127.0.0.1:{settings.port}", f"localhost:{settings.port}"],
        allowed_origins=[f"{parsed.scheme}://{host}"],
    )


def create_app(settings: Settings):
    """The ASGI app. A policy that can't be loaded leaves memory off, not the server down."""
    app = AIngram(settings)
    server = build_server(app)
    return aingram_oauth.limit_registrations(server.streamable_http_app(
        streamable_http_path="/mcp", json_response=True, stateless_http=True,
        transport_security=transport_security(settings), host=settings.host))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        load_env()
        settings = Settings.from_env(need_server=True)
        if not settings.loopback_bind:
            log.warning("listening on %s, not loopback: make sure only the TLS proxy can reach it",
                        settings.host)
        asgi = create_app(settings)
    except (ConfigError, PolicyError) as e:
        log.error("refusing to start: %s", e)
        return 1
    import uvicorn
    uvicorn.run(asgi, host=settings.host, port=settings.port, log_level="info",
                proxy_headers=True, forwarded_allow_ips="127.0.0.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
