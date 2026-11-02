"""OAuth for the brain voice: claude.ai's connector, approved by the admin wallet.

claude.ai custom connectors speak OAuth, and nothing in a chat can sign with a
wallet, so the brain gets tokens instead of a key. The flow:

  1. The connector registers itself (RFC 7591). Only redirect URIs in
     AINGRAM_OAUTH_REDIRECT_URIS (Claude's callback by default) are accepted.
  2. It sends the admin to /authorize. The MCP SDK validates the request
     (client, redirect URI, PKCE, scope); authorize() seals it with an HMAC
     into the link of the approval page, so nothing is stored yet.
  3. On /oauth/grant the admin's wallet signs a Sign-In with Ethereum message
     naming this server, the voice being granted, and the exact request.
     approve() checks it, creates a key row for the grant (voice brain), and
     returns the redirect carrying a one-time code.
  4. The connector trades the code (with its PKCE verifier) for an access
     token (ACCESS_TTL) and a refresh token (REFRESH_TTL). Refreshing rotates
     both. Only token hashes are stored, and revoking the grant's key on the
     admin page cuts every token issued under it.

The same provider also accepts Code's static bearer keys, so one verifier
serves both voices. A token's `subject` is always the key it acts for.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

import anyio.to_thread
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      RefreshToken, RegistrationError, TokenError)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

import aingram_admin as admin
import aingram_core as core
import aingram_service as svc

SCOPE = "brain"
ACCESS_TTL = timedelta(days=7)      # long, so refreshes (and stale-session trouble) are rare
REFRESH_TTL = timedelta(days=90)
CODE_TTL = timedelta(minutes=5)
REQUEST_TTL = timedelta(minutes=10)  # time to open the page, connect the wallet and sign
UNUSED_CLIENT_TTL = timedelta(hours=1)  # a registration that led to no token is pruned after this
UNUSED_CLIENTS_MAX = 1000               # and at most this many unused ones are kept
REGISTRATIONS_PER_IP_HOUR = 10
REGISTER_BODY_MAX = 16 * 1024
ACCESS_RE = re.compile(r"^aiga_[A-Za-z0-9_-]{43}$")
REFRESH_RE = re.compile(r"^aigr_[A-Za-z0-9_-]{43}$")
NAME_MAX = 60


def grant_statement(about: dict) -> str:
    """What the admin's wallet shows: the voice, the connector, and where it returns to.
    The connector names itself at registration, so its name is cleaned to one plain line;
    the return host comes from the allowlisted redirect URI and can't be chosen freely."""
    return (f"Grant the brain voice of this AIngram server to {clean_name(about)} "
            f"(returns to {about['redirect_host']}). It will read and write memory as the brain.")


def clean_name(about_or_name) -> str:
    """One plain line: no control, format (bidi), or separator characters, at most NAME_MAX."""
    name = about_or_name["client_name"] if isinstance(about_or_name, dict) else about_or_name
    name = "".join(c for c in str(name or "") if unicodedata.category(c)[0] not in "CZ" or c == " ")
    return name[:NAME_MAX].strip() or "a connector"


def _token(prefix: str) -> str:
    return prefix + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    # validate=True: one spelling per value, so a link can't be re-spelled into another Request ID.
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


class GrantCode(AuthorizationCode):
    key_id: str


class AIngramOAuth:
    """The MCP SDK's OAuthAuthorizationServerProvider, backed by the AIngram store.
    `app` is aingram_server.AIngram (settings and connect())."""

    def __init__(self, app, key: bytes | None = None):
        self.app = app
        s = app.settings
        self.mcp_url = f"{s.public_url}/mcp"
        self.redirects = set(s.oauth_redirect_uris)
        self._key = key or secrets.token_bytes(32)
        self._codes: dict[str, GrantCode] = {}
        self._lock = threading.Lock()

    async def _db(self, fn, *args):
        def run():
            with self.app.connect() as conn:
                return fn(conn, *args)
        return await anyio.to_thread.run_sync(run)

    # ------------------------------------------------------------ clients

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        def get(conn):
            row = conn.execute("SELECT info FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()
            return OAuthClientInformationFull.model_validate_json(row["info"]) if row else None
        return await self._db(get)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Anyone can register (Claude's callback URL is public), so registration is cheap
        to refuse and cheap to keep: only allowlisted redirect URIs, only the fields the
        flow needs (the name trimmed to one plain line), and unused registrations pruned.
        The per-IP rate limit is in front of this, in limit_registrations()."""
        uris = {str(u) for u in client_info.redirect_uris or []}
        if not uris or not uris <= self.redirects:
            raise RegistrationError("invalid_redirect_uri",
                                    "this server only accepts connectors from Claude (claude.ai)")
        kept = OAuthClientInformationFull(
            client_id=client_info.client_id, client_secret=client_info.client_secret,
            client_id_issued_at=client_info.client_id_issued_at,
            client_secret_expires_at=client_info.client_secret_expires_at,
            redirect_uris=client_info.redirect_uris, grant_types=client_info.grant_types,
            response_types=client_info.response_types,
            token_endpoint_auth_method=client_info.token_endpoint_auth_method,
            scope=client_info.scope, client_name=clean_name(client_info.client_name or ""))

        def store(conn):
            now = datetime.now(timezone.utc)
            unused = "client_id NOT IN (SELECT client_id FROM oauth_tokens)"
            conn.execute(f"DELETE FROM oauth_clients WHERE created_at < ? AND {unused}",
                         (svc._iso(now - UNUSED_CLIENT_TTL),))
            conn.execute(f"DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM oauth_clients "
                         f"WHERE {unused} ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (UNUSED_CLIENTS_MAX - 1,))
            conn.execute("INSERT INTO oauth_clients (client_id, info, created_at) VALUES (?,?,?)",
                         (kept.client_id, kept.model_dump_json(exclude_none=True), svc._iso(now)))
        await self._db(store)

    # ------------------------------------------------------------ authorization

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and params.resource.rstrip("/") not in (self.mcp_url, self.app.settings.public_url):
            raise AuthorizeError("invalid_target", "tokens here are only for this server's /mcp")
        return f"{self.app.settings.public_url}/oauth/grant?r={self.seal(client.client_id, params)}"

    def seal(self, client_id: str, params: AuthorizationParams, now: float | None = None) -> str:
        """The authorization request, HMAC-sealed into the approval link: no server state
        until the admin signs, so unauthenticated /authorize calls can't fill anything."""
        body = json.dumps({
            "c": client_id, "u": str(params.redirect_uri), "x": params.redirect_uri_provided_explicitly,
            "s": params.state, "p": params.code_challenge, "r": params.resource,
            "t": int(now or time.time()),
        }, separators=(",", ":")).encode()
        mac = hmac.new(self._key, body, "sha256").digest()[:16]
        return f"{_b64(body)}.{_b64(mac)}"

    def unseal(self, sealed, now: float | None = None) -> dict:
        try:
            body_b64, mac_b64 = sealed.split(".")
            body, mac = _unb64(body_b64), _unb64(mac_b64)
        except (AttributeError, ValueError, TypeError):
            raise admin.Refused("this approval link is not valid; connect again from Claude") from None
        if not hmac.compare_digest(mac, hmac.new(self._key, body, "sha256").digest()[:16]):
            raise admin.Refused("this approval link is not valid; connect again from Claude")
        req = json.loads(body)
        if (now or time.time()) - req["t"] > REQUEST_TTL.total_seconds():
            raise admin.Refused("this approval link expired; connect again from Claude")
        return req

    @staticmethod
    def request_id(sealed: str) -> str:
        """Names one exact request in the signed message (from the decoded bytes, so
        there is exactly one Request ID per request)."""
        body_b64, mac_b64 = sealed.split(".")
        return hashlib.sha256(_unb64(body_b64) + b"." + _unb64(mac_b64)).hexdigest()[:32]

    def describe(self, conn, sealed) -> dict:
        req = self.unseal(sealed)
        row = conn.execute("SELECT info FROM oauth_clients WHERE client_id = ?", (req["c"],)).fetchone()
        if row is None:
            raise admin.Refused("this connector is not registered; connect again from Claude")
        info = json.loads(row["info"])
        return {"client_name": clean_name(info.get("client_name") or ""),
                "redirect_host": urlparse(req["u"]).netloc, "voice": SCOPE,
                "request_id": self.request_id(sealed),
                # How long ago Connect was clicked: an old request is a reason to stop and ask why.
                "age_seconds": max(0, int(time.time()) - req["t"])}

    def approve(self, conn, sealed) -> str:
        """After the admin's signature is verified: create the grant and return the redirect."""
        req = self.unseal(sealed)
        about = self.describe(conn, sealed)
        key_id = f"k_brain_{secrets.token_hex(4)}"
        core.add_key(conn, key_id=key_id, voice="brain",
                     label=f"{clean_name(about)} connector, via {about['redirect_host']}")
        code = secrets.token_urlsafe(32)
        with self._lock:
            now = time.time()
            for c, g in list(self._codes.items()):
                if g.expires_at < now:
                    del self._codes[c]
            self._codes[code] = GrantCode(
                code=code, scopes=[SCOPE], expires_at=now + CODE_TTL.total_seconds(), client_id=req["c"],
                code_challenge=req["p"], redirect_uri=req["u"], redirect_uri_provided_explicitly=req["x"],
                resource=self.mcp_url, subject=key_id, key_id=key_id)
        return self._redirect(req, code=code)

    def deny(self, sealed) -> str:
        return self._redirect(self.unseal(sealed), error="access_denied",
                              error_description="the admin declined")

    @staticmethod
    def _redirect(req: dict, **params) -> str:
        if req["s"] is not None:
            params["state"] = req["s"]
        sep = "&" if urlparse(req["u"]).query else "?"
        return f"{req['u']}{sep}{urlencode(params)}"

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        with self._lock:
            code = self._codes.get(authorization_code)
        return code if code and code.client_id == client.client_id else None

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: GrantCode) -> OAuthToken:
        with self._lock:
            if self._codes.pop(authorization_code.code, None) is None:
                raise TokenError("invalid_grant", "authorization code already used")
        return await self._db(self._issue, client.client_id, authorization_code.key_id)

    # ------------------------------------------------------------ tokens

    def _issue(self, conn, client_id: str, key_id: str) -> OAuthToken:
        now = int(time.time())
        access, refresh = _token("aiga_"), _token("aigr_")
        for token, kind, ttl in ((access, "access", ACCESS_TTL), (refresh, "refresh", REFRESH_TTL)):
            conn.execute("INSERT INTO oauth_tokens (token_hash, kind, key_id, client_id, scopes, resource, "
                         "created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                         (svc.hash_secret(token), kind, key_id, client_id, SCOPE, self.mcp_url,
                          core.utc_now(), now + int(ttl.total_seconds())))
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=int(ACCESS_TTL.total_seconds()),
                          refresh_token=refresh, scope=SCOPE)

    @staticmethod
    def _live(conn, token: str, kind: str):
        """The token row and its key, if the token is unexpired, unrevoked and its grant still stands."""
        row = conn.execute(
            "SELECT t.*, k.voice, k.revoked_at AS key_revoked FROM oauth_tokens t JOIN keys k ON k.key_id = t.key_id "
            "WHERE t.token_hash = ? AND t.kind = ?", (svc.hash_secret(token), kind)).fetchone()
        if (row is None or row["revoked_at"] is not None or row["key_revoked"] is not None
                or row["expires_at"] < time.time() or row["voice"] != SCOPE):
            return None
        return row

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        if not REFRESH_RE.match(refresh_token or ""):
            return None
        row = await self._db(self._live, refresh_token, "refresh")
        if row is None or row["client_id"] != client.client_id:
            return None
        return RefreshToken(token=row["token_hash"], client_id=row["client_id"], scopes=[SCOPE],
                            expires_at=row["expires_at"], resource=row["resource"], subject=row["key_id"])

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        def rotate(conn):
            conn.execute("BEGIN IMMEDIATE")
            try:
                n = conn.execute("UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                                 (core.utc_now(), refresh_token.token)).rowcount
                if n != 1:
                    raise TokenError("invalid_grant", "refresh token already used")
                out = self._issue(conn, client.client_id, refresh_token.subject)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            return out
        return await self._db(rotate)

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Both voices' credentials: Code's static keys and the brain's OAuth tokens."""
        if svc.SECRET_RE.match(token or ""):
            found = await anyio.to_thread.run_sync(self.app.lookup_key, token)
            if found is None:
                return None
            key_id, voice = found
            return AccessToken(token=svc.hash_secret(token), client_id=key_id, scopes=[voice],
                               resource=self.mcp_url, subject=key_id)
        if not ACCESS_RE.match(token or ""):
            return None  # malformed tokens never touch the database

        def lookup(conn):
            row = self._live(conn, token, "access")
            if row is not None:
                svc.touch_key(conn, row["key_id"])
            return row
        row = await self._db(lookup)
        if row is None:
            return None
        return AccessToken(token=row["token_hash"], client_id=row["client_id"], scopes=[SCOPE],
                           expires_at=row["expires_at"], resource=row["resource"], subject=row["key_id"])

    async def revoke_token(self, token) -> None:
        """A connector disconnecting: end every token it holds for that grant. The grant
        itself (its key) stays until the admin revokes it."""
        if token.subject is None or token.client_id == token.subject:
            return  # a static key: those are revoked on the admin page, not over OAuth

        def revoke(conn):
            conn.execute("UPDATE oauth_tokens SET revoked_at = ? WHERE key_id = ? AND client_id = ? "
                         "AND revoked_at IS NULL", (core.utc_now(), token.subject, token.client_id))
        await self._db(revoke)


def limit_registrations(asgi, per_hour: int = REGISTRATIONS_PER_IP_HOUR):
    """ASGI wrapper: at most `per_hour` POST /register per client IP, and small bodies only.
    Per IP, so one abuser can't use up registrations for everyone else (the client IP is
    the proxy's X-Forwarded-For, which uvicorn trusts only from 127.0.0.1)."""
    seen: dict[str, list[float]] = {}
    lock = threading.Lock()

    async def app(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/register" and scope["method"] == "POST":
            length = dict(scope.get("headers") or []).get(b"content-length")
            if length is None or not length.isdigit() or int(length) > REGISTER_BODY_MAX:
                return await _refuse(send, 413, "registration body must be small and have a length")
            ip = (scope.get("client") or ("?", 0))[0]
            now = time.time()
            with lock:
                for k in [k for k, v in seen.items() if not v or now - v[-1] > 3600]:
                    del seen[k]
                times = [t for t in seen.get(ip, []) if now - t < 3600]
                allowed = len(times) < per_hour
                if allowed:
                    times.append(now)
                seen[ip] = times
            if not allowed:
                return await _refuse(send, 429, "too many registrations from this address; try again later")
        return await asgi(scope, receive, send)
    return app


async def _refuse(send, status: int, description: str):
    body = json.dumps({"error": "invalid_client_metadata", "error_description": description}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
