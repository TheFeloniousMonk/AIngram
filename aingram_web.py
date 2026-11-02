"""AIngram admin web: wallet sign-in, a look-only session, and signed changes.

Served at /admin by the same app as /mcp.

Sign-in is Sign-In with Ethereum (EIP-4361): the server issues a one-time
message naming this site, the admin's wallet signs it, and the server opens a
session if the signer is AINGRAM_ADMIN_ADDRESS. The session is an HttpOnly,
SameSite=Strict cookie whose hash is stored in admin_sessions; it ends after
SESSION_IDLE without use, SESSION_MAX after sign-in, or at sign-out.

A session can only look. Every change goes through aingram_admin.prepare and
confirm, so the wallet signs each one, and a stolen cookie changes nothing.

State-changing requests must be JSON, from the public origin, carrying the
session cookie; the Host header must be one this server answers to.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import anyio.to_thread
from eth_utils import to_checksum_address
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

import admin_auth
import aingram_admin as admin
import aingram_oauth
import aingram_core as core
import aingram_service as svc
from aingram_config import ADDRESS_RE
from aingram_policy import PolicyError

SESSION_IDLE = timedelta(minutes=30)
SESSION_MAX = timedelta(hours=8)
SEEN_RESOLUTION = timedelta(seconds=60)
CHALLENGE_TTL = timedelta(minutes=5)
PREPARE_PER_MINUTE = 30
BODY_MAX = 512 * 1024
STATEMENT = "Sign in to the AIngram admin page. Signing in only lets you look; every change asks your wallet again."

STATIC_DIR = Path(__file__).with_name("admin")
STATIC = {"admin": ("index.html", "text/html; charset=utf-8"),
          "admin/admin.js": ("admin.js", "text/javascript; charset=utf-8"),
          "admin/wallet.js": ("wallet.js", "text/javascript; charset=utf-8"),
          "admin/admin.css": ("admin.css", "text/css; charset=utf-8"),
          "oauth/grant": ("grant.html", "text/html; charset=utf-8"),
          "admin/grant.js": ("grant.js", "text/javascript; charset=utf-8")}
PAGE_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                                "form-action 'none'; frame-ancestors 'none'"),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- sign-in

class SignIn:
    """EIP-4361 challenges that need no server state until they are used.

    The nonce is a random part plus an HMAC (under a per-process key) over the
    address, issue time and random part, so the server can recognise its own
    challenges without storing them, and nobody can fill a table to lock the
    admin out. Used nonces are remembered until they expire, and only a valid
    admin signature adds one. A restart just means signing in again.

    The same class signs voice grants (path /oauth/grant, its own statement):
    there the message also carries a Request ID naming the exact authorization
    request, and the MAC covers the URI, statement and request, so a signature
    for one purpose or one request can never be used for another."""

    def __init__(self, public_url: str, admin_address: str, key: bytes | None = None, *,
                 path: str = "/admin", statement: str = STATEMENT):
        self.domain = urlparse(public_url).netloc
        self.uri = f"{public_url}{path}"
        self.statement = statement
        self.admin = admin_address.lower()
        self._key = key or secrets.token_bytes(32)
        self._used: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def _mac(self, address: str, issued: str, rand: str, request_id: str | None, statement: str) -> str:
        data = f"{self.domain}|{self.uri}|{statement}|{address}|{issued}|{rand}|{request_id or ''}"
        return hmac.new(self._key, data.encode(), "sha256").hexdigest()[:32]

    def _message(self, address: str, issued: datetime, nonce: str, request_id: str | None, statement: str) -> str:
        lines = [
            f"{self.domain} wants you to sign in with your Ethereum account:",
            address,
            "",
            statement,
            "",
            f"URI: {self.uri}",
            "Version: 1",
            "Chain ID: 1",
            f"Nonce: {nonce}",
            f"Issued At: {issued.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"Expiration Time: {(issued + CHALLENGE_TTL).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        ]
        if request_id is not None:
            lines.append(f"Request ID: {request_id}")
        return "\n".join(lines)

    def challenge(self, address, now: datetime | None = None, request_id: str | None = None,
                  statement: str | None = None) -> str:
        if not isinstance(address, str) or not ADDRESS_RE.match(address):
            raise admin.Refused("connect a wallet first")
        statement = statement or self.statement
        now = (now or _now()).replace(microsecond=0)
        address = to_checksum_address(address)
        rand = secrets.token_hex(16)
        nonce = rand + self._mac(address, now.strftime("%Y-%m-%dT%H:%M:%SZ"), rand, request_id, statement)
        return self._message(address, now, nonce, request_id, statement)

    def verify(self, message, signature, now: datetime | None = None, request_id: str | None = None,
               statement: str | None = None) -> str:
        """The admin address, if this is an unused, unexpired challenge from this server
        (for request_id and statement, when given) signed by the admin wallet."""
        if not isinstance(message, str) or not isinstance(signature, str):
            raise admin.Refused("bad request")
        statement = statement or self.statement
        now = now or _now()
        lines = message.split("\n")
        unknown = admin.Refused("this sign-in request is unknown or already used; start again")
        expected = 11 if request_id is None else 12
        nonce = re.fullmatch(r"Nonce: ([0-9a-f]{32})([0-9a-f]{32})", lines[8]) if len(lines) == expected else None
        issued_m = re.fullmatch(r"Issued At: (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", lines[9]) if nonce else None
        if not issued_m or not ADDRESS_RE.match(lines[1]):
            raise unknown
        rand, mac = nonce.groups()
        issued_s = issued_m.group(1)
        issued = datetime.strptime(issued_s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if (not hmac.compare_digest(mac, self._mac(lines[1], issued_s, rand, request_id, statement))
                or self._message(lines[1], issued, rand + mac, request_id, statement) != message):
            raise unknown
        if not timedelta(0) <= now - issued <= CHALLENGE_TTL:
            raise admin.Refused("this sign-in request expired; start again")
        try:
            signer = admin_auth.recover_signer(message, signature).lower()
        except admin_auth.AdminAuthError:
            raise admin.Refused("the signature could not be checked") from None
        if signer != lines[1].lower():
            raise admin.Refused("the signature is not from the wallet named in the request")
        if not hmac.compare_digest(signer, self.admin):
            raise admin.Refused("this wallet is not the admin wallet for this server")
        with self._lock:
            for n, at in list(self._used.items()):
                if now - at > CHALLENGE_TTL:
                    del self._used[n]
            if rand in self._used:
                raise unknown
            self._used[rand] = issued
        return signer


# ---------------------------------------------------------------- sessions

def open_session(conn, address: str, now: datetime | None = None) -> str:
    now = now or _now()
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO admin_sessions (token_hash, address, created_at, last_seen_at, expires_at) "
                 "VALUES (?,?,?,?,?)", (_hash(token), address, _iso(now), _iso(now), _iso(now + SESSION_MAX)))
    return token


def session_address(conn, token, admin_address: str, now: datetime | None = None) -> str | None:
    """The signed-in address for a live session token, or None."""
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    now = now or _now()
    row = conn.execute("SELECT * FROM admin_sessions WHERE token_hash = ?", (_hash(token),)).fetchone()
    if (row is None or row["ended_at"] is not None or now >= _parse(row["expires_at"])
            or now - _parse(row["last_seen_at"]) > SESSION_IDLE
            or row["address"].lower() != admin_address.lower()):
        return None
    if now - _parse(row["last_seen_at"]) > SEEN_RESOLUTION:
        conn.execute("UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?",
                     (_iso(now), row["token_hash"]))
    return row["address"]


def end_all_sessions(conn) -> None:
    conn.execute("UPDATE admin_sessions SET ended_at = ? WHERE ended_at IS NULL", (_iso(_now()),))


class RateLimit:
    """At most `count` events per `window`, across the process."""

    def __init__(self, count: int, window: timedelta):
        self.count, self.window = count, window
        self._times: list[datetime] = []
        self._lock = threading.Lock()

    def allow(self, now: datetime | None = None) -> bool:
        now = now or _now()
        with self._lock:
            self._times = [t for t in self._times if now - t < self.window]
            if len(self._times) >= self.count:
                return False
            self._times.append(now)
            return True


def end_session(conn, token) -> None:
    if isinstance(token, str):
        conn.execute("UPDATE admin_sessions SET ended_at = ? WHERE token_hash = ? AND ended_at IS NULL",
                     (_iso(_now()), _hash(token)))


# ---------------------------------------------------------------- routes

def add_routes(server, app, oauth=None) -> None:
    """Register /admin, /admin/api/*, and the brain's grant page /oauth/grant with
    /oauth/api/*, on the MCP server's Starlette app. `app` is the aingram_server.AIngram
    holding settings and the current policy; `oauth` its aingram_oauth.AIngramOAuth."""
    s = app.settings
    public = urlparse(s.public_url)  # normalised by Settings: lowercase host, no default port
    origin = f"{public.scheme}://{public.netloc}"
    hosts = {public.netloc, f"127.0.0.1:{s.port}", f"localhost:{s.port}"}
    secure = public.scheme == "https"
    cookie = "__Host-aingram_admin" if secure else "aingram_admin"
    signin = SignIn(s.public_url, s.admin_address)
    grant_signin = SignIn(s.public_url, s.admin_address, path="/oauth/grant")
    drafts = admin.PolicyDrafts()
    limiter = RateLimit(PREPARE_PER_MINUTE, timedelta(minutes=1))
    pages = {path: ((STATIC_DIR / name).read_bytes(), ctype) for path, (name, ctype) in STATIC.items()}

    def reply(obj, status=200) -> JSONResponse:
        return JSONResponse(obj, status_code=status, headers={"Cache-Control": "no-store"})

    def refuse(message, status=400) -> JSONResponse:
        return reply({"error": message}, status)

    async def body_json(request: Request):
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            raise admin.Refused("expected JSON")
        raw = await request.body()
        if len(raw) > BODY_MAX:
            raise admin.Refused("request too large")
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise admin.Refused("bad JSON") from None
        if not isinstance(data, dict):
            raise admin.Refused("expected a JSON object")
        return data

    def handler(work, *, auth=True, post=False):
        """Wrap work(conn, policy, request_data) -> response with the checks every route shares."""
        async def endpoint(request: Request) -> Response:
            if request.headers.get("host", "").lower() not in hosts:
                return refuse("unknown host", 421)
            if post and request.headers.get("origin", "").lower() != origin:
                return refuse("cross-site request refused", 403)
            try:
                data = await body_json(request) if post else dict(request.query_params)
                data["_path"] = request.path_params
            except admin.Refused as e:
                return refuse(str(e))
            token = request.cookies.get(cookie)

            def run():
                with app.connect() as conn:
                    if auth and session_address(conn, token, s.admin_address) is None:
                        return refuse("sign in first", 401)
                    data["_token"] = token
                    return work(conn, app.current_policy(conn), data)
            try:
                return await anyio.to_thread.run_sync(run)
            except admin.Refused as e:
                return refuse(str(e))
            except (svc.ServiceError, PolicyError, core.AIngramError) as e:
                return refuse(str(e))
            except (UnicodeError, ValueError, RecursionError):
                return refuse("malformed request")  # e.g. lone surrogates or absurd nesting
        return endpoint

    def route(path, methods, **kw):
        def deco(work):
            server.custom_route(path, methods=methods, include_in_schema=False)(handler(work, **kw))
            return work
        return deco

    # -- page

    async def static(request: Request) -> Response:
        if request.headers.get("host", "").lower() not in hosts:
            return Response("unknown host", status_code=421)
        content, ctype = pages[request.url.path.strip("/")]
        return Response(content, media_type=ctype, headers=PAGE_HEADERS)

    for path in STATIC:
        server.custom_route(f"/{path}", methods=["GET"], include_in_schema=False)(static)

    # -- granting the brain voice to a connector (claude.ai). No session: the admin
    # wallet signs this one request, and only that signature creates a grant.

    def grant_request(conn, d):
        if oauth is None:
            raise admin.Refused("OAuth is not enabled on this server")
        sealed = d.get("r")
        about = oauth.describe(conn, sealed)
        return sealed, about, aingram_oauth.grant_statement(about)

    @route("/oauth/api/describe", ["POST"], auth=False, post=True)
    def grant_describe(conn, policy, d):
        _, about, statement = grant_request(conn, d)
        return reply({**about, "statement": statement, "server": s.public_url})

    @route("/oauth/api/challenge", ["POST"], auth=False, post=True)
    def grant_challenge(conn, policy, d):
        sealed, about, statement = grant_request(conn, d)
        return reply({"message": grant_signin.challenge(d.get("address"), request_id=about["request_id"],
                                                        statement=statement)})

    @route("/oauth/api/approve", ["POST"], auth=False, post=True)
    def grant_approve(conn, policy, d):
        sealed, about, statement = grant_request(conn, d)
        grant_signin.verify(d.get("message"), d.get("signature"), request_id=about["request_id"],
                            statement=statement)
        return reply({"redirect": oauth.approve(conn, sealed)})

    @route("/oauth/api/deny", ["POST"], auth=False, post=True)
    def grant_deny(conn, policy, d):
        sealed, _, _ = grant_request(conn, d)
        return reply({"redirect": oauth.deny(sealed)})

    # -- sign-in

    @route("/admin/api/login/challenge", ["POST"], auth=False, post=True)
    def login_challenge(conn, policy, d):
        return reply({"message": signin.challenge(d.get("address"))})

    @route("/admin/api/login/verify", ["POST"], auth=False, post=True)
    def login_verify(conn, policy, d):
        address = signin.verify(d.get("message"), d.get("signature"))
        token = open_session(conn, address)
        resp = reply({"address": to_checksum_address(address)})
        resp.set_cookie(cookie, token, max_age=int(SESSION_MAX.total_seconds()), path="/",
                        secure=secure, httponly=True, samesite="strict")
        return resp

    @route("/admin/api/logout", ["POST"], auth=False, post=True)
    def logout(conn, policy, d):
        # Signing out everywhere only takes access away, so a live session is enough for it.
        if d.get("everywhere") is True and session_address(conn, d["_token"], s.admin_address):
            end_all_sessions(conn)
        else:
            end_session(conn, d["_token"])
        resp = reply({"ok": True})
        resp.delete_cookie(cookie, path="/", secure=secure, httponly=True, samesite="strict")
        return resp

    # -- looking

    @route("/admin/api/me", ["GET"])
    def me(conn, policy, d):
        return reply({"address": to_checksum_address(s.admin_address), "server": s.server_name,
                      "mcp_url": f"{s.public_url}/mcp", "policy_problem": app.policy_problem,
                      **admin.overview(conn, policy)})

    @route("/admin/api/keys", ["GET"])
    def list_keys(conn, policy, d):
        return reply({"keys": admin.keys(conn)})

    @route("/admin/api/subjects", ["GET"])
    def list_subjects(conn, policy, d):
        return reply({"subjects": admin.subjects(conn)})

    @route("/admin/api/entries", ["GET"])
    def list_entries(conn, policy, d):
        before = d.get("before")
        if before is not None and not before.isdigit():
            raise admin.Refused("before must be a sequence number")
        return reply(admin.entries(conn, subject=d.get("subject") or None, query=d.get("query") or None,
                                   before=int(before) if before else None))

    @route("/admin/api/faded", ["GET"])
    def list_faded(conn, policy, d):
        if policy is None:
            return reply({"entries": [], "total": 0, "this_week": 0})
        return reply(admin.faded(conn, policy))

    @route("/admin/api/entries/{ref}", ["GET"])
    def get_entry(conn, policy, d):
        return reply(admin.entry(conn, d["_path"]["ref"]))

    @route("/admin/api/log", ["GET"])
    def get_log(conn, policy, d):
        return reply({"log": admin.admin_log(conn)})

    @route("/admin/api/policy", ["GET"])
    def get_policy(conn, policy, d):
        return reply(admin.policy_state(conn, s, policy))

    @route("/admin/api/policy/check", ["POST"], post=True)
    def check_policy(conn, policy, d):
        return reply(admin.policy_check(conn, d.get("body"), policy))

    @route("/admin/api/verify", ["POST"], post=True)
    def verify_chain(conn, policy, d):
        return reply({"problems": admin.verify(conn)})

    @route("/admin/api/export", ["GET"])
    def export(conn, policy, d):
        # Written inside a fresh private (0700) directory, so no other local user can read
        # it or race its name, and removed once sent or if writing fails.
        folder = tempfile.mkdtemp(prefix="aingram-export-")
        path = os.path.join(folder, "export.jsonl")
        try:
            core.export_jsonl(conn, path)
        except BaseException:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        name = f"aingram-export-{_now().strftime('%Y%m%dT%H%M%SZ')}.jsonl"
        return FileResponse(path, media_type="application/x-ndjson", filename=name,
                            headers={"Cache-Control": "no-store"},
                            background=BackgroundTask(shutil.rmtree, folder, ignore_errors=True))

    # -- changing: every one is signed by the wallet

    @route("/admin/api/actions/prepare", ["POST"], post=True)
    def prepare(conn, policy, d):
        if not limiter.allow():
            raise admin.Refused("too many commands prepared; wait a minute")
        request = {k: v for k, v in d.items() if not k.startswith("_")}
        message = admin.prepare(conn, s, policy, request, drafts)
        return reply({"message": message, "action": admin_auth.parse_message(message)["action"]})

    @route("/admin/api/actions/confirm", ["POST"], post=True)
    def confirm(conn, policy, d):
        return reply(admin.confirm(conn, s, policy, d.get("message"), d.get("signature"), drafts))
