"""Deployment settings, read from the environment.

Nothing deployment-specific lives in the code or in committed files. Values
come from the process environment, or from a .env file (see .env.example).
A variable already set in the environment wins over the .env file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# The release, as in the git tag v<VERSION>. Bump it with a CHANGELOG.md entry.
VERSION = "2.0.0"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
# The first draft the admin page offers before any policy is approved.
DEFAULT_POLICY = Path(__file__).with_name("policy.example.yaml")
# OAuth clients may only register these exact redirect URIs: Claude's connector
# callback (Anthropic has said it may move from claude.ai to claude.com). Any
# other site registering itself to fish for a grant is refused at registration.
DEFAULT_OAUTH_REDIRECTS = ("https://claude.ai/api/mcp/auth_callback",
                           "https://claude.com/api/mcp/auth_callback")


class ConfigError(Exception):
    pass


def load_env(path: str | os.PathLike | None = None) -> None:
    """Load a .env file into os.environ without overriding what is already set."""
    path = Path(path or os.environ.get("AINGRAM_ENV_FILE", ".env"))
    if not path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - python-dotenv is in requirements.txt
        raise ConfigError(f"{path} exists but python-dotenv is not installed") from None
    load_dotenv(path, override=False)


def _get(env, name: str, required: bool, default: str | None = None) -> str | None:
    value = env.get(name, "").strip()
    if value:
        return value
    if required and default is None:
        raise ConfigError(f"{name} is not set (see .env.example)")
    return default


@dataclass(frozen=True)
class Settings:
    db_path: str
    policy_path: str
    server_name: str | None
    admin_address: str | None
    host: str
    port: int
    public_url: str | None
    oauth_redirect_uris: tuple[str, ...] = ()

    @property
    def loopback_bind(self) -> bool:
        return self.host in LOOPBACK

    @classmethod
    def from_env(cls, env=None, *, need_admin: bool = False, need_server: bool = False) -> "Settings":
        env = os.environ if env is None else env
        address = _get(env, "AINGRAM_ADMIN_ADDRESS", need_admin or need_server)
        if address is not None and not ADDRESS_RE.match(address):
            raise ConfigError("AINGRAM_ADMIN_ADDRESS must be a 0x-prefixed 20-byte hex address")
        port = _get(env, "AINGRAM_PORT", False, "8787")
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ConfigError("AINGRAM_PORT must be a TCP port number")
        public_url = _get(env, "AINGRAM_PUBLIC_URL", need_server)
        if public_url is not None:
            public_url = public_url.rstrip("/")
            parsed = urlparse(public_url)
            if (not parsed.hostname or parsed.path or parsed.query or parsed.fragment
                    or parsed.username or parsed.password):
                raise ConfigError("AINGRAM_PUBLIC_URL must be a bare origin such as https://host")
            if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in LOOPBACK):
                raise ConfigError("AINGRAM_PUBLIC_URL must be https:// (plain http only for localhost)")
            # Normalise to what browsers send as Origin: lowercase host, no default port.
            try:
                url_port = parsed.port
            except ValueError:
                raise ConfigError("AINGRAM_PUBLIC_URL has an invalid port") from None
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            default = {"https": 443, "http": 80}[parsed.scheme]
            public_url = f"{parsed.scheme}://{host}" + (f":{url_port}" if url_port not in (None, default) else "")
        # Bound into every signed admin command. Defaults to the public hostname.
        server_name = _get(env, "AINGRAM_SERVER_NAME", False)
        if server_name is None and public_url is not None:
            server_name = urlparse(public_url).netloc
        if server_name is None and (need_admin or need_server):
            raise ConfigError("AINGRAM_SERVER_NAME or AINGRAM_PUBLIC_URL must be set (see .env.example)")
        redirects = tuple(u.strip() for u in _get(env, "AINGRAM_OAUTH_REDIRECT_URIS", False,
                                                  ",".join(DEFAULT_OAUTH_REDIRECTS)).split(",") if u.strip())
        for uri in redirects:
            p = urlparse(uri)
            if not p.hostname or p.fragment or not (
                    p.scheme == "https" or (p.scheme == "http" and p.hostname in LOOPBACK)):
                raise ConfigError(f"AINGRAM_OAUTH_REDIRECT_URIS: {uri!r} must be an https URL")
        return cls(
            db_path=_get(env, "AINGRAM_DB", True),
            policy_path=_get(env, "AINGRAM_POLICY", False, str(DEFAULT_POLICY)),
            server_name=server_name,
            admin_address=address,
            host=_get(env, "AINGRAM_HOST", False, "127.0.0.1"),
            port=int(port),
            public_url=public_url,
            oauth_redirect_uris=redirects,
        )
