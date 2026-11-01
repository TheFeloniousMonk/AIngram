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

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
LOOPBACK = ("127.0.0.1", "localhost", "::1")


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
        return cls(
            db_path=_get(env, "AINGRAM_DB", True),
            policy_path=_get(env, "AINGRAM_POLICY", False, "policy.yaml"),
            server_name=_get(env, "AINGRAM_SERVER_NAME", need_admin or need_server),
            admin_address=address,
            host=_get(env, "AINGRAM_HOST", False, "127.0.0.1"),
            port=int(port),
            public_url=public_url,
        )
