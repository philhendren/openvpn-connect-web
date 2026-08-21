"""Configuration objects, driven entirely by ``VPN_CONNECT_*`` environment variables."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "VPN_CONNECT_"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_path(name: str, default: Path) -> Path:
    raw = _env(name)
    return Path(raw).expanduser() if raw else default


def _env_optional_path(name: str) -> Path | None:
    raw = _env(name)
    return Path(raw).expanduser() if raw else None


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    """Everything the app needs to know about this machine's OpenVPN setup."""

    # --- Flask -----------------------------------------------------------
    SECRET_KEY: str = field(default_factory=lambda: _env("SECRET_KEY") or secrets.token_hex(32))
    #: scrypt/pbkdf2 hash produced by ``flask --app app set-password``.
    PASSWORD_HASH: str = field(default_factory=lambda: _env("PASSWORD_HASH"))
    SESSION_HOURS: int = field(default_factory=lambda: _env_int("SESSION_HOURS", 12))
    #: Only enable when served over TLS -- a plain-HTTP LAN deployment must leave this off.
    SESSION_COOKIE_SECURE: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))
    #: Comma-separated CIDRs allowed to reach the panel at all, tested against the real socket
    #: peer before anything else happens. Empty means loopback only -- see app/services/access.py
    #: for why an unset value cannot safely mean "everything", and why this is an explicit list
    #: rather than a private-vs-public test.
    ALLOW_FROM: str = field(default_factory=lambda: _env("ALLOW_FROM"))
    #: Comma-separated CIDRs of reverse proxies whose ``X-Forwarded-For`` may be believed, and
    #: only for attributing a request to a client -- never for the allowlist above. Empty means
    #: no header is read at all, so a direct install behaves exactly as if this did not exist.
    #: Set it to 127.0.0.0/8 when something like `tailscale serve` fronts the app on loopback.
    TRUSTED_PROXIES: str = field(default_factory=lambda: _env("TRUSTED_PROXIES"))
    LOGIN_MAX_ATTEMPTS: int = field(default_factory=lambda: _env_int("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_LOCKOUT_SECONDS: int = field(
        default_factory=lambda: _env_int("LOGIN_LOCKOUT_SECONDS", 300)
    )

    # --- OpenVPN ---------------------------------------------------------
    VPN_DIR: Path = field(default_factory=lambda: _env_path("VPN_DIR", Path.home() / ".vpn"))
    HELPER: Path = field(
        default_factory=lambda: _env_path("HELPER", Path("/usr/local/sbin/vpn-connect-helper"))
    )
    MGMT_SOCKET: Path = field(
        default_factory=lambda: _env_path("MGMT_SOCKET", Path("/run/vpn-connect/mgmt.sock"))
    )
    #: The tunnel interface openvpn brings up; also the device whose routes the UI lists.
    TUN_DEVICE: str = field(default_factory=lambda: _env("TUN_DEVICE", "tun0"))
    #: Challenge prompt text; must match what the concentrator expects to display.
    STATIC_CHALLENGE: str = field(
        default_factory=lambda: _env("STATIC_CHALLENGE", "Enter Authenticator Code")
    )
    #: Seconds to wait for the management socket to appear after launching openvpn.
    SOCKET_WAIT_SECONDS: float = field(default_factory=lambda: float(_env_int("SOCKET_WAIT", 15)))
    #: Seconds to wait for CONNECTED after submitting credentials.
    CONNECT_TIMEOUT_SECONDS: float = field(
        default_factory=lambda: float(_env_int("CONNECT_TIMEOUT", 90))
    )
    #: Seconds allowed for any single helper subprocess call.
    COMMAND_TIMEOUT_SECONDS: float = field(
        default_factory=lambda: float(_env_int("CMD_TIMEOUT", 20))
    )
    #: Interval for the management interface's asynchronous byte counters.
    BYTECOUNT_INTERVAL: int = field(default_factory=lambda: _env_int("BYTECOUNT_INTERVAL", 5))

    # --- DNS ---------------------------------------------------------------
    #: The hand-maintained file the DNS panel offers to import from, then retires. Unset by
    #: default -- not every install has one -- so set explicitly, e.g.
    #: VPN_CONNECT_DNS_LEGACY_CONF=/etc/dnsmasq.d/examplecorp.conf.
    DNS_LEGACY_CONF: Path | None = field(
        default_factory=lambda: _env_optional_path("DNS_LEGACY_CONF")
    )

    # --- notifications ---------------------------------------------------
    #: ntfy server. Configurable so a self-hosted instance works as well as ntfy.sh.
    NTFY_SERVER: str = field(default_factory=lambda: _env("NTFY_SERVER", "https://ntfy.sh"))
    #: Seconds allowed for a single notification POST. Short on purpose -- a slow push must not
    #: keep a worker thread alive behind a tunnel that has already changed state.
    NOTIFY_TIMEOUT_SECONDS: float = field(
        default_factory=lambda: float(_env_int("NOTIFY_TIMEOUT", 5))
    )

    @property
    def database(self) -> Path:
        """Everything configurable lives here: connections, settings and history."""
        return _env_path("DATABASE", self.VPN_DIR / "vpn-connect.db")

    @property
    def pid_file(self) -> Path:
        return _env_path("PID_FILE", self.VPN_DIR / "openvpn.pid")

    @property
    def env_file(self) -> Path:
        """The environment file systemd loads. Read only to check it for damage.

        Its contents are never parsed for settings here -- systemd has already done that, and
        this process sees the result. See app/services/deploy.py.
        """
        return _env_path("ENV_FILE", self.VPN_DIR / "webapp.env")

    @property
    def dns_staging(self) -> Path:
        """Where the app writes rendered dnsmasq rules for the root helper to pick up.

        Never passed to the helper over argv -- the helper reads this one fixed, name-resolved
        path itself, the same way it resolves a connection's .ovpn from a name rather than
        accepting a path.
        """
        return _env_path("DNS_STAGING", self.VPN_DIR / "dns-staged.conf")


def load_config() -> dict[str, object]:
    """Return the Config as a mapping suitable for ``app.config.from_mapping``."""
    cfg = Config()
    return {
        "APP_CONFIG": cfg,
        "SECRET_KEY": cfg.SECRET_KEY,
        "SESSION_COOKIE_SECURE": cfg.SESSION_COOKIE_SECURE,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
    }
