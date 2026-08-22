"""Which OpenVPN client this machine actually has, looked up once when the app starts.

Two different programs answer to "OpenVPN" on Linux, and they are not interchangeable:

* **The classic client** (`openvpn`, the 2.x line) is what this panel drives. It takes a config
  file on the command line and exposes a *management interface* -- a socket that reports state,
  byte counters and log lines, asks for credentials, and accepts a shutdown signal. Every live
  thing this app shows comes through it, which is why the whole design assumes it.
* **OpenVPN 3 Linux** (`openvpn3`) is a separate implementation with a D-Bus service behind a
  `openvpn3 session-*` command line. It has **no management interface at all**, so a panel built
  on one cannot drive it by swapping a binary path -- the events it is built out of do not exist
  over there. Supporting it means a second backend that polls the D-Bus API instead.

So this module does not choose between them. It answers "what is installed?" honestly and once,
so that a machine with only `openvpn3` gets told exactly that, in the UI, instead of discovering
it as a puzzle at the first connect.

Lookups only: no subprocess, nothing executed, nothing that can fail slowly. That is what makes
it safe to do while the app is still starting up.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

#: The classic client lives in `sbin`, and a Flask process started from a login shell frequently
#: has no `sbin` on its PATH while the systemd unit does. Searching these as well means the
#: answer does not depend on how the app happened to be started.
FALLBACK_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin", "/usr/local/bin")

CLASSIC = "openvpn"
V3 = "openvpn3"


@dataclass(frozen=True)
class Clients:
    """What was found on this machine. Either path may be ``None``; both often are not."""

    classic: str | None
    v3: str | None

    @property
    def supported(self) -> bool:
        """Can this panel drive what is installed?"""
        return self.classic is not None

    @property
    def v3_only(self) -> bool:
        """The case worth a specific message rather than a generic "not found"."""
        return self.classic is None and self.v3 is not None

    @property
    def summary(self) -> str:
        """One line, for the startup log."""
        if self.classic and self.v3:
            return f"{self.classic} (classic, in use), {self.v3} (OpenVPN 3, not used)"
        if self.classic:
            return f"{self.classic} (classic)"
        if self.v3:
            return f"{self.v3} (OpenVPN 3 only -- this panel cannot drive it)"
        return "none found"

    def to_dict(self) -> dict[str, object]:
        return {
            "classic": self.classic,
            "v3": self.v3,
            "supported": self.supported,
        }


def _find(name: str, which) -> str | None:
    return which(name) or which(name, path=":".join(FALLBACK_DIRS))


def discover(*, which=shutil.which) -> Clients:
    """Look for both clients. Injectable, so a test never depends on the machine running it."""
    return Clients(classic=_find(CLASSIC, which), v3=_find(V3, which))
