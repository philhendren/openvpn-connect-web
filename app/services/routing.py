"""Reads the routes OpenVPN installed for the client.

The kernel routing table is used deliberately, rather than the server's ``PUSH_REPLY``: the push
says what was *offered*, ``ip route`` says what was actually installed. They differ whenever a
route is rejected, overridden by a local one, or added by an up hook. Reading the kernel also
means this works for an ``unmanaged`` tunnel -- one started by scripts/vpn-connect.sh, where there
is no management connection to ask.

``ip route`` needs no privileges, so this stays outside the root helper.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from dataclasses import dataclass

from app.services.whois import is_public_network

log = logging.getLogger(__name__)

#: A route sending traffic into the tunnel (``via <vpn gateway> dev tun0``).
TUNNEL = "tunnel"
#: The tunnel's own subnet, attached to the device by the kernel rather than pushed.
ON_LINK = "on-link"
#: The host route to the concentrator itself, pinned to the physical interface so the tunnel's
#: own packets do not try to travel through the tunnel.
BYPASS = "bypass"

_KIND_ORDER = {TUNNEL: 0, ON_LINK: 1, BYPASS: 2}


@dataclass(frozen=True)
class Route:
    """One row of the routing table, as the UI wants to show it."""

    destination: str
    gateway: str | None
    device: str
    metric: int | None
    kind: str = TUNNEL

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        return _network(self.destination)

    @property
    def addresses(self) -> int | None:
        """How many addresses the prefix covers -- the useful measure of a split tunnel."""
        network = self.network
        return network.num_addresses if network else None

    @property
    def public(self) -> bool:
        """Whether this is a registry-allocated public block rather than a private range.

        Drives whether the UI offers a whois lookup for the row: RFC 1918 and the rest of the
        private ranges never resolve to anything a registry knows about, so there is nothing
        useful to look up.
        """
        return is_public_network(self.network)

    def to_dict(self) -> dict[str, object]:
        return {
            "destination": self.destination,
            "gateway": self.gateway,
            "device": self.device,
            "metric": self.metric,
            "kind": self.kind,
            "addresses": self.addresses,
            "public": self.public,
        }


def read_routes(
    runner=subprocess.run,
    *,
    device: str = "tun0",
    remote_ip: str | None = None,
    timeout: float = 5.0,
) -> list[Route]:
    """Return the routes belonging to ``device``, plus the concentrator's bypass route.

    Returns an empty list rather than raising if ``ip`` is missing or the device is down --
    callers render "no routes", which is the honest answer for a tunnel that is not up.
    """
    try:
        result = runner(
            ["ip", "-json", "-4", "route", "show"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not read the routing table: %s", exc)
        return []
    if result.returncode != 0:
        log.warning("ip route exited %s: %s", result.returncode, (result.stderr or "").strip())
        return []
    return parse_routes(result.stdout, device=device, remote_ip=remote_ip)


def parse_routes(
    payload: str, *, device: str = "tun0", remote_ip: str | None = None
) -> list[Route]:
    """Turn ``ip -json route show`` output into sorted :class:`Route` objects."""
    try:
        entries = json.loads(payload or "[]")
    except json.JSONDecodeError as exc:
        log.warning("could not parse ip route output: %s", exc)
        return []
    if not isinstance(entries, list):
        return []

    routes: list[Route] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        destination = str(entry.get("dst") or "")
        entry_device = str(entry.get("dev") or "")
        gateway = entry.get("gateway")
        if not destination or not entry_device:
            continue

        if entry_device == device:
            kind = TUNNEL if gateway else ON_LINK
        elif remote_ip and destination == remote_ip:
            # The host route openvpn pins to the physical interface for its own traffic.
            kind = BYPASS
        else:
            continue

        metric = entry.get("metric")
        routes.append(
            Route(
                destination=destination,
                gateway=str(gateway) if gateway else None,
                device=entry_device,
                metric=int(metric) if isinstance(metric, int) else None,
                kind=kind,
            )
        )
    return sorted(routes, key=_sort_key)


def _sort_key(route: Route) -> tuple[int, int, int]:
    network = route.network
    if network is None:
        return (_KIND_ORDER.get(route.kind, 9), 0, 0)
    return (_KIND_ORDER.get(route.kind, 9), int(network.network_address), network.prefixlen)


def _network(destination: str) -> ipaddress.IPv4Network | None:
    if destination == "default":
        destination = "0.0.0.0/0"
    try:
        return ipaddress.IPv4Network(destination, strict=False)
    except ValueError:
        return None
