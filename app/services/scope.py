"""What actually goes through the tunnel: full, split, or nothing.

Answers the question the routes table only implies. Two things make this worth its own module
rather than a boolean somewhere:

**The redirect-gateway trap.** ``redirect-gateway`` does *not* replace the default route. It
installs ``0.0.0.0/1`` and ``128.0.0.0/1``, which together cover the whole address space at a
longer prefix than the default, so they win without touching it. Anything that decides "full
tunnel" by looking for a default route via tun therefore reports a **fully-tunnelled connection as
split**. Coverage is computed by collapsing the routed prefixes, which merges that pair back into
``0.0.0.0/0`` on its own -- and deduplicates overlapping prefixes, which a naive sum of prefix
sizes would double-count.

**IPv6.** The routes table is deliberately IPv4-only. If this machine has IPv6 egress and the
profile routes none of it, traffic leaves outside the tunnel while everything else on the page
looks healthy. That is the single most useful thing this panel says, so it is checked here even
though nothing else in the app looks at v6.

**Public ranges on a split tunnel.** A pushed prefix that is not this operator's own private
address space -- an AWS region's block, say -- does not mean "only the one service the profile
needs". Routing is prefix-based: once ``5.20.0.0/14`` is in the table, *anything* reachable in that
block goes through the tunnel too, not just whatever this VPN was actually set up to reach. That
silently narrows the "personal traffic stays direct" assumption a split tunnel is usually meant to
give, so it is counted and surfaced here rather than left for someone to notice by reading the
routes table closely. Which organisation each block belongs to is a job for
:mod:`app.services.whois`, not this module -- this only says how much of the tunnel is public
space, not who owns it, so it stays privilege-free and needs no network round trip of its own.

Like the routes table this reads the kernel, needs no privileges, and therefore works for an
``unmanaged`` tunnel as well.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from dataclasses import dataclass

from app.services.whois import is_public_network

log = logging.getLogger(__name__)

FULL = "full"
SPLIT = "split"
NONE = "none"

#: The two halves ``redirect-gateway`` installs instead of a default route, per family.
REDIRECT_PAIRS = {
    4: frozenset({"0.0.0.0/1", "128.0.0.0/1"}),
    6: frozenset({"::/1", "8000::/1"}),
}

_BITS = {4: 32, 6: 128}
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class FamilyScope:
    """What one address family does."""

    family: int
    mode: str
    coverage: float
    prefixes: int
    blocks: int
    default_via_tunnel: bool
    redirect_pair: bool
    egress_device: str | None
    #: How many of ``prefixes`` are public (registry-allocated) rather than this operator's own
    #: private address space -- see the module docstring for why that distinction matters.
    public_prefixes: int = 0
    public_blocks: int = 0
    public_coverage: float = 0.0

    @property
    def routed(self) -> bool:
        return self.mode != NONE

    def to_dict(self, *, leaking: bool = False) -> dict[str, object]:
        return {
            "family": self.family,
            "mode": self.mode,
            "coverage": round(self.coverage, 6),
            "prefixes": self.prefixes,
            "blocks": self.blocks,
            "default_via_tunnel": self.default_via_tunnel,
            "redirect_pair": self.redirect_pair,
            "egress_device": self.egress_device,
            "leaking": leaking,
            "public_prefixes": self.public_prefixes,
            "public_blocks": self.public_blocks,
            "public_coverage": round(self.public_coverage, 6),
        }


def _empty(family: int) -> FamilyScope:
    return FamilyScope(
        family=family,
        mode=NONE,
        coverage=0.0,
        prefixes=0,
        blocks=0,
        default_via_tunnel=False,
        redirect_pair=False,
        egress_device=None,
    )


@dataclass(frozen=True)
class TunnelScope:
    ipv4: FamilyScope
    ipv6: FamilyScope
    device: str

    @property
    def mode(self) -> str:
        """The headline, taken from IPv4 -- which is what the routes table shows."""
        return self.ipv4.mode

    @property
    def active(self) -> bool:
        """Whether the tunnel is carrying anything at all.

        Leaking is only a meaningful accusation while a tunnel exists. Without this, a machine
        with the tunnel simply *down* reports every family as leaking, which is not a leak -- it
        is a VPN that is off, and saying otherwise would train the operator to ignore the warning.
        """
        return self.ipv4.routed or self.ipv6.routed

    def leaking(self, family: FamilyScope) -> bool:
        """This family can leave the machine, and the running tunnel carries none of it."""
        return self.active and family.egress_device is not None and not family.routed

    @property
    def warnings(self) -> list[str]:
        """Contradictions worth interrupting the operator for. Usually empty.

        The important thing this does *not* do is treat a split tunnel with untunnelled IPv6 as a
        problem. On a work VPN that is the intended arrangement -- personal traffic goes direct,
        and IPv6 going direct alongside it is consistent. Warning there would be crying wolf on a
        correctly configured machine, and an operator who learns to dismiss this warning will
        dismiss the one below too.

        What *is* worth a warning is a contradiction: IPv4 carries everything, so the tunnel is
        evidently meant to carry everything, yet IPv6 still escapes. That is the classic leak --
        you believe you are covered and you are not.
        """
        if self.ipv4.mode != FULL or self.ipv6.mode == FULL:
            return []
        if self.ipv6.egress_device is None:
            return []
        via = self.ipv6.egress_device
        if self.ipv6.mode == NONE:
            return [
                f"IPv4 goes entirely through the VPN, but IPv6 does not go through it at all — "
                f"IPv6 traffic still leaves directly via {via}. Anything reachable over IPv6 "
                f"bypasses the VPN."
            ]
        return [
            f"IPv4 goes entirely through the VPN, but only part of IPv6 does — the rest still "
            f"leaves directly via {via}."
        ]

    @property
    def public_notice(self) -> str | None:
        """Explains what a pushed public range actually implies, on a split tunnel.

        Only worth saying on a split tunnel. On a full tunnel every address is already covered,
        public or private, so pointing out that some of it happens to be public adds nothing --
        the operator already knows everything goes through the VPN. The case worth a plain-
        language explanation is the one behind the question this exists to answer: "I'm on a
        split tunnel and public ranges came down -- does that mean traffic to anything hosted
        there goes through the VPN?" Yes, and this is where that gets said, not buried as a
        number in the coverage stats.
        """
        if self.mode != SPLIT:
            return None
        public = self.ipv4.public_prefixes
        if not public:
            return None
        plural = "network" if public == 1 else "networks"
        return (
            f"{public} of the routed {plural} — {_percent(self.ipv4.public_coverage)} of the "
            f"internet — is public address space, not this VPN operator's own. Anything else "
            f"hosted in those ranges, not just the service this VPN is meant to reach, also "
            f"travels through the tunnel. See Routes below for who they belong to."
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "device": self.device,
            "mode": self.mode,
            "active": self.active,
            "ipv4": self.ipv4.to_dict(leaking=self.leaking(self.ipv4)),
            "ipv6": self.ipv6.to_dict(leaking=self.leaking(self.ipv6)),
            "warnings": self.warnings,
            "public_notice": self.public_notice,
        }


EMPTY_SCOPE = TunnelScope(ipv4=_empty(4), ipv6=_empty(6), device="")


def _percent(fraction: float) -> str:
    """Matches the frontend's formatting: a split tunnel can carry a ten-thousandth of the
    address space, so fixed decimals would round most real answers down to "0.00%"."""
    if fraction >= 1:
        return "100%"
    if fraction <= 0:
        return "0%"
    value = fraction * 100
    return f"{value:.2f}%" if value >= 0.1 else f"{value:.2g}%"


# --- computation -----------------------------------------------------------


def coverage(networks: list[_Network], family: int) -> float:
    """The fraction of the address space these prefixes cover, 0.0 to 1.0.

    Collapsing first is what makes this correct: it merges the ``/1`` pair into a default route
    and folds overlapping prefixes together, so neither inflates the total.
    """
    if not networks:
        return 0.0
    total = sum(block.num_addresses for block in ipaddress.collapse_addresses(networks))
    return total / (2 ** _BITS[family])


def evaluate(family: int, entries: list[dict], device: str) -> FamilyScope:
    """Turn parsed ``ip route`` entries into one family's verdict."""
    networks: list[_Network] = []
    public_networks: list[_Network] = []
    destinations: set[str] = set()
    prefixes = 0
    default_via_tunnel = False
    egress_device: str | None = None

    for entry in entries:
        destination = str(entry.get("dst") or "")
        entry_device = str(entry.get("dev") or "")
        if not destination or not entry_device:
            continue

        is_default = destination == "default"
        if is_default and entry_device != device:
            # Where this family leaves the machine when the tunnel is not carrying it.
            egress_device = egress_device or entry_device

        if entry_device != device:
            continue

        network = _network(destination, family)
        if network is None:
            continue
        # Link-local and multicast are not egress; counting them would put a floor under
        # coverage for every tunnel that has them.
        if network.is_link_local or network.is_multicast:
            continue

        prefixes += 1
        destinations.add(destination)
        networks.append(network)
        if is_public_network(network):
            public_networks.append(network)
        default_via_tunnel = default_via_tunnel or is_default

    if not networks:
        return FamilyScope(
            family=family,
            mode=NONE,
            coverage=0.0,
            prefixes=0,
            blocks=0,
            default_via_tunnel=False,
            redirect_pair=False,
            egress_device=egress_device,
        )

    collapsed = list(ipaddress.collapse_addresses(networks))
    fraction = coverage(networks, family)
    return FamilyScope(
        family=family,
        # Derived from coverage rather than from spotting a default route, which is exactly
        # what makes the redirect-gateway pair come out right.
        mode=FULL if fraction >= 1.0 else SPLIT,
        coverage=fraction,
        prefixes=prefixes,
        blocks=len(collapsed),
        default_via_tunnel=default_via_tunnel,
        redirect_pair=REDIRECT_PAIRS[family] <= destinations,
        egress_device=egress_device,
        public_prefixes=len(public_networks),
        # Collapsed separately from the family total: a public block adjacent to a private one
        # must not merge across the boundary and undercount which of the two actually covers it.
        public_blocks=len(list(ipaddress.collapse_addresses(public_networks))),
        public_coverage=coverage(public_networks, family),
    )


def _network(destination: str, family: int) -> _Network | None:
    if destination == "default":
        destination = "0.0.0.0/0" if family == 4 else "::/0"
    cls = ipaddress.IPv4Network if family == 4 else ipaddress.IPv6Network
    try:
        return cls(destination, strict=False)
    except ValueError:
        return None


# --- reading the kernel ----------------------------------------------------


def _read(runner, family: int, timeout: float) -> list[dict]:
    """``ip -json -N route show``, or an empty list if it cannot be read.

    Never raises: a machine with IPv6 compiled out should report "no IPv6", not an error page.
    """
    try:
        result = runner(
            ["ip", "-json", f"-{family}", "route", "show"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not read the IPv%s routing table: %s", family, exc)
        return []
    if result.returncode != 0:
        log.info("ip -%s route exited %s", family, result.returncode)
        return []
    try:
        entries = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        log.warning("could not parse ip -%s route output: %s", family, exc)
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def read_scope(runner=subprocess.run, *, device: str = "tun0", timeout: float = 5.0) -> TunnelScope:
    """Both families' verdicts, read from the kernel."""
    return TunnelScope(
        ipv4=evaluate(4, _read(runner, 4, timeout), device),
        ipv6=evaluate(6, _read(runner, 6, timeout), device),
        device=device,
    )
