"""Compares what the concentrator *pushed* against what actually reached the kernel.

:mod:`app.services.routing` reads the routing table because that is the ground truth: it says
what the tunnel is carrying right now. But it can only report what is *there*, and the failure
that sends people hunting is the opposite one -- the server pushed a subnet, the client declined
it, the tunnel comes up looking perfectly healthy, and one internal range is unreachable with no
error anywhere a user would look.

The push arrives on the management log as one line::

    PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,route-gateway ...'

Parsing it is pure string work and the comparison is pure set work, so all of it lives here with
no subprocess and no I/O. Two things it deliberately refuses to do:

* **Guess when it has not seen the push.** The management log is a bounded buffer, and a tunnel
  that has been up for weeks may have pushed its reply well outside it. ``seen=False`` produces
  an empty report, never "everything was rejected" -- the controller keeps the PUSH_REPLY line
  aside precisely so this stays rare, but a report that lies once is worse than one that is
  occasionally silent.
* **Diff against an empty routing table.** No routes at all means the tunnel is down or going
  down, not that every pushed route was refused.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

#: What ``redirect-gateway`` asks for: everything.
EVERYTHING = ipaddress.IPv4Network("0.0.0.0/0")
#: What ``redirect-gateway def1`` actually installs -- two halves that beat an existing default
#: route on specificity without deleting it, so the original is still there when the tunnel drops.
HALVES = (ipaddress.IPv4Network("0.0.0.0/1"), ipaddress.IPv4Network("128.0.0.0/1"))

_PUSH_REPLY = re.compile(r"PUSH_REPLY,(.*)", re.IGNORECASE)

#: Lines where OpenVPN itself explains a route it could not install. Shown verbatim rather than
#: paraphrased: they are the client's own words, and the next thing anyone does with a route
#: problem is search for exactly this text.
_TROUBLE = (
    "route add command failed",
    "needs a gateway parameter",
    "cannot read current default gateway",
    "route-nopull",
    "unable to redirect",
)


@dataclass(frozen=True)
class PushedRoute:
    """One routing option out of the PUSH_REPLY, as the UI wants to show it."""

    option: str
    """The pushed option, verbatim -- what to show when asked 'pushed as what, exactly?'."""

    destination: str
    """The prefix in CIDR form, or the raw option when it could not be read as one."""

    gateway: str | None = None
    metric: int | None = None
    catch_all: bool = False
    """``redirect-gateway``: a directive rather than a prefix, and matched differently."""

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        try:
            return ipaddress.IPv4Network(self.destination, strict=False)
        except ValueError:
            return None

    @property
    def readable(self) -> bool:
        """Whether this parsed into a prefix at all.

        An unreadable option is worth showing rather than dropping: OpenVPN will not have
        installed it either, and the malformed text is the answer.
        """
        return self.catch_all or self.network is not None

    @property
    def addresses(self) -> int | None:
        network = self.network
        return network.num_addresses if network else None

    def to_dict(self) -> dict[str, object]:
        return {
            "option": self.option,
            "destination": self.destination,
            "gateway": self.gateway,
            "metric": self.metric,
            "catch_all": self.catch_all,
            "readable": self.readable,
            "addresses": self.addresses,
        }


@dataclass(frozen=True)
class PushReport:
    """What was asked for, and what of it is missing."""

    seen: bool = False
    """Whether a PUSH_REPLY was available to read. Everything else is meaningless without it."""

    pushed: tuple[PushedRoute, ...] = ()
    rejected: tuple[PushedRoute, ...] = ()
    notes: tuple[str, ...] = ()
    """OpenVPN's own log lines about routes it could not install."""

    @property
    def wholesale(self) -> bool:
        """Every pushed route is missing -- one cause, not several.

        Worth telling apart: a single absent prefix is usually that one route failing, while
        *all* of them means the routes were never pulled (``--route-nopull``) or the push never
        got applied at all. The wording differs, so the distinction is made here.
        """
        return bool(self.pushed) and len(self.rejected) == len(self.pushed)

    def to_dict(self) -> dict[str, object]:
        return {
            "seen": self.seen,
            "count": len(self.pushed),
            "wholesale": self.wholesale,
            "rejected": [route.to_dict() for route in self.rejected],
            "notes": list(self.notes),
        }


#: Returned whenever there is nothing to say, so callers never branch on ``None``.
NOTHING_PUSHED = PushReport()


def find_reply(log_lines) -> str | None:
    """The most recent PUSH_REPLY line in ``log_lines``, if one is still in there.

    Newest wins: a reconnect on the same controller pushes again, and the older reply describes
    a tunnel that no longer exists.
    """
    for line in reversed(list(log_lines)):
        if "PUSH_REPLY" in line:
            return line
    return None


def parse(reply: str | None) -> list[PushedRoute]:
    """Pull the routing options out of one PUSH_REPLY line.

    Only ``route`` and ``redirect-gateway`` are read. ``route-ipv6`` is deliberately skipped:
    the comparison is against the IPv4 table, and a v6 prefix diffed against v4 routes would be
    reported as rejected every single time.
    """
    if not reply:
        return []
    match = _PUSH_REPLY.search(reply)
    if not match:
        return []

    routes: list[PushedRoute] = []
    seen: set[str] = set()
    for raw in match.group(1).split(","):
        option = raw.strip().strip("'\"").strip()
        if not option or option in seen:
            continue
        verb, _, rest = option.partition(" ")
        verb = verb.lower()
        if verb == "route":
            seen.add(option)
            routes.append(_route(option, rest.split()))
        elif verb == "redirect-gateway":
            seen.add(option)
            routes.append(PushedRoute(option=option, destination="default", catch_all=True))
    return routes


def _route(option: str, args: list[str]) -> PushedRoute:
    """``route <network> [netmask] [gateway] [metric]``, all but the first optional.

    An option that will not parse comes back with the raw text as its destination rather than
    being dropped. OpenVPN did not install it either, and the malformed text *is* the answer.
    """
    if not args:
        return PushedRoute(option=option, destination=option)

    destination = _cidr(args[0], args[1] if len(args) > 1 else "255.255.255.255")
    if destination is None:
        return PushedRoute(option=option, destination=option)

    # Left as written: OpenVPN resolves the symbolic names (``vpn_gateway``, ``net_gateway``,
    # ``remote_host``) itself, and showing the operator the word the server actually sent is
    # more use than showing the address it happened to mean.
    gateway = args[2] if len(args) > 2 else None
    metric = int(args[3]) if len(args) > 3 and args[3].isdigit() else None
    return PushedRoute(option=option, destination=destination, gateway=gateway, metric=metric)


def _cidr(network: str, netmask: str) -> str | None:
    spec = network if "/" in network else f"{network}/{netmask}"
    try:
        return str(ipaddress.IPv4Network(spec, strict=False))
    except ValueError:
        return None


def report(reply: str | None, installed, log_lines=()) -> PushReport:
    """Diff the push against the kernel, and say nothing when there is nothing to compare.

    ``installed`` is whatever :func:`app.services.routing.read_routes` returned -- the routes on
    the tunnel device. An empty list is treated as "no answer", not "all rejected".
    """
    if not reply:
        return NOTHING_PUSHED

    pushed = parse(reply)
    if not installed:
        return PushReport(seen=True, pushed=tuple(pushed))

    present = {route.network for route in installed if route.network is not None}
    rejected = tuple(route for route in pushed if not _installed(route, present))
    return PushReport(
        seen=True,
        pushed=tuple(pushed),
        rejected=tuple(sorted(rejected, key=_sort_key)),
        notes=tuple(_notes(log_lines)) if rejected else (),
    )


def _installed(route: PushedRoute, present: set) -> bool:
    if route.catch_all:
        # ``def1`` is the usual form and installs the two halves instead of a default route, so
        # either shape counts: the tunnel is carrying everything in both cases.
        return EVERYTHING in present or all(half in present for half in HALVES)
    network = route.network
    return network is not None and network in present


def _sort_key(route: PushedRoute) -> tuple[int, int, int]:
    network = route.network
    if network is None:
        return (1, 0, 0)
    return (0, int(network.network_address), network.prefixlen)


def _notes(log_lines) -> list[str]:
    notes: list[str] = []
    for line in log_lines:
        lowered = line.lower()
        if any(needle in lowered for needle in _TROUBLE) and line not in notes:
            notes.append(line)
    return notes[-5:]
