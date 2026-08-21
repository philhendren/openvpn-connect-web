"""Which source addresses may reach the panel at all.

The gate that uses this runs before authentication, before CSRF and before the session is
touched, so an address that is not on the list never reaches a route. Zero I/O -- the policy is a
parsed list of networks and a membership test, so it is testable without a socket.

**Why this is not a private-vs-public test.** Binding to 0.0.0.0 on this machine means listening
on every interface, and while the tunnel is up that includes ``tun0`` -- so the network at the far
end of the VPN can reach the control panel. ``tun0`` addresses are RFC1918 (the operator's is
172.27.246.54/23), exactly like the LAN, so :func:`app.services.whois.is_public_network` and any
other "is this private?" heuristic would happily let the concentrator in. The only thing that
separates "my LAN" from "the corporate network I am tunnelled into" is naming the CIDRs, which is
why this module takes an explicit list and nothing else.

Membership is always tested against the real socket peer. No forwarded header is consulted --
``X-Forwarded-For`` is attacker-controlled unless a proxy is known to be in front, and a header
that could unlock the gate would defeat the point of having it.

:func:`client_address` answers a *different* question -- "who should this request be attributed
to?" -- for the login throttle, and that one does read the header, but only from a peer named in
``VPN_CONNECT_TRUSTED_PROXIES``. The two must not be collapsed into one value (which is what
Werkzeug's ProxyFix would do, by rewriting ``REMOTE_ADDR`` for everything): the gate needs the
address that cannot be forged, the throttle needs the address that identifies a person.
"""

from __future__ import annotations

import ipaddress

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network

#: What an unset ``VPN_CONNECT_ALLOW_FROM`` means: this machine and nothing else.
#:
#: Fail closed. An empty setting cannot mean "allow everything", because the setting is absent on
#: exactly two occasions -- a fresh install, and an existing install upgraded to a version that
#: has this gate -- and in both the safe reading is the narrow one. The cost is that widening
#: BIND without also setting this locks you out of the LAN UI, which the 403 body explains and a
#: re-run of deploy/install.sh fixes.
LOOPBACK_ONLY: tuple[_Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class AccessError(ValueError):
    """Raised for an allowlist the app refuses to start with."""


def parse_networks(
    raw: str | None, setting: str = "VPN_CONNECT_ALLOW_FROM"
) -> tuple[_Network, ...]:
    """Parse a comma-separated list of addresses and CIDRs. Empty in, empty out.

    Accepts bare addresses (``100.119.222.51`` becomes a /32) and CIDRs with host bits set
    (``192.168.4.46/22`` becomes 192.168.4.0/22), because the useful thing to paste is whatever
    ``ip addr`` just printed, not the network address you worked out by hand.

    A malformed entry raises rather than being skipped. Silently dropping one entry from a list
    of three either locks someone out or -- worse, if the dropped entry was the narrow one --
    leaves a wider list in force than the file says. A startup failure naming the bad token is
    the only outcome that cannot be misread.
    """
    if raw is None or not raw.strip():
        return ()
    networks: list[_Network] = []
    for token in raw.split(","):
        entry = token.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise AccessError(f"{entry!r} is not a valid address or CIDR in {setting}.") from exc
    return tuple(networks)


def parse_allow_from(raw: str | None) -> tuple[_Network, ...]:
    """The allowlist, which falls back to loopback rather than to nothing.

    The empty case is the whole difference between this and :func:`parse_networks`: an empty
    allowlist would mean "refuse everything", which is never what an unset variable was meant to
    say, whereas an empty *proxy* list correctly means "believe no forwarded headers".
    """
    return parse_networks(raw, "VPN_CONNECT_ALLOW_FROM") or LOOPBACK_ONLY


def _parse(address_text: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An address, or None if it is not one. Never raises."""
    if not address_text:
        return None
    try:
        address = ipaddress.ip_address(address_text.strip())
    except ValueError:
        return None
    # A dual-stack listener reports an IPv4 client as ::ffff:192.168.4.46, which matches no IPv4
    # network. Compare the address the operator actually wrote down.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_allowed(remote_addr: str | None, networks: tuple[_Network, ...]) -> bool:
    """Whether this socket peer is on the list.

    Anything unparseable is denied. ``remote_addr`` is absent or malformed only when the request
    did not arrive over a normal socket, and there is no reading of that which should open the
    panel.
    """
    address = _parse(remote_addr)
    if address is None:
        return False
    # A version mismatch is False rather than an error in ipaddress, so mixing v4 and v6 entries
    # in one list needs no special handling here.
    return any(address in network for network in networks)


#: How far back along an X-Forwarded-For chain to look before giving up. Nobody legitimately runs
#: twenty reverse proxies; the cap just stops a long header turning into pointless work.
MAX_FORWARDED_HOPS = 20


def client_address(
    remote_addr: str | None,
    forwarded_for: str | None,
    proxies: tuple[_Network, ...],
) -> str:
    """Who to attribute this request to, for the login throttle and its log line.

    Returns the socket peer unless a trusted proxy sent it, in which case the client it names is
    used instead. With ``proxies`` empty -- the default -- this is exactly ``remote_addr`` and no
    header is read at all.

    **The rightmost entry wins, not the leftmost.** A proxy *appends* to ``X-Forwarded-For``, so
    on ``1.2.3.4, 100.119.222.51`` the left half is whatever the client chose to send and only
    the right half was observed by our own proxy. Reading left to right is the classic way to let
    an attacker pick their own throttle bucket -- and therefore never hit the lockout.
    """
    if not proxies or not is_allowed(remote_addr, proxies):
        return remote_addr or "unknown"
    hops = [hop.strip() for hop in (forwarded_for or "").split(",")]
    for hop in reversed(hops[-MAX_FORWARDED_HOPS:]):
        if not hop:
            continue
        if is_allowed(hop, proxies):
            continue  # another hop of our own infrastructure; keep walking left
        parsed = _parse(hop)
        if parsed is None:
            # Garbage in the chain. Everything further left came through it, so stop believing
            # the header entirely rather than reaching past the bad entry for a nicer answer.
            return remote_addr or "unknown"
        return str(parsed)
    return remote_addr or "unknown"


def describe(networks: tuple[_Network, ...]) -> str:
    """The allowlist as it should appear in a log line."""
    return ", ".join(str(network) for network in networks)
