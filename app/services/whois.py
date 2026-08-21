"""Who registered a routed destination that is not a private address.

A pushed route to ``10.0.0.0/8`` or ``10.99.0.0/23`` is self-explanatory -- it is the VPN
operator's own address space. A pushed route to ``5.20.0.0/14`` is not: nothing about the
destination itself says whether that covers one server the profile actually needs or an entire
cloud region, and if it is the latter, *everything else* hosted in that block also travels through
the tunnel, not just the service in question. ``whois`` is the cheapest way to say what is
actually in a block, so routes that are not private addresses get looked up and the registered
organisation shown next to them.

Looked up on demand, not folded into :mod:`app.services.routing`: a route list can run into the
hundreds, whois is an external TCP service (port 43) with no guaranteed latency, and firing dozens
of queries the moment the routes table loads would make the whole panel wait on the slowest one.
Callers ask for a bounded batch of destinations, resolved in parallel and capped per-lookup, and
results are cached in-process -- a public block's registration does not change between polls.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

log = logging.getLogger(__name__)

#: Fields whois responses use for "who owns this", checked in priority order across the
#: registries actually seen in practice (ARIN, RIPE, APNIC). Earlier entries are the most
#: specific -- an organisation name beats a generic net or block name.
_FIELDS = (
    "orgname",
    "org-name",
    "organization",
    "owner",
    "descr",
    "netname",
    "net-name",
)

#: Placeholder values registries put on reserved or not-yet-delegated blocks -- real, but not an
#: organisation, so showing them would be noise rather than an answer.
_NOISE = {"NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK", "IANA-NETBLOCK", "NOT DISCLOSED"}

#: One lookup must never hang the batch it is part of.
LOOKUP_TIMEOUT_SECONDS = 5.0
#: How long a resolved organisation is trusted before being asked for again.
_CACHE_TTL_SECONDS = 24 * 3600
#: A failed lookup is retried sooner -- it might be a transient whois-server hiccup.
_NEGATIVE_TTL_SECONDS = 600
#: Bounds how many TCP:43 connections one request opens at once, so a large batch does not read
#: as a burst against whatever whois server answers for it.
_MAX_WORKERS = 6
#: The most destinations one request will resolve, independent of what the caller asks for.
MAX_BATCH = 40

_lock = threading.Lock()
_cache: dict[str, tuple[float, str | None]] = {}

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class WhoisResult:
    destination: str
    org: str | None

    def to_dict(self) -> dict[str, object]:
        return {"destination": self.destination, "org": self.org}


def is_public_network(network: _Network | None) -> bool:
    """Whether a parsed network is worth a whois lookup at all.

    Excludes RFC 1918 and the rest of ``ipaddress``'s private ranges (loopback, link-local,
    CGNAT, documentation blocks) -- none of those resolve to anything a public registry knows.
    Also excludes anything wider than a /1: the redirect-gateway pair and a bare default route
    are not a registry-delegated block, they are "everything", and :mod:`app.services.scope`
    already explains what those mean.
    """
    if network is None:
        return False
    if network.is_private or network.is_multicast:
        return False
    if network.prefixlen <= 1:
        return False
    return network.is_global


def is_public(destination: str) -> bool:
    """String-destination convenience wrapper around :func:`is_public_network`."""
    return is_public_network(_network(destination))


def lookup_many(destinations: list[str], *, runner=subprocess.run) -> list[WhoisResult]:
    """Resolve a batch of destinations, in parallel, each individually capped.

    Non-public destinations are dropped silently rather than erroring -- callers pass whatever a
    routes table gave them, and filtering here means every caller gets the same rule for free.
    Duplicates collapse to one lookup.
    """
    unique = list(dict.fromkeys(d for d in destinations if is_public(d)))[:MAX_BATCH]
    if not unique:
        return []
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(unique))) as pool:
        orgs = list(pool.map(lambda d: _resolve(d, runner=runner), unique))
    return [WhoisResult(destination=d, org=org) for d, org in zip(unique, orgs, strict=True)]


def _resolve(destination: str, *, runner) -> str | None:
    hit, cached = _peek_cache(destination)
    if hit:
        return cached
    org = _query(destination, runner=runner)
    _store(destination, org)
    return org


def _query(destination: str, *, runner) -> str | None:
    network = _network(destination)
    if network is None:
        return None
    try:
        result = runner(
            ["whois", str(network.network_address)],
            capture_output=True,
            text=True,
            timeout=LOOKUP_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.info("whois lookup for %s failed: %s", destination, exc)
        return None
    if result.returncode != 0:
        return None
    return _parse(result.stdout)


def _parse(output: str) -> str | None:
    """Pick the most specific "who owns this" field out of a whois response.

    Whois output has no single schema -- ARIN, RIPE and APNIC each use different field names and
    none of them are machine-readable by design. Scanning for a fixed priority list of the field
    names actually seen in practice is good enough for a display string; it does not need to be
    exhaustive.
    """
    found: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line or line.startswith(("%", "#")):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in _FIELDS and value and value.upper() not in _NOISE and key not in found:
            found[key] = value
    for field in _FIELDS:
        if field in found:
            return found[field]
    return None


def _network(destination: str) -> _Network | None:
    if destination == "default":
        destination = "0.0.0.0/0"
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return None


def _peek_cache(destination: str) -> tuple[bool, str | None]:
    """Whether ``destination`` has a live cache entry, and its value if so.

    A resolved organisation and a confirmed miss both count as a hit -- the miss just expires
    sooner, so a whois server that is briefly unreachable does not stay wrong for a full day.
    """
    with _lock:
        entry = _cache.get(destination)
        if entry is None:
            return False, None
        stamped, org = entry
        ttl = _CACHE_TTL_SECONDS if org else _NEGATIVE_TTL_SECONDS
        if time.monotonic() - stamped > ttl:
            del _cache[destination]
            return False, None
        return True, org


def _store(destination: str, org: str | None) -> None:
    with _lock:
        _cache[destination] = (time.monotonic(), org)
