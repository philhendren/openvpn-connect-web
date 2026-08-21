"""DNS split-config policy: what a domain-scoped forwarder or fallback server may contain, and
the exact dnsmasq syntax a saved rule set renders to.

Persistence lives in :mod:`app.services.store`; this module holds only the grammar and a pure
render function, so the text written to ``/etc/dnsmasq.d/vpn-connect.conf`` has one home and is
testable with zero I/O.

Deliberately excludes dnsmasq's ``address=/domain/IP`` form (return this IP, no forwarding) --
nothing here needs it, and it would double the grammar surface for no current use case.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

#: Dot-separated labels, 1-63 chars each, no leading/trailing hyphen per label. The '/' character
#: is excluded outright rather than escaped: dnsmasq's own `/domain/` slot treats a stray '/' as
#: ending the domain early, so a value containing one must never reach render_dnsmasq() at all.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
DOMAIN = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
MAX_DOMAIN_LENGTH = 253


class DnsError(ValueError):
    """Raised for a rule the app refuses to save."""


def validate_domain(value: str) -> str:
    """Return the cleaned domain, or raise."""
    domain = (value or "").strip().rstrip(".").lower()
    if not domain or len(domain) > MAX_DOMAIN_LENGTH or not DOMAIN.match(domain):
        raise DnsError(
            "A domain may only contain letters, digits, '-' and '.', up to "
            f"{MAX_DOMAIN_LENGTH} characters, with no leading or trailing hyphen in a label."
        )
    return domain


def validate_address(value: str) -> str:
    """Return the cleaned IPv4 or IPv6 literal, or raise."""
    address = (value or "").strip()
    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise DnsError(f"{value!r} is not a valid IPv4 or IPv6 address.") from exc
    return address


@dataclass(frozen=True)
class ParsedRule:
    """One line successfully classified out of an existing dnsmasq config file."""

    kind: str  # "domain" | "fallback"
    domain: str | None
    address: str


def render_dnsmasq(domain_rules, fallback_rules) -> str:
    """The exact text written to ``/etc/dnsmasq.d/vpn-connect.conf``.

    Domain rows render alphabetically -- dnsmasq matches them by specificity regardless of file
    order, so alphabetical is just the stable, diffable choice. Fallback rows render in
    ``position`` order, since dnsmasq tries bare ``server=`` lines in the order they appear for a
    query that matches no domain.
    """
    lines = [
        "# Managed by vpn-connect. Do not edit -- changes here are overwritten on the next save."
    ]
    for rule in sorted(domain_rules, key=lambda r: r.domain or ""):
        lines.append(f"server=/{rule.domain}/{rule.address}")
    for rule in sorted(fallback_rules, key=lambda r: r.position or 0):
        lines.append(f"server={rule.address}")
    return "\n".join(lines) + "\n"


#: Matches the two shapes render_dnsmasq() ever produces, for parsing an existing file back.
_DOMAIN_LINE = re.compile(r"^server=/(?P<domain>[^/]+)/(?P<address>.+)$")
_FALLBACK_LINE = re.compile(r"^server=(?P<address>[^/]+)$")


def parse_dnsmasq(text: str) -> tuple[list[ParsedRule], list[str]]:
    """Best-effort parse of an existing dnsmasq config, for the legacy-import preview.

    Never raises: a line this cannot classify is returned in the second list rather than dropped
    silently or turned into a 500, so the operator sees exactly what would not be imported.
    """
    parsed: list[ParsedRule] = []
    unparsed: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain_match = _DOMAIN_LINE.match(line)
        if domain_match:
            try:
                domain = validate_domain(domain_match.group("domain"))
                address = validate_address(domain_match.group("address"))
            except DnsError:
                unparsed.append(raw)
                continue
            parsed.append(ParsedRule(kind="domain", domain=domain, address=address))
            continue
        fallback_match = _FALLBACK_LINE.match(line)
        if fallback_match:
            try:
                address = validate_address(fallback_match.group("address"))
            except DnsError:
                unparsed.append(raw)
                continue
            parsed.append(ParsedRule(kind="fallback", domain=None, address=address))
            continue
        unparsed.append(raw)
    return parsed, unparsed
