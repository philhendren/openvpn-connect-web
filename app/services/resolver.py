"""Which resolver actually answers what, and whether the DNS rules below it still matter.

The DNS counterpart of :mod:`app.services.routing`, and it makes the same choice for the same
reason: the server's ``PUSH_REPLY`` says what was *offered*, systemd-resolved says what was
actually installed, and the two diverge constantly. OpenVPN 2.6+ applies pushed ``dhcp-option
DNS`` itself over D-Bus when resolved is running -- no ``--up`` script involved, which is why the
tunnel can take DNS over on a client that runs no external scripts at all. Older clients, or a
box without resolved, apply nothing and leave the pushed options as decoration.

That difference is the whole point of this module. A domain forwarder in the DNS panel is
essential on one of those setups and dead weight on the other, and nothing in the rule itself
says which. Reading resolved answers it directly.

``resolvectl`` needs no privileges, so this stays outside the root helper. The pushed options are
read separately, best-effort, from the management log the controller already keeps.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: The tunnel resolves everything -- resolved sent it a ``~.`` route-only domain, so every lookup
#: goes over the tunnel and any local forwarder underneath it is bypassed.
ALL = "all"
#: The tunnel resolves the domains it was scoped to, and nothing else.
SPLIT = "split"
#: The tunnel is up but has no resolver of its own; whatever is under it does all the work.
NONE = "none"
#: No tunnel interface to ask about.
DOWN = "down"

# PUSH_REPLY packs its options into one comma-separated, quoted string, so a value ends at the
# next comma or quote -- \S+ would swallow the separator and the option after it.
_VALUE = r"([^\s,'\"]+)"
#: ``dhcp-option DNS 10.100.53.2`` inside a PUSH_REPLY line.
_PUSHED_DNS = re.compile(rf"dhcp-option\s+DNS\s+{_VALUE}", re.IGNORECASE)
#: ``dhcp-option DOMAIN example.org`` / ``DOMAIN-SEARCH``.
_PUSHED_DOMAIN = re.compile(rf"dhcp-option\s+DOMAIN(?:-SEARCH)?\s+{_VALUE}", re.IGNORECASE)


@dataclass(frozen=True)
class LinkDns:
    """What systemd-resolved has configured on one interface."""

    device: str
    servers: list[str] = field(default_factory=list)
    #: Domains this link is *routed* for (resolved's ``~domain`` form), without the tilde.
    routed: list[str] = field(default_factory=list)
    #: Ordinary search domains, appended to unqualified names.
    search: list[str] = field(default_factory=list)
    default_route: bool = False

    @property
    def catch_all(self) -> bool:
        """``~.`` -- the marker that this link claims every lookup, not just its own domains."""
        return "." in self.routed

    def to_dict(self) -> dict[str, object]:
        return {
            "device": self.device,
            "servers": self.servers,
            "routed": self.routed,
            "search": self.search,
            "default_route": self.default_route,
            "catch_all": self.catch_all,
        }


@dataclass(frozen=True)
class DnsReport:
    """The verdict, in the same shape as TunnelScope: a headline, the detail, and the evidence."""

    mode: str
    headline: str
    detail: str
    #: True when the operator has something to decide, not merely something to read.
    action_needed: bool
    link: LinkDns | None
    #: Per-rule remarks: whether each domain forwarder is doing anything right now.
    notes: list[str] = field(default_factory=list)
    #: What the server offered, when the management log still holds the PUSH_REPLY. Best effort:
    #: the log buffer is a rolling 200 lines, so on a long-running tunnel this is simply empty.
    pushed_servers: list[str] = field(default_factory=list)
    pushed_domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "headline": self.headline,
            "detail": self.detail,
            "action_needed": self.action_needed,
            "link": self.link.to_dict() if self.link else None,
            "notes": self.notes,
            "pushed_servers": self.pushed_servers,
            "pushed_domains": self.pushed_domains,
        }


def read_link(device: str, *, runner=subprocess.run, timeout: float = 5.0) -> LinkDns | None:
    """Ask systemd-resolved what is configured on ``device``, or None if it cannot say.

    Returns None both when the interface does not exist (tunnel down) and when resolved is not
    running at all -- the caller cannot act differently on those, and guessing which one it was
    would be worse than saying nothing.
    """
    try:
        result = runner(
            ["resolvectl", "--json=short", "status", device],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.info("resolvectl unavailable: %s", exc)
        return None
    if result.returncode != 0 or not (result.stdout or "").strip():
        return None
    try:
        links = json.loads(result.stdout)
    except json.JSONDecodeError:
        log.info("resolvectl returned output that is not JSON")
        return None
    if not isinstance(links, list) or not links:
        return None
    return _link(device, links[0])


def _link(device: str, raw: object) -> LinkDns | None:
    if not isinstance(raw, dict):
        return None
    servers = [
        address
        for server in raw.get("servers") or []
        if isinstance(server, dict) and (address := server.get("addressString"))
    ]
    routed: list[str] = []
    search: list[str] = []
    for domain in raw.get("searchDomains") or []:
        if not isinstance(domain, dict) or not (name := domain.get("name")):
            continue
        (routed if domain.get("routeOnly") else search).append(str(name))
    return LinkDns(
        device=device,
        servers=servers,
        routed=routed,
        search=search,
        default_route=bool(raw.get("defaultRoute")),
    )


def pushed_options(log_lines) -> tuple[list[str], list[str]]:
    """Pull ``dhcp-option DNS``/``DOMAIN`` out of the PUSH_REPLY the management log recorded.

    Only ever additional context -- see DnsReport.pushed_servers for why it is allowed to be
    empty on a perfectly healthy tunnel.
    """
    servers: list[str] = []
    domains: list[str] = []
    for line in log_lines:
        if "PUSH_REPLY" not in line:
            continue
        for match in _PUSHED_DNS.finditer(line):
            if match.group(1) not in servers:
                servers.append(match.group(1))
        for match in _PUSHED_DOMAIN.finditer(line):
            if match.group(1) not in domains:
                domains.append(match.group(1))
    return servers, domains


def report(
    *,
    device: str,
    domain_rules,
    fallback_rules=(),
    log_lines=(),
    runner=subprocess.run,
    timeout: float = 5.0,
) -> DnsReport:
    """Explain, in one paragraph, who resolves what right now -- and whether that needs action."""
    link = read_link(device, runner=runner, timeout=timeout)
    pushed_servers, pushed_domains = pushed_options(log_lines)
    rule_domains = [rule.domain for rule in domain_rules if rule.domain]

    if link is None or not link.servers:
        mode = DOWN if link is None else NONE
        headline, detail, action_needed, notes = _no_tunnel_resolver(
            mode, device, rule_domains, fallback_rules, pushed_servers
        )
    elif link.catch_all:
        mode = ALL
        headline, detail, action_needed, notes = _tunnel_takes_everything(link, rule_domains)
    else:
        mode = SPLIT
        headline, detail, action_needed, notes = _tunnel_takes_some(link, rule_domains)

    return DnsReport(
        mode=mode,
        headline=headline,
        detail=detail,
        action_needed=action_needed,
        link=link,
        notes=notes,
        pushed_servers=pushed_servers,
        pushed_domains=pushed_domains,
    )


def _tunnel_takes_everything(link: LinkDns, rule_domains) -> tuple[str, str, bool, list[str]]:
    """``~.`` on the tunnel link: resolved sends every lookup over the tunnel."""
    servers = _join(link.servers)
    headline = "The tunnel is resolving everything."
    detail = (
        f"OpenVPN gave systemd-resolved a catch-all domain on {link.device}, so every lookup — "
        f"not just internal names — goes to {servers} over the tunnel. Your VPN provider sees "
        "every domain you look up while connected, and the rules below are bypassed until the "
        "tunnel drops."
    )
    notes = [
        f"{domain} — resolved by the tunnel, not by this rule, while the tunnel is up."
        for domain in rule_domains
    ]
    if not rule_domains:
        notes.append(
            "Nothing below is in use right now. It takes over again the moment the tunnel drops."
        )
    return headline, detail, True, notes


def _tunnel_takes_some(link: LinkDns, rule_domains) -> tuple[str, str, bool, list[str]]:
    """Domain-scoped resolver on the tunnel link: the split is already being done above us."""
    servers = _join(link.servers)
    claimed = link.routed or link.search
    headline = f"Split DNS is already active for {_join(claimed)}."
    detail = (
        f"systemd-resolved sends {_join(claimed)} to {servers} over the tunnel and everything "
        "else to your normal resolver, so the split is being done for you. No action needed."
    )
    notes = []
    for domain in rule_domains:
        if _covered(domain, claimed):
            notes.append(
                f"{domain} — the tunnel already claims this; the rule below is redundant but "
                "harmless."
            )
        else:
            notes.append(f"{domain} — not claimed by the tunnel, so this rule is what resolves it.")
    return headline, detail, False, notes


def _no_tunnel_resolver(
    mode: str, device: str, rule_domains, fallback_rules, pushed_servers
) -> tuple[str, str, bool, list[str]]:
    """No resolver on the tunnel -- either it is down, or nothing applied what was pushed."""
    if mode == DOWN:
        headline = "The tunnel is not resolving anything."
        detail = (
            f"There is no {device} interface for systemd-resolved to have configured. The rules "
            "below are the whole story: they are what your system resolver forwards to."
        )
    else:
        headline = "The tunnel pushed DNS, but nothing applied it."
        offered = f" It offered {_join(pushed_servers)}." if pushed_servers else ""
        detail = (
            f"{device} is up but has no resolver configured on it, so nothing internal resolves "
            f"by itself.{offered} The rules below are what make internal names work — keep them."
        )
    notes = [f"{domain} — in use: this rule is what resolves it." for domain in rule_domains]
    if not rule_domains:
        notes.append(
            "No domain forwarders are configured, so nothing is being sent over the tunnel."
        )
    if not fallback_rules:
        notes.append("No fallback servers are configured; dnsmasq will use its own defaults.")
    return headline, detail, mode == NONE and not rule_domains, notes


def _covered(domain: str, claimed) -> bool:
    """Whether resolved already routes ``domain`` -- as itself or under a claimed parent."""
    domain = domain.lower().rstrip(".")
    for entry in claimed:
        entry = str(entry).lower().rstrip(".")
        if entry in ("", ".") or domain == entry or domain.endswith(f".{entry}"):
            return True
    return False


def _join(values) -> str:
    values = [str(value) for value in values]
    if not values:
        return "nothing"
    if len(values) == 1:
        return values[0]
    return f"{', '.join(values[:-1])} and {values[-1]}"
