"""DNS rules as the app manages them: CRUD on top of the database, applied to the live dnsmasq
config through the root helper after every change.

Mirrors app.services.connections.Connections: validate via the store, persist, then perform the
side effect (here, ``dns-apply`` instead of writing a plain file) around it. The database commit
is the point of no return -- a failed apply degrades to a returned warning, never a rollback,
exactly like a failed .ovpn write does not undo a saved connection. Rolling back on a helper
failure would just move the "two sources of truth" problem this feature exists to remove from
file-vs-file to disk-vs-database.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

from app.config import Config
from app.services import dns, resolver, store
from app.services.dns import ParsedRule
from app.services.rooted import HelperError, run_helper
from app.services.store import DnsRule, StoreError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LegacyPreview:
    """What parsing the pre-existing dnsmasq file found, shown before anything is imported."""

    path: str
    rules: list[ParsedRule]
    unparsed: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "rules": [
                {"kind": r.kind, "domain": r.domain, "address": r.address} for r in self.rules
            ],
            "unparsed": self.unparsed,
        }


class DnsRules:
    """DNS rule CRUD plus applying them to the live config."""

    def __init__(self, db, config: Config, *, runner=subprocess.run) -> None:
        self._db = db
        self._config = config
        self._run = runner

    # -- reading ------------------------------------------------------------

    def list(self) -> tuple[list[DnsRule], list[DnsRule]]:
        """(domain_rules, fallback_rules)."""
        rules = store.list_dns_rules(self._db)
        domain_rules = [r for r in rules if r.kind == "domain"]
        fallback_rules = [r for r in rules if r.kind == "fallback"]
        return domain_rules, fallback_rules

    def legacy_preview(self) -> LegacyPreview | None:
        """What the pre-existing config file holds, only while nothing has been saved yet.

        Once the app has any rule of its own, the banner stops appearing -- and by then
        ``dns-apply`` has already renamed the legacy file aside, so the file this looks for is
        genuinely gone.
        """
        path = self._config.DNS_LEGACY_CONF
        if path is None or store.list_dns_rules(self._db):
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        rules, unparsed = dns.parse_dnsmasq(text)
        if not rules and not unparsed:
            return None
        return LegacyPreview(path=str(path), rules=rules, unparsed=unparsed)

    def status(self, log_lines=()) -> resolver.DnsReport:
        """Who is actually resolving what, cross-referenced against the rules held here.

        Goes through the same injected runner as ``dns-apply`` so that no test ever reaches the
        real systemd-resolved, even though this call needs no privileges.
        """
        domain_rules, fallback_rules = self.list()
        return resolver.report(
            device=self._config.TUN_DEVICE,
            domain_rules=domain_rules,
            fallback_rules=fallback_rules,
            log_lines=log_lines,
            runner=self._run,
            timeout=self._config.COMMAND_TIMEOUT_SECONDS,
        )

    # -- writing --------------------------------------------------------------

    def add(self, *, kind: str, domain: str | None, address: str) -> tuple[DnsRule, str | None]:
        rule = store.add_dns_rule(self._db, kind=kind, domain=domain, address=address)
        return rule, self._apply()

    def delete(self, rule_id: int) -> str | None:
        store.delete_dns_rule(self._db, rule_id)
        return self._apply()

    def move(self, rule_id: int, direction: str) -> str | None:
        store.move_fallback_rule(self._db, rule_id, direction)
        return self._apply()

    def import_legacy(self) -> tuple[list[DnsRule], list[DnsRule], str | None, int, list[str]]:
        """Insert every rule the legacy preview parsed, in one transaction, then apply once."""
        preview = self.legacy_preview()
        if preview is None:
            raise StoreError("There is nothing to import.")
        for parsed in preview.rules:
            store.add_dns_rule(
                self._db, kind=parsed.kind, domain=parsed.domain, address=parsed.address
            )
        warning = self._apply()
        domain_rules, fallback_rules = self.list()
        return domain_rules, fallback_rules, warning, len(preview.rules), preview.unparsed

    def _apply(self) -> str | None:
        """Render the current rules, stage them, and ask the helper to install and restart dnsmasq.

        Never raises: the database write this follows has already committed, so a helper failure
        must not make the save itself look like it failed. The message comes back as a warning
        the caller can surface instead.
        """
        domain_rules, fallback_rules = self.list()
        content = dns.render_dnsmasq(domain_rules, fallback_rules)
        store.write_dns_staging(self._config.dns_staging, content)
        try:
            result = run_helper(
                helper=self._config.HELPER,
                action="dns-apply",
                runner=self._run,
                timeout=self._config.COMMAND_TIMEOUT_SECONDS,
            )
        except HelperError as exc:
            log.warning("dns-apply failed: %s", exc)
            return str(exc)
        stdout = (result.stdout or "").strip()
        if stdout.startswith("applied:"):
            return stdout.removeprefix("applied:").strip()
        return None
