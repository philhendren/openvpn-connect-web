"""The resolver verdict: who actually answers a lookup while the tunnel is up.

The cases here are the four that change what the operator should do about a domain forwarder --
the tunnel taking DNS over entirely, scoping it to named domains, applying none of it, or not
being there at all. Everything is driven off canned ``resolvectl --json=short`` output, so no
test touches systemd-resolved.
"""

from __future__ import annotations

import json
import subprocess

from app.services import resolver
from app.services.store import DnsRule


class FakeResolvectl:
    """Stands in for subprocess.run, returning one canned links payload."""

    def __init__(self, payload=None, *, returncode: int = 0, stdout: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stdout = json.dumps(payload) if stdout is None else stdout
        self.side_effect: Exception | None = None

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.side_effect is not None:
            raise self.side_effect
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")


def _link(*, servers=("10.100.53.2",), domains=(), default_route=True):
    """One entry shaped like a real ``resolvectl --json=short status tun0`` link."""
    return [
        {
            "ifname": "tun0",
            "ifindex": 114,
            "defaultRoute": default_route,
            "servers": [{"addressString": address} for address in servers],
            "searchDomains": [
                {"name": name, "routeOnly": route_only} for name, route_only in domains
            ],
        }
    ]


def _rule(domain: str, address: str = "10.100.53.2") -> DnsRule:
    return DnsRule(
        id=1, kind="domain", domain=domain, address=address, position=None, updated_at="now"
    )


# --- reading the link ---


def test_the_query_is_scoped_to_the_tunnel_device():
    runner = FakeResolvectl(_link())
    resolver.read_link("tun0", runner=runner)
    assert runner.calls == [["resolvectl", "--json=short", "status", "tun0"]]


def test_servers_and_routed_domains_are_pulled_apart():
    runner = FakeResolvectl(
        _link(domains=[("example.corp", True), ("example.org", False), (".", True)])
    )
    link = resolver.read_link("tun0", runner=runner)
    assert link.servers == ["10.100.53.2"]
    assert link.routed == ["example.corp", "."]
    assert link.search == ["example.org"]
    assert link.catch_all is True


def test_a_missing_interface_reads_as_no_link():
    runner = FakeResolvectl(None, returncode=1, stdout="")
    assert resolver.read_link("tun0", runner=runner) is None


def test_resolvectl_not_installed_reads_as_no_link():
    runner = FakeResolvectl(_link())
    runner.side_effect = FileNotFoundError("resolvectl")
    assert resolver.read_link("tun0", runner=runner) is None


def test_output_that_is_not_json_reads_as_no_link():
    runner = FakeResolvectl(None, stdout="Failed to resolve interface\n")
    assert resolver.read_link("tun0", runner=runner) is None


def test_a_timeout_reads_as_no_link():
    runner = FakeResolvectl(_link())
    runner.side_effect = subprocess.TimeoutExpired(cmd="resolvectl", timeout=1)
    assert resolver.read_link("tun0", runner=runner) is None


# --- the verdict ---


def test_a_catch_all_domain_means_the_tunnel_resolves_everything():
    runner = FakeResolvectl(_link(domains=[(".", True)]))
    report = resolver.report(device="tun0", domain_rules=[_rule("example.corp")], runner=runner)
    assert report.mode == resolver.ALL
    assert report.action_needed is True
    assert "10.100.53.2" in report.detail
    # The whole point: the rule below is not what is doing the work right now.
    assert any("not by this rule" in note for note in report.notes)


def test_domain_scoped_dns_is_a_working_split_needing_no_action():
    runner = FakeResolvectl(_link(domains=[("example.corp", True)], default_route=False))
    report = resolver.report(device="tun0", domain_rules=[], runner=runner)
    assert report.mode == resolver.SPLIT
    assert report.action_needed is False
    assert "example.corp" in report.headline


def test_a_rule_the_tunnel_already_claims_is_called_redundant():
    runner = FakeResolvectl(_link(domains=[("example.corp", True)], default_route=False))
    report = resolver.report(device="tun0", domain_rules=[_rule("example.corp")], runner=runner)
    assert any("redundant" in note for note in report.notes)


def test_a_subdomain_of_a_claimed_domain_counts_as_claimed():
    runner = FakeResolvectl(_link(domains=[("example.corp", True)], default_route=False))
    report = resolver.report(device="tun0", domain_rules=[_rule("api.example.corp")], runner=runner)
    assert any("redundant" in note for note in report.notes)


def test_an_unclaimed_rule_is_reported_as_the_one_doing_the_work():
    runner = FakeResolvectl(_link(domains=[("other.example", True)], default_route=False))
    report = resolver.report(device="tun0", domain_rules=[_rule("example.corp")], runner=runner)
    assert any("this rule is what resolves it" in note for note in report.notes)


def test_a_tunnel_with_no_resolver_leaves_the_rules_doing_the_work():
    runner = FakeResolvectl(_link(servers=()))
    report = resolver.report(device="tun0", domain_rules=[_rule("example.corp")], runner=runner)
    assert report.mode == resolver.NONE
    assert "keep them" in report.detail
    assert any("in use" in note for note in report.notes)


def test_a_tunnel_with_no_resolver_and_no_rules_needs_action():
    runner = FakeResolvectl(_link(servers=()))
    report = resolver.report(device="tun0", domain_rules=[], runner=runner)
    assert report.mode == resolver.NONE
    assert report.action_needed is True


def test_no_interface_at_all_is_reported_as_down():
    runner = FakeResolvectl(None, returncode=1, stdout="")
    report = resolver.report(device="tun0", domain_rules=[], runner=runner)
    assert report.mode == resolver.DOWN
    assert report.action_needed is False
    assert report.link is None


# --- pushed options, read from the management log ---


PUSH_REPLY = (
    "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,"
    "dhcp-option DNS 10.100.53.2,dhcp-option DNS 10.100.53.3,"
    "dhcp-option DOMAIN example.corp,redirect-gateway def1'"
)


def test_pushed_dns_options_are_read_out_of_the_push_reply():
    servers, domains = resolver.pushed_options([PUSH_REPLY])
    assert servers == ["10.100.53.2", "10.100.53.3"]
    assert domains == ["example.corp"]


def test_a_log_without_a_push_reply_yields_nothing():
    servers, domains = resolver.pushed_options(["Initialization Sequence Completed"])
    assert servers == []
    assert domains == []


def test_the_push_is_surfaced_when_nothing_applied_it():
    runner = FakeResolvectl(_link(servers=()))
    report = resolver.report(device="tun0", domain_rules=[], log_lines=[PUSH_REPLY], runner=runner)
    assert report.pushed_servers == ["10.100.53.2", "10.100.53.3"]
    assert "10.100.53.2" in report.detail


def test_the_report_survives_a_log_the_buffer_has_already_dropped():
    """A 200-line rolling buffer loses the PUSH_REPLY on a long-running tunnel; that is fine."""
    runner = FakeResolvectl(_link(domains=[(".", True)]))
    report = resolver.report(device="tun0", domain_rules=[], log_lines=[], runner=runner)
    assert report.pushed_servers == []
    assert report.headline  # the verdict does not depend on the push
