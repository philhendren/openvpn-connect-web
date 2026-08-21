"""DNS split-config grammar: what a domain or address may contain, and the exact text a saved
rule set renders to. Zero I/O -- persistence lives in the store, applying lives in dns_rules.py.
"""

from __future__ import annotations

import pytest

from app.services.dns import (
    DnsError,
    ParsedRule,
    parse_dnsmasq,
    render_dnsmasq,
    validate_address,
    validate_domain,
)
from app.services.store import DnsRule


@pytest.mark.parametrize("domain", ["example.corp", "sub.example.corp", "a.b.c.example"])
def test_good_domains_are_accepted(domain):
    assert validate_domain(domain) == domain


def test_a_domain_is_trimmed_and_lowercased():
    assert validate_domain("  Example.Corp.  ") == "example.corp"


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "/etc/passwd",  # breaks out of the /domain/ slot
        "example.corp/extra",
        "evil\ndomain.com",  # embedded newline
        "a" * 254,  # over the 253-char total limit
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "*",
        "a b.com",
    ],
)
def test_bad_domains_are_refused(domain):
    with pytest.raises(DnsError):
        validate_domain(domain)


@pytest.mark.parametrize("address", ["8.8.8.8", "10.100.53.2", "2001:4860:4860::8888", "::1"])
def test_good_addresses_are_accepted(address):
    assert validate_address(address) == address


@pytest.mark.parametrize(
    "address",
    [
        "",
        "8.8.8.8; rm -rf /",
        "8.8.8.8\nserver=1.1.1.1",  # newline-smuggled second directive
        "999.999.999.999",
        "example.corp",  # a domain, not an address
        "9" * 10_000,
    ],
)
def test_bad_addresses_are_refused(address):
    with pytest.raises(DnsError):
        validate_address(address)


def _rule(*, kind, domain=None, address, position=None, rule_id=1):
    """A DnsRule with the fields render_dnsmasq() actually reads; id/updated_at are unused here."""
    return DnsRule(
        id=rule_id, kind=kind, domain=domain, address=address, position=position, updated_at=""
    )


def test_render_produces_the_exact_dnsmasq_syntax():
    domain_rules = [_rule(kind="domain", domain="example.corp", address="10.100.53.2")]
    fallback_rules = [
        _rule(kind="fallback", address="8.8.8.8", position=0),
        _rule(kind="fallback", address="8.8.4.4", position=1),
    ]
    text = render_dnsmasq(domain_rules, fallback_rules)
    assert text == (
        "# Managed by vpn-connect. Do not edit -- changes here are overwritten on the next save.\n"
        "server=/example.corp/10.100.53.2\n"
        "server=8.8.8.8\n"
        "server=8.8.4.4\n"
    )


def test_render_with_no_rules_is_just_the_header():
    assert render_dnsmasq([], []) == (
        "# Managed by vpn-connect. Do not edit -- changes here are overwritten on the next save.\n"
    )


def test_domain_rules_render_alphabetically_regardless_of_input_order():
    domain_rules = [
        _rule(kind="domain", domain="z.example", address="1.1.1.1"),
        _rule(kind="domain", domain="a.example", address="2.2.2.2"),
    ]
    text = render_dnsmasq(domain_rules, [])
    assert text.index("a.example") < text.index("z.example")


def test_fallback_rules_render_in_position_order():
    fallback_rules = [
        _rule(kind="fallback", address="9.9.9.9", position=1),
        _rule(kind="fallback", address="1.1.1.1", position=0),
    ]
    text = render_dnsmasq([], fallback_rules)
    assert text.index("1.1.1.1") < text.index("9.9.9.9")


def test_parse_round_trips_a_real_hand_written_conf():
    text = "server=/example.corp/10.100.53.2\nserver=8.8.8.8\nserver=8.8.4.4\n"
    parsed, unparsed = parse_dnsmasq(text)
    assert unparsed == []
    assert parsed == [
        ParsedRule(kind="domain", domain="example.corp", address="10.100.53.2"),
        ParsedRule(kind="fallback", domain=None, address="8.8.8.8"),
        ParsedRule(kind="fallback", domain=None, address="8.8.4.4"),
    ]


def test_parse_ignores_comments_and_blank_lines():
    parsed, unparsed = parse_dnsmasq("# a comment\n\nserver=8.8.8.8\n")
    assert unparsed == []
    assert parsed == [ParsedRule(kind="fallback", domain=None, address="8.8.8.8")]


def test_parse_surfaces_a_line_it_cannot_classify_rather_than_dropping_it():
    parsed, unparsed = parse_dnsmasq("address=/ads.example/0.0.0.0\n")
    assert parsed == []
    assert unparsed == ["address=/ads.example/0.0.0.0"]


def test_parse_never_raises_on_hostile_input():
    parsed, unparsed = parse_dnsmasq("server=/../../etc/passwd/1.2.3.4\nserver=not-an-ip\n")
    assert parsed == []
    assert len(unparsed) == 2
