"""Split versus full tunnel, coverage, and the IPv6 check.

A wrong verdict here is a security-relevant lie -- "fully tunnelled" when it is not, or silence
about IPv6 escaping -- so the awkward cases get their own tests rather than being implied by a
happy path.
"""

from __future__ import annotations

import pytest

from app.services.scope import (
    FULL,
    NONE,
    SPLIT,
    coverage,
    evaluate,
    read_scope,
)


def route(dst: str, dev: str = "tun0", **extra) -> dict:
    return {"dst": dst, "dev": dev, **extra}


def v4(entries: list[dict], device: str = "tun0"):
    return evaluate(4, entries, device)


def v6(entries: list[dict], device: str = "tun0"):
    return evaluate(6, entries, device)


#: The shape of the real ExampleCorp table: a physical default plus many pushed prefixes.
SPLIT_TABLE = [
    route("default", "eno1"),
    route("10.100.0.0/18"),
    route("5.20.0.0/14"),
    route("14.70.228.6"),
    route("10.99.0.0/23"),
]


# --- the redirect-gateway trap ---------------------------------------------


def test_a_one_slash_pair_is_a_full_tunnel():
    """The trap: redirect-gateway leaves the default route alone and installs two /1 halves."""
    result = v4([route("default", "eno1"), route("0.0.0.0/1"), route("128.0.0.0/1")])
    assert result.mode == FULL
    assert result.coverage == 1.0


def test_the_one_slash_pair_has_no_default_route_via_the_tunnel():
    """Proof the naive check would get this wrong: there is no default route on tun at all."""
    result = v4([route("default", "eno1"), route("0.0.0.0/1"), route("128.0.0.0/1")])
    assert result.default_via_tunnel is False
    assert result.redirect_pair is True


def test_half_of_the_pair_is_not_a_full_tunnel():
    """One /1 alone covers half the internet -- large, but emphatically still split."""
    result = v4([route("default", "eno1"), route("0.0.0.0/1")])
    assert result.mode == SPLIT
    assert result.coverage == 0.5


def test_a_plain_default_route_is_also_a_full_tunnel():
    result = v4([route("default")])
    assert result.mode == FULL
    assert result.default_via_tunnel is True
    assert result.redirect_pair is False


def test_the_pair_on_the_wrong_device_does_not_count():
    result = v4([route("0.0.0.0/1", "eno1"), route("128.0.0.0/1", "eno1")])
    assert result.mode == NONE


# --- coverage --------------------------------------------------------------


def test_a_real_split_tunnel_carries_a_sliver():
    result = v4(SPLIT_TABLE)
    assert result.mode == SPLIT
    assert 0 < result.coverage < 0.001


def test_overlapping_prefixes_are_not_counted_twice():
    """A naive sum of prefix sizes would report 10.0.0.0/8 plus a slice of itself."""
    result = v4([route("10.0.0.0/8"), route("10.1.0.0/16")])
    assert result.prefixes == 2
    assert result.blocks == 1
    assert result.coverage == pytest.approx(2**24 / 2**32)


def test_adjacent_prefixes_merge():
    result = v4([route("10.0.0.0/9"), route("10.128.0.0/9")])
    assert result.blocks == 1
    assert result.coverage == pytest.approx(2**24 / 2**32)


def test_coverage_of_nothing_is_zero():
    assert coverage([], 4) == 0.0


def test_a_host_route_counts_as_one_address():
    assert v4([route("14.70.228.6")]).coverage == pytest.approx(1 / 2**32)


def test_link_local_and_multicast_do_not_inflate_coverage():
    """Otherwise every tunnel would show a floor of coverage it does not actually carry."""
    result = v4([route("169.254.0.0/16"), route("224.0.0.0/4")])
    assert result.mode == NONE
    assert result.coverage == 0.0


# --- public ranges -----------------------------------------------------------


def test_public_ranges_are_counted_separately_from_private_ones():
    """The ExampleCorp split table: two pushed prefixes are AWS/Azure-style public allocations, two
    are the operator's own RFC 1918 space -- only the former are worth a whois lookup."""
    result = v4(SPLIT_TABLE)
    assert result.public_prefixes == 2  # 5.20.0.0/14 and the 14.70.228.6 host route
    assert result.public_coverage == pytest.approx((2**18 + 1) / 2**32)


def test_a_purely_private_split_tunnel_has_no_public_prefixes():
    result = v4([route("10.0.0.0/8"), route("172.16.0.0/12")])
    assert result.public_prefixes == 0
    assert result.public_coverage == 0.0


def test_a_public_block_does_not_merge_across_a_private_one_when_collapsing():
    """Collapsing the public subset must not pretend an adjacent private prefix is also public."""
    result = v4([route("3.0.0.0/9"), route("3.128.0.0/9")])  # adjacent, both public
    assert result.public_prefixes == 2
    assert result.public_blocks == 1
    assert result.public_coverage == pytest.approx(2**24 / 2**32)


def test_the_redirect_pair_is_not_counted_as_a_public_range():
    """A /1 half is "everything", not a registry-delegated block -- scope.py already explains
    what a full tunnel means, so it must not also show up as a public-range surprise."""
    result = v4([route("default", "eno1"), route("0.0.0.0/1"), route("128.0.0.0/1")])
    assert result.mode == FULL
    assert result.public_prefixes == 0


# --- nothing routed --------------------------------------------------------


def test_a_down_tunnel_is_none():
    assert v4([route("default", "eno1")]).mode == NONE


def test_an_empty_table_is_none():
    assert v4([]).mode == NONE


def test_junk_entries_are_skipped():
    assert v4([{"dev": "tun0"}, {"dst": "10.0.0.0/8"}, {}, route("not-a-prefix")]).mode == NONE


def test_the_device_is_honoured():
    assert v4([route("default", "tun7")], device="tun7").mode == FULL
    assert v4([route("default", "tun7")], device="tun0").mode == NONE


# --- IPv6 ------------------------------------------------------------------


def test_ipv6_leaking_is_detected():
    """The headline case: v6 can leave the machine and none of it enters the tunnel."""
    result = v6([{"dst": "default", "dev": "eno1"}, {"dst": "fe80::/64", "dev": "tun0"}])
    assert result.mode == NONE
    assert result.egress_device == "eno1"


def test_ipv6_absent_has_nowhere_to_leak_to():
    """No v6 egress at all means nothing to warn about."""
    result = v6([{"dst": "fe80::/64", "dev": "eno1"}])
    assert result.mode == NONE
    assert result.egress_device is None


def test_ipv6_fully_tunnelled():
    assert v6([{"dst": "default", "dev": "tun0"}]).mode == FULL


def test_the_ipv6_redirect_pair_is_understood_too():
    result = v6([{"dst": "::/1", "dev": "tun0"}, {"dst": "8000::/1", "dev": "tun0"}])
    assert result.mode == FULL
    assert result.redirect_pair is True


# --- the combined verdict --------------------------------------------------


def _scope(v4_entries, v6_entries, device="tun0"):
    calls = {"4": v4_entries, "6": v6_entries}

    def runner(argv, **_kwargs):
        import json

        family = argv[2].lstrip("-")
        return type("R", (), {"returncode": 0, "stdout": json.dumps(calls[family]), "stderr": ""})()

    return read_scope(runner, device=device)


def test_a_split_tunnel_with_direct_ipv6_does_not_warn():
    """On a work VPN this is the intended arrangement, not a fault.

    Personal traffic is meant to go direct, and IPv6 going direct alongside it is consistent.
    Warning here would cry wolf on a correctly configured machine -- and an operator who learns
    to dismiss this warning will dismiss the real one too.
    """
    result = _scope(SPLIT_TABLE, [{"dst": "default", "dev": "eno1"}])
    assert result.mode == SPLIT
    assert result.warnings == []


def test_a_full_tunnel_that_leaks_ipv6_warns():
    """The contradiction worth interrupting for: IPv4 carries everything, IPv6 escapes."""
    result = _scope([route("default")], [{"dst": "default", "dev": "eno1"}])
    assert len(result.warnings) == 1
    assert "bypasses the VPN" in result.warnings[0]
    assert "eno1" in result.warnings[0]


def test_a_clean_full_tunnel_has_nothing_to_warn_about():
    result = _scope([route("default")], [{"dst": "default", "dev": "tun0"}])
    assert result.mode == FULL
    assert result.warnings == []


def test_full_v4_but_partial_v6_is_called_out():
    result = _scope(
        [route("default")],
        [{"dst": "default", "dev": "eno1"}, {"dst": "2001:db8::/32", "dev": "tun0"}],
    )
    assert result.ipv6.mode == SPLIT
    assert "only part of IPv6" in result.warnings[0]


def test_a_full_tunnel_covering_both_families_is_silent():
    result = _scope([route("default")], [{"dst": "default", "dev": "tun0"}])
    assert result.mode == FULL
    assert result.warnings == []


def test_a_full_tunnel_on_a_machine_without_ipv6_is_silent():
    """Nothing can escape over a family the machine does not route at all."""
    result = _scope([route("default")], [{"dst": "fe80::/64", "dev": "eno1"}])
    assert result.warnings == []


def test_a_tunnel_that_is_simply_down_is_not_leaking():
    """A VPN that is off is not a leak. Saying otherwise trains the operator to ignore warnings."""
    result = _scope([route("default", "eno1")], [{"dst": "default", "dev": "eno1"}])
    assert result.active is False
    assert result.leaking(result.ipv4) is False
    assert result.leaking(result.ipv6) is False
    assert result.warnings == []


def test_a_live_tunnel_carrying_no_ipv6_is_leaking():
    result = _scope(SPLIT_TABLE, [{"dst": "default", "dev": "eno1"}])
    assert result.active is True
    assert result.leaking(result.ipv6) is True


def test_no_ipv6_on_the_machine_produces_no_noise():
    result = _scope(SPLIT_TABLE, [])
    assert result.ipv6.mode == NONE
    assert result.warnings == []


def test_a_missing_ip_command_is_not_an_error():
    """A machine without iproute2 should report "no tunnel", not fail the page."""

    def runner(*_args, **_kwargs):
        raise FileNotFoundError("ip")

    assert read_scope(runner).mode == NONE


def test_unreadable_output_is_not_an_error():
    def runner(*_args, **_kwargs):
        return type("R", (), {"returncode": 0, "stdout": "not json", "stderr": ""})()

    assert read_scope(runner).mode == NONE


def test_the_payload_serialises():
    payload = _scope(SPLIT_TABLE, [{"dst": "default", "dev": "eno1"}]).to_dict()
    assert payload["mode"] == SPLIT
    assert payload["ipv4"]["prefixes"] == 4
    assert payload["ipv6"]["leaking"] is True  # the fact
    assert payload["warnings"] == []  # ...but not, here, a problem worth raising
    assert payload["ipv4"]["public_prefixes"] == 2
    assert "public address space" in payload["public_notice"]


# --- the public-range notice --------------------------------------------------


def test_a_split_tunnel_with_a_public_range_gets_the_notice():
    """The exact question this exists to answer: AWS routes came down on a split tunnel, does
    that mean traffic to anything hosted there goes through the VPN? Yes -- said plainly."""
    result = _scope(SPLIT_TABLE, [])
    assert result.mode == SPLIT
    notice = result.public_notice
    assert notice is not None
    assert "2 of the routed networks" in notice
    assert "not just the service this VPN is meant to reach" in notice


def test_a_purely_private_split_tunnel_gets_no_notice():
    result = _scope([route("default", "eno1"), route("10.0.0.0/8")], [])
    assert result.mode == SPLIT
    assert result.public_notice is None


def test_a_full_tunnel_gets_no_public_notice():
    """Everything is already covered on a full tunnel -- pointing out that some of it happens to
    be public space adds nothing the operator does not already know."""
    result = _scope([route("default"), route("5.20.0.0/14")], [])
    assert result.mode == FULL
    assert result.public_notice is None


def test_a_down_tunnel_gets_no_public_notice():
    result = _scope([route("default", "eno1")], [])
    assert result.mode == NONE
    assert result.public_notice is None
