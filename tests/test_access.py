"""Source-address allowlist: what VPN_CONNECT_ALLOW_FROM parses to, and who it lets in.

Zero I/O -- the gate that calls this lives in the app factory and is exercised in test_web.py.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.services.access import (
    LOOPBACK_ONLY,
    AccessError,
    client_address,
    describe,
    is_allowed,
    parse_allow_from,
    parse_networks,
)

#: The operator's real shape: loopback, the LAN behind eno1, and the whole tailnet CGNAT range.
TYPICAL = "127.0.0.0/8,192.168.4.0/22,100.64.0.0/10"


@pytest.mark.parametrize("raw", ["", "   ", None, ",", " , "])
def test_an_empty_setting_means_loopback_only(raw):
    """Fail closed. An absent setting must never be read as 'allow everything'."""
    assert parse_allow_from(raw) == LOOPBACK_ONLY


def test_a_bare_address_becomes_a_host_route():
    assert parse_allow_from("100.119.222.51") == (ipaddress.ip_network("100.119.222.51/32"),)


def test_host_bits_are_tolerated():
    """What `ip addr` prints is 192.168.4.46/22, and that is what gets pasted in."""
    assert parse_allow_from("192.168.4.46/22") == (ipaddress.ip_network("192.168.4.0/22"),)


def test_entries_are_trimmed():
    assert parse_allow_from(" 10.0.0.0/8 , ::1/128 ") == (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    )


@pytest.mark.parametrize(
    "raw",
    [
        "192.168.4.0/22,not-an-address",
        "999.999.999.999",
        "192.168.4.0/64",
        "192.168.4.0/22 192.168.5.0/24",  # space-separated, not comma-separated
        "example.com",
    ],
)
def test_a_bad_entry_is_refused_rather_than_skipped(raw):
    """Dropping one entry silently either locks someone out or leaves the list wider than
    the file says. Neither is discoverable, so this refuses to start instead."""
    with pytest.raises(AccessError):
        parse_allow_from(raw)


def test_the_bad_entry_is_named():
    with pytest.raises(AccessError, match="not-an-address"):
        parse_allow_from("127.0.0.0/8,not-an-address")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "192.168.4.46", "192.168.7.255", "100.119.222.51", "100.64.0.1"],
)
def test_allowed_sources(address):
    assert is_allowed(address, parse_allow_from(TYPICAL))


def test_the_vpn_side_is_refused():
    """The point of the whole module. 172.27.246.54 is this machine's tun0 address: RFC1918,
    exactly like the LAN, so any private-vs-public test would let the concentrator in."""
    assert not is_allowed("172.27.246.54", parse_allow_from(TYPICAL))
    assert not is_allowed("172.27.246.1", parse_allow_from(TYPICAL))


def test_docker_and_the_wider_internet_are_refused():
    networks = parse_allow_from(TYPICAL)
    assert not is_allowed("172.17.0.2", networks)
    assert not is_allowed("8.8.8.8", networks)
    assert not is_allowed("192.168.8.1", networks)  # just outside the /22


def test_an_ipv4_mapped_peer_matches_its_ipv4_network():
    """A dual-stack listener reports an IPv4 client this way; it must not be a silent denial."""
    assert is_allowed("::ffff:192.168.4.46", parse_allow_from(TYPICAL))


def test_ipv6_and_ipv4_entries_do_not_match_across_versions():
    assert not is_allowed("::1", parse_allow_from("127.0.0.0/8"))
    assert not is_allowed("127.0.0.1", parse_allow_from("::1/128"))


@pytest.mark.parametrize("address", [None, "", "   ", "not-an-address", "192.168.4.46:5000"])
def test_an_unusable_peer_address_is_denied(address):
    assert not is_allowed(address, parse_allow_from(TYPICAL))


def test_describe_is_readable():
    assert describe(parse_allow_from("192.168.4.46/22")) == "192.168.4.0/22"


# --- attributing a request to a client, behind a proxy ----------------------

#: What `tailscale serve` looks like: it fronts the app on loopback, so every socket peer is
#: 127.0.0.1 and the tailnet address only survives in the header.
SERVE = parse_allow_from("127.0.0.0/8")


def test_no_proxy_configured_means_the_header_is_ignored():
    """The default. A direct install must behave exactly as if this feature did not exist."""
    assert client_address("192.168.4.46", "1.2.3.4", ()) == "192.168.4.46"


def test_a_header_from_an_untrusted_peer_is_ignored():
    """Anyone can send this header; only a peer we named may be believed."""
    assert client_address("192.168.4.46", "1.2.3.4", SERVE) == "192.168.4.46"


def test_a_trusted_proxy_names_the_client():
    assert client_address("127.0.0.1", "100.119.222.51", SERVE) == "100.119.222.51"


def test_the_rightmost_entry_wins():
    """A proxy appends, so the left half is whatever the client chose to send. Reading left to
    right would let an attacker pick their own throttle bucket and never hit the lockout."""
    assert client_address("127.0.0.1", "1.2.3.4, 100.119.222.51", SERVE) == "100.119.222.51"


def test_a_forged_chain_cannot_reach_past_the_real_client():
    forged = "10.0.0.1, 10.0.0.2, 10.0.0.3, 100.119.222.51"
    assert client_address("127.0.0.1", forged, SERVE) == "100.119.222.51"


def test_our_own_hops_are_walked_past():
    """Two trusted proxies chained: both appear in the header and neither is the client."""
    assert client_address("127.0.0.1", "100.119.222.51, 127.0.0.1", SERVE) == "100.119.222.51"


def test_a_trusted_peer_with_no_header_falls_back_to_the_peer():
    assert client_address("127.0.0.1", None, SERVE) == "127.0.0.1"
    assert client_address("127.0.0.1", "", SERVE) == "127.0.0.1"


def test_garbage_in_the_chain_discards_the_whole_header():
    """Everything further left arrived through the bad entry, so there is no reason to reach
    past it for a nicer-looking answer."""
    assert client_address("127.0.0.1", "100.119.222.51, nonsense", SERVE) == "127.0.0.1"
    assert client_address("127.0.0.1", "<script>", SERVE) == "127.0.0.1"


def test_an_ipv4_mapped_forwarded_client_is_normalised():
    assert client_address("127.0.0.1", "::ffff:100.119.222.51", SERVE) == "100.119.222.51"


def test_a_very_long_chain_is_bounded():
    chain = ", ".join(f"10.0.0.{i % 250}" for i in range(5000)) + ", 100.119.222.51"
    assert client_address("127.0.0.1", chain, SERVE) == "100.119.222.51"


def test_a_missing_peer_never_returns_none():
    """The throttle keys a dict on this, so it must always be a string."""
    assert client_address(None, None, SERVE) == "unknown"
    assert client_address(None, None, ()) == "unknown"


def test_the_proxy_list_is_empty_when_unset_not_loopback():
    """The opposite default to the allowlist, and deliberately so: an empty allowlist would mean
    'refuse everyone', an empty proxy list correctly means 'believe no headers'."""
    assert parse_networks("") == ()
    assert parse_networks(None) == ()
    assert parse_allow_from("") == LOOPBACK_ONLY


def test_a_bad_proxy_entry_names_the_right_setting():
    with pytest.raises(AccessError, match="VPN_CONNECT_TRUSTED_PROXIES"):
        parse_networks("nonsense", "VPN_CONNECT_TRUSTED_PROXIES")
