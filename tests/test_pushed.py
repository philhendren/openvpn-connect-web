"""Comparing the concentrator's PUSH_REPLY against the routes the kernel actually holds."""

from __future__ import annotations

from app.services import pushed
from app.services.pushed import PushReport, find_reply, parse, report
from app.services.routing import Route


def _reply(*options: str) -> str:
    return "PUSH: Received control message: 'PUSH_REPLY," + ",".join(options) + "'"


def _installed(*destinations: str) -> list[Route]:
    return [
        Route(destination=d, gateway="10.20.0.1", device="tun0", metric=None) for d in destinations
    ]


def _destinations(routes) -> list[str]:
    return [route.destination for route in routes]


# -- parsing ---------------------------------------------------------------


def test_a_pushed_route_becomes_a_prefix():
    (route,) = parse(_reply("route 10.20.0.0 255.255.0.0"))
    assert route.destination == "10.20.0.0/16"
    assert route.addresses == 65536
    assert route.readable


def test_a_route_with_no_netmask_is_a_single_host():
    """OpenVPN defaults the mask to 255.255.255.255, so the push means one address."""
    (route,) = parse(_reply("route 172.16.9.5"))
    assert route.destination == "172.16.9.5/32"
    assert route.addresses == 1


def test_the_gateway_and_metric_are_read_from_their_positions():
    (route,) = parse(_reply("route 192.168.30.0 255.255.255.0 vpn_gateway 500"))
    assert route.gateway == "vpn_gateway"
    assert route.metric == 500


def test_a_symbolic_gateway_is_shown_as_written():
    """``vpn_gateway`` is a name OpenVPN resolves itself, not an address to be parsed."""
    (route,) = parse(_reply("route 10.0.0.0 255.0.0.0 vpn_gateway"))
    assert route.gateway == "vpn_gateway"


def test_redirect_gateway_is_a_directive_not_a_prefix():
    (route,) = parse(_reply("redirect-gateway def1 bypass-dhcp"))
    assert route.catch_all
    assert route.destination == "default"
    assert route.option == "redirect-gateway def1 bypass-dhcp"


def test_options_that_are_not_routes_are_ignored():
    routes = parse(
        _reply(
            "dhcp-option DNS 10.20.0.1",
            "route-gateway 10.20.0.1",
            "route 10.20.0.0 255.255.0.0",
            "ping 10",
            "topology subnet",
            "ifconfig 10.20.0.42 255.255.255.0",
        )
    )
    assert _destinations(routes) == ["10.20.0.0/16"]


def test_pushed_ipv6_routes_are_skipped():
    """The comparison is against the IPv4 table; a v6 prefix would read as rejected every time."""
    assert parse(_reply("route-ipv6 2001:db8::/64", "route 10.20.0.0 255.255.0.0")) == parse(
        _reply("route 10.20.0.0 255.255.0.0")
    )


def test_an_unreadable_route_option_survives_as_its_own_text():
    (route,) = parse(_reply("route wibble"))
    assert not route.readable
    assert route.destination == "route wibble"
    assert route.addresses is None


def test_a_bare_route_verb_is_unreadable_rather_than_dropped():
    (route,) = parse(_reply("route"))
    assert not route.readable


def test_an_invalid_netmask_makes_the_option_unreadable():
    """255.0.255.0 is not a run of ones -- OpenVPN would not have installed this either."""
    (route,) = parse(_reply("route 10.0.0.0 255.0.255.0"))
    assert not route.readable


def test_a_route_already_in_cidr_form_is_accepted():
    (route,) = parse(_reply("route 10.20.0.0/16"))
    assert route.destination == "10.20.0.0/16"


def test_host_bits_are_tolerated():
    (route,) = parse(_reply("route 10.20.0.42 255.255.0.0"))
    assert route.destination == "10.20.0.0/16"


def test_a_repeated_option_is_listed_once():
    routes = parse(_reply("route 10.20.0.0 255.255.0.0", "route 10.20.0.0 255.255.0.0"))
    assert len(routes) == 1


def test_a_line_without_a_push_reply_yields_nothing():
    assert parse("OPTIONS IMPORT: route options modified") == []


def test_no_line_at_all_yields_nothing():
    assert parse(None) == []
    assert parse("") == []


# -- finding the reply in the log -----------------------------------------


def test_the_newest_push_reply_wins():
    """A reconnect pushes again, and the older reply describes a tunnel that is gone."""
    lines = [_reply("route 10.1.0.0 255.255.0.0"), "…", _reply("route 10.2.0.0 255.255.0.0")]
    assert "10.2.0.0" in find_reply(lines)


def test_find_reply_returns_none_when_the_push_has_aged_out():
    assert find_reply(["MANAGEMENT: CMD 'state'", "TLS: soft reset"]) is None


def test_find_reply_accepts_any_iterable():
    assert find_reply(iter([_reply("route 10.1.0.0 255.255.0.0")])) is not None


# -- the comparison --------------------------------------------------------


def test_a_pushed_route_present_in_the_kernel_is_not_rejected():
    result = report(_reply("route 10.20.0.0 255.255.0.0"), _installed("10.20.0.0/16"))
    assert result.seen
    assert result.rejected == ()


def test_a_pushed_route_missing_from_the_kernel_is_rejected():
    result = report(
        _reply("route 10.20.0.0 255.255.0.0", "route 192.168.30.0 255.255.255.0"),
        _installed("10.20.0.0/16"),
    )
    assert _destinations(result.rejected) == ["192.168.30.0/24"]
    assert not result.wholesale


def test_a_host_route_matches_the_kernels_bare_address():
    """``ip route`` prints a /32 without its prefix length, so the match is on the network."""
    result = report(_reply("route 172.16.9.5"), _installed("172.16.9.5"))
    assert result.rejected == ()


def test_redirect_gateway_is_satisfied_by_the_two_halves():
    """``def1`` installs 0.0.0.0/1 and 128.0.0.0/1 rather than replacing the default route."""
    result = report(
        _reply("redirect-gateway def1"), _installed("0.0.0.0/1", "128.0.0.0/1", "10.20.0.0/16")
    )
    assert result.rejected == ()


def test_redirect_gateway_is_satisfied_by_a_plain_default_route():
    result = report(_reply("redirect-gateway"), _installed("default"))
    assert result.rejected == ()


def test_redirect_gateway_is_rejected_when_only_one_half_arrived():
    result = report(_reply("redirect-gateway def1"), _installed("0.0.0.0/1"))
    assert [route.catch_all for route in result.rejected] == [True]


def test_an_unreadable_option_is_always_reported_as_rejected():
    result = report(_reply("route wibble"), _installed("10.20.0.0/16"))
    assert _destinations(result.rejected) == ["route wibble"]


def test_rejected_routes_are_sorted_by_address_with_unreadable_last():
    result = report(
        _reply("route wibble", "route 192.168.30.0 255.255.255.0", "route 10.5.0.0 255.255.0.0"),
        _installed("10.20.0.0/16"),
    )
    assert _destinations(result.rejected) == ["10.5.0.0/16", "192.168.30.0/24", "route wibble"]


def test_every_route_missing_is_reported_as_one_cause():
    result = report(
        _reply("route 10.20.0.0 255.255.0.0", "route 192.168.30.0 255.255.255.0"),
        _installed("10.99.0.0/23"),
    )
    assert result.wholesale
    assert len(result.rejected) == 2


def test_wholesale_is_false_when_nothing_was_pushed():
    assert not report(_reply("ping 10"), _installed("10.20.0.0/16")).wholesale


def test_no_push_reply_reports_nothing_rather_than_everything():
    """The buffer is bounded; a report that lies once is worse than one that is sometimes silent."""
    result = report(None, _installed("10.20.0.0/16"))
    assert result is pushed.NOTHING_PUSHED
    assert not result.seen
    assert result.rejected == ()


def test_an_empty_routing_table_is_not_treated_as_a_wholesale_rejection():
    """No routes at all means the tunnel is down, not that the server was refused."""
    result = report(_reply("route 10.20.0.0 255.255.0.0"), [])
    assert result.seen
    assert result.rejected == ()
    assert len(result.pushed) == 1


def test_routes_with_no_parsable_destination_do_not_crash_the_match():
    result = report(_reply("route 10.20.0.0 255.255.0.0"), [Route("nonsense", None, "tun0", None)])
    assert _destinations(result.rejected) == ["10.20.0.0/16"]


# -- OpenVPN's own complaints ---------------------------------------------


def test_route_errors_from_the_log_are_carried_verbatim():
    result = report(
        _reply("route 192.168.30.0 255.255.255.0"),
        _installed("10.20.0.0/16"),
        log_lines=[
            "TLS: soft reset",
            "ERROR: Linux route add command failed: external program exited with error status: 2",
        ],
    )
    assert result.notes == (
        "ERROR: Linux route add command failed: external program exited with error status: 2",
    )


def test_unrelated_log_lines_are_not_carried():
    result = report(
        _reply("route 192.168.30.0 255.255.255.0"),
        _installed("10.20.0.0/16"),
        log_lines=["Initialization Sequence Completed", "MANAGEMENT: CMD 'state'"],
    )
    assert result.notes == ()


def test_notes_are_not_gathered_when_nothing_was_rejected():
    """A stale route error from a previous rekey must not be paired with a clean comparison."""
    result = report(
        _reply("route 10.20.0.0 255.255.0.0"),
        _installed("10.20.0.0/16"),
        log_lines=["ERROR: Linux route add command failed"],
    )
    assert result.notes == ()


def test_repeated_errors_are_listed_once_and_capped():
    lines = [f"ERROR: Linux route add command failed: attempt {n}" for n in range(9)]
    result = report(_reply("route 192.168.30.0 255.255.255.0"), _installed("10.20.0.0/16"), lines)
    assert len(result.notes) == 5
    assert result.notes[-1].endswith("attempt 8")


def test_a_duplicate_error_line_is_not_repeated():
    line = "ERROR: Linux route add command failed"
    result = report(
        _reply("route 192.168.30.0 255.255.255.0"), _installed("10.20.0.0/16"), [line, line]
    )
    assert result.notes == (line,)


# -- serialisation ---------------------------------------------------------


def test_the_report_serialises_the_shape_the_page_reads():
    result = report(
        _reply("route 192.168.30.0 255.255.255.0 vpn_gateway 500", "route 10.20.0.0 255.255.0.0"),
        _installed("10.20.0.0/16"),
    )
    assert result.to_dict() == {
        "seen": True,
        "count": 2,
        "wholesale": False,
        "rejected": [
            {
                "option": "route 192.168.30.0 255.255.255.0 vpn_gateway 500",
                "destination": "192.168.30.0/24",
                "gateway": "vpn_gateway",
                "metric": 500,
                "catch_all": False,
                "readable": True,
                "addresses": 256,
            }
        ],
        "notes": [],
    }


def test_the_empty_report_serialises_without_a_none_anywhere():
    assert PushReport().to_dict() == {
        "seen": False,
        "count": 0,
        "wholesale": False,
        "rejected": [],
        "notes": [],
    }
