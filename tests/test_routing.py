"""Parsing the kernel routing table into the rows the UI shows."""

from __future__ import annotations

import json
import subprocess

from app.services.routing import BYPASS, ON_LINK, TUNNEL, Route, parse_routes, read_routes
from tests.conftest import ROUTE_JSON, FakeRunner


def _destinations(routes: list[Route]) -> list[str]:
    return [route.destination for route in routes]


def test_only_the_tunnel_device_is_listed():
    routes = parse_routes(ROUTE_JSON, device="tun0")
    assert _destinations(routes) == [
        "5.20.0.0/14",
        "10.100.0.0/18",
        "14.70.228.6",
        "10.99.0.0/23",
    ]


def test_unrelated_local_routes_are_dropped():
    """The default route, docker0 and the LAN must never appear -- they are not VPN routes."""
    routes = parse_routes(ROUTE_JSON, device="tun0")
    assert "default" not in _destinations(routes)
    assert "172.17.0.0/16" not in _destinations(routes)


def test_routes_are_sorted_by_address_not_by_string():
    routes = parse_routes(ROUTE_JSON, device="tun0")
    tunnel = [r for r in routes if r.kind == TUNNEL]
    # "10.x" sorts before "14.x" numerically but after it as a string.
    assert _destinations(tunnel) == ["5.20.0.0/14", "10.100.0.0/18", "14.70.228.6"]


def test_the_tunnel_subnet_is_marked_on_link():
    routes = parse_routes(ROUTE_JSON, device="tun0")
    on_link = [r for r in routes if r.kind == ON_LINK]
    assert [r.destination for r in on_link] == ["10.99.0.0/23"]
    assert on_link[0].gateway is None


def test_the_server_bypass_route_is_included_when_the_remote_is_known():
    routes = parse_routes(ROUTE_JSON, device="tun0", remote_ip="14.75.69.22")
    bypass = [r for r in routes if r.kind == BYPASS]
    assert [(r.destination, r.device) for r in bypass] == [("14.75.69.22", "eno1")]
    assert routes[-1].kind == BYPASS  # always last, whatever its address


def test_the_bypass_route_is_omitted_when_the_remote_is_unknown():
    routes = parse_routes(ROUTE_JSON, device="tun0", remote_ip=None)
    assert all(route.kind != BYPASS for route in routes)
    assert "14.75.69.22" not in _destinations(routes)


def test_a_different_device_yields_nothing():
    assert parse_routes(ROUTE_JSON, device="tun9") == []


def test_prefix_size_is_reported():
    routes = {r.destination: r for r in parse_routes(ROUTE_JSON, device="tun0")}
    assert routes["5.20.0.0/14"].addresses == 262144
    assert routes["14.70.228.6"].addresses == 1  # a host route has no prefix in ip's output
    assert routes["10.99.0.0/23"].addresses == 512


def test_a_default_route_is_understood():
    payload = json.dumps([{"dst": "default", "gateway": "10.8.0.1", "dev": "tun0"}])
    (route,) = parse_routes(payload, device="tun0")
    assert route.addresses == 2**32
    assert route.to_dict()["destination"] == "default"


def test_missing_metric_and_gateway_serialise_as_null():
    payload = json.dumps([{"dst": "10.0.0.0/8", "dev": "tun0"}])
    (route,) = parse_routes(payload, device="tun0")
    assert route.to_dict() == {
        "destination": "10.0.0.0/8",
        "gateway": None,
        "device": "tun0",
        "metric": None,
        "kind": ON_LINK,
        "addresses": 16777216,
        "public": False,
    }


def test_malformed_output_is_survivable():
    assert parse_routes("not json", device="tun0") == []
    assert parse_routes("", device="tun0") == []
    assert parse_routes('{"dst": "10.0.0.0/8"}', device="tun0") == []  # object, not a list
    assert parse_routes('["nonsense", {"dev": "tun0"}]', device="tun0") == []


def test_public_ranges_are_flagged_and_private_ones_are_not():
    """5.20.0.0/14 and the host route are real public (AWS/Azure-style) allocations; the rest of
    the split tunnel -- the pushed corporate range and its own subnet -- is RFC 1918."""
    routes = {r.destination: r for r in parse_routes(ROUTE_JSON, device="tun0")}
    assert routes["5.20.0.0/14"].public is True
    assert routes["14.70.228.6"].public is True
    assert routes["10.100.0.0/18"].public is False
    assert routes["10.99.0.0/23"].public is False


def test_a_default_route_is_not_flagged_public():
    """A default route covers everything, private or not -- it is not a registry block."""
    payload = json.dumps([{"dst": "default", "gateway": "10.8.0.1", "dev": "tun0"}])
    (route,) = parse_routes(payload, device="tun0")
    assert route.public is False


def test_an_unparseable_destination_does_not_crash_the_sort():
    payload = json.dumps(
        [
            {"dst": "garbage", "dev": "tun0", "gateway": "10.8.0.1"},
            {"dst": "10.0.0.0/8", "dev": "tun0"},
        ]
    )
    routes = parse_routes(payload, device="tun0")
    assert "garbage" in _destinations(routes)
    assert next(r for r in routes if r.destination == "garbage").addresses is None


def test_read_routes_asks_ip_for_json_and_never_uses_a_shell():
    runner = FakeRunner()
    read_routes(runner, device="tun0")
    assert runner.calls == [["ip", "-json", "-4", "route", "show"]]


def test_read_routes_returns_empty_when_ip_fails():
    runner = FakeRunner()
    runner.side_effect = FileNotFoundError("no ip binary")
    assert read_routes(runner, device="tun0") == []


def test_read_routes_returns_empty_on_a_nonzero_exit():
    def runner(argv, **kwargs):
        class Result:
            returncode = 2
            stdout = ""
            stderr = 'Cannot find device "tun0"'

        return Result()

    assert read_routes(runner, device="tun0") == []


def test_read_routes_survives_a_timeout():
    runner = FakeRunner()
    runner.side_effect = subprocess.TimeoutExpired(["ip"], 5)
    assert read_routes(runner, device="tun0") == []
