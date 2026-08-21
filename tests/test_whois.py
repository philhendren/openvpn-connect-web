"""Deciding what is worth a whois lookup, parsing the answer, and not hammering the server."""

from __future__ import annotations

import subprocess

import pytest

from app.services import whois
from app.services.whois import MAX_BATCH, is_public, lookup_many

#: A trimmed real ARIN response, the shape whois.arin.net returns for an AWS-style allocation.
ARIN_RESPONSE = """\
NetRange:       3.5.140.0 - 3.5.143.255
CIDR:           3.5.140.0/22
NetName:        AT-88-Z
NetHandle:      NET-3-5-140-0-1
Parent:         NET3 (NET-3-0-0-0-0)
NetType:        Direct Allocation
Organization:   Amazon.com, Inc. (AMAZO-4)
RegDate:        2021-05-05
Updated:        2021-05-05
Ref:            https://rdap.arin.net/registry/ip/3.5.140.0
"""

#: A trimmed RIPE response -- a different registry, different field names entirely.
RIPE_RESPONSE = """\
% Abuse contact for '81.2.69.0/24' is 'abuse@example.net'

inetnum:        81.2.69.0 - 81.2.69.255
netname:        EXAMPLE-NET
descr:          Example Hosting Ltd
country:        GB
"""

#: A reserved block record: real, but not an organisation -- must not be shown as one.
NOISE_RESPONSE = """\
netname:        NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK
descr:          IANA-NETBLOCK
"""


@pytest.fixture(autouse=True)
def _clear_cache():
    """Every test starts cold -- otherwise test order would leak cached lookups between them."""
    whois._cache.clear()
    yield
    whois._cache.clear()


class ScriptedRunner:
    """Replacement for subprocess.run keyed by the address it is asked to look up."""

    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        address = argv[-1]
        answer = self.answers.get(address, "")
        if isinstance(answer, Exception):
            raise answer
        stdout, returncode = answer if isinstance(answer, tuple) else (answer, 0)
        return type("R", (), {"returncode": returncode, "stdout": stdout, "stderr": ""})()


# --- what is worth looking up ------------------------------------------------


@pytest.mark.parametrize(
    "destination",
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "169.254.0.0/16", "224.0.0.0/4"],
)
def test_private_and_reserved_ranges_are_not_public(destination):
    assert is_public(destination) is False


@pytest.mark.parametrize("destination", ["3.5.140.0/22", "52.94.0.0/22", "8.8.8.8"])
def test_registry_allocated_blocks_are_public(destination):
    assert is_public(destination) is True


def test_a_default_route_is_not_worth_looking_up():
    """It covers everything -- not a registry-delegated block, and scope.py already explains it."""
    assert is_public("default") is False


def test_the_redirect_gateway_halves_are_not_worth_looking_up():
    assert is_public("0.0.0.0/1") is False
    assert is_public("128.0.0.0/1") is False


def test_garbage_is_not_public():
    assert is_public("not-an-address") is False


# --- parsing ------------------------------------------------------------------


def test_an_arin_response_yields_the_organization():
    runner = ScriptedRunner({"3.5.140.0": ARIN_RESPONSE})
    (result,) = lookup_many(["3.5.140.0/22"], runner=runner)
    assert result.destination == "3.5.140.0/22"
    assert result.org == "Amazon.com, Inc. (AMAZO-4)"


def test_a_ripe_response_falls_back_to_descr():
    """RIPE records rarely carry an org-name -- descr is the useful field there."""
    runner = ScriptedRunner({"81.2.69.0": RIPE_RESPONSE})
    (result,) = lookup_many(["81.2.69.0/24"], runner=runner)
    assert result.org == "Example Hosting Ltd"


def test_placeholder_records_yield_nothing_useful():
    """192.0.2.0/24 is TEST-NET-1, which ``is_private`` would filter -- go through ``_query``
    directly so the parser itself, not the public-address filter, is what is under test."""
    runner = ScriptedRunner({"192.0.2.0": NOISE_RESPONSE})
    assert whois._query("192.0.2.0/32", runner=runner) is None


def test_a_response_with_nothing_recognisable_yields_none():
    runner = ScriptedRunner({"8.8.8.8": "% no match found\n"})
    (result,) = lookup_many(["8.8.8.8"], runner=runner)
    assert result.org is None


# --- resilience -----------------------------------------------------------


def test_a_missing_whois_binary_does_not_raise():
    runner = ScriptedRunner({"8.8.8.8": FileNotFoundError("no whois")})
    (result,) = lookup_many(["8.8.8.8"], runner=runner)
    assert result.org is None


def test_a_timeout_does_not_raise():
    runner = ScriptedRunner({"8.8.8.8": subprocess.TimeoutExpired(["whois"], 5)})
    (result,) = lookup_many(["8.8.8.8"], runner=runner)
    assert result.org is None


def test_a_nonzero_exit_yields_none():
    runner = ScriptedRunner({"8.8.8.8": (ARIN_RESPONSE, 1)})
    (result,) = lookup_many(["8.8.8.8"], runner=runner)
    assert result.org is None


# --- batching, dedup and caching ----------------------------------------------


def test_private_destinations_are_dropped_before_any_lookup():
    runner = ScriptedRunner({})
    assert lookup_many(["10.0.0.0/8", "172.16.0.0/12"], runner=runner) == []
    assert runner.calls == []


def test_duplicate_destinations_are_resolved_once():
    runner = ScriptedRunner({"3.5.140.0": ARIN_RESPONSE})
    results = lookup_many(["3.5.140.0/22", "3.5.140.0/22"], runner=runner)
    assert len(results) == 1
    assert runner.calls == [["whois", "3.5.140.0"]]


def test_a_repeat_lookup_is_served_from_cache():
    runner = ScriptedRunner({"3.5.140.0": ARIN_RESPONSE})
    lookup_many(["3.5.140.0/22"], runner=runner)
    lookup_many(["3.5.140.0/22"], runner=runner)
    assert len(runner.calls) == 1  # the second call never touched the network


def test_a_failed_lookup_is_also_cached_so_it_is_not_retried_within_the_same_batch():
    runner = ScriptedRunner({"3.5.140.0": FileNotFoundError("no whois")})
    lookup_many(["3.5.140.0/22"], runner=runner)
    assert len(runner.calls) == 1
    lookup_many(["3.5.140.0/22"], runner=runner)
    assert len(runner.calls) == 1  # still cached, even though it was a miss


def test_a_batch_is_capped_so_a_huge_routes_table_cannot_open_hundreds_of_sockets():
    destinations = [f"5.{i}.0.0/16" for i in range(MAX_BATCH + 10)]
    runner = ScriptedRunner({})
    results = lookup_many(destinations, runner=runner)
    assert len(results) == MAX_BATCH
    assert len(runner.calls) == MAX_BATCH


def test_looking_up_nothing_never_touches_the_runner():
    runner = ScriptedRunner({})
    assert lookup_many([], runner=runner) == []
    assert runner.calls == []
