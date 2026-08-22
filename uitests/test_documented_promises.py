"""Scenarios for the promises the documentation makes about this page.

Every test here defends a sentence somebody can read in README.md, USAGE.md or a module
docstring. That is the whole selection rule, and it is what makes the suite maintainable: when
one of these fails, the question is never "is this test worth keeping" but "which documented
claim am I about to make untrue". Change the behaviour deliberately and the failure tells you
which paragraph to rewrite in the same pull request.

The gap they cover is real. app/static/js/app.js is over 1500 lines and the Python suite passes
straight through every one of them, because it stops at the JSON. PR #16 was a user-visible bug
in exactly that blind spot: /api/dns had been returning the right four rules the entire time, and
the badge simply never asked.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from uitests.steps import (
    given_a_signed_in_operator,
    given_the_panel_is_shut,
    then_the_badge_is_hidden,
    then_the_badge_reads,
    then_the_page_asked_for,
    then_the_panel_is_open,
    then_the_panel_is_still_shut,
    when_the_first_status_poll_settles,
    when_the_operator_opens,
    when_the_operator_reloads,
    when_the_operator_selects_the_profile,
    while_watching_for,
)

# --- 1.1 counts are readable with every panel shut --------------------------


def test_the_counts_are_readable_with_every_panel_still_shut(page, app_instance):
    """USAGE.md: "the count next to the panel title ... is visible with the panel still collapsed".

    This is the PR #16 regression. The DNS badge sat at its placeholder until somebody opened the
    panel, which made a real number look like a missing one -- while the routes and scope badges
    beside it were right all along, because syncRoutes() refreshes those on the status poll.
    """
    given_a_signed_in_operator(page, app_instance)
    given_the_panel_is_shut(page, "routes")
    given_the_panel_is_shut(page, "dns")
    given_the_panel_is_shut(page, "scope")

    when_the_first_status_poll_settles(page)

    then_the_badge_reads(page, "routes-count", "8 via tun0")
    then_the_badge_reads(page, "dns-count", "4 rules")
    # The scope badge is styled uppercase, so its rendered text is a CSS decision rather than a
    # fact. The mode behind it is the fact.
    expect(page.locator("#scope-mode")).to_have_attribute("data-mode", "split")

    then_the_panel_is_still_shut(page, "routes")
    then_the_panel_is_still_shut(page, "dns")
    then_the_panel_is_still_shut(page, "scope")


# --- 1.2 a closed panel costs nothing ---------------------------------------


def test_a_closed_traffic_panel_polls_for_nothing(page, api_calls, app_instance):
    """README/app.js: "Closed, this costs nothing at all -- which is why the series is not folded
    into /api/status."

    The claim is about absence over time, which is the one thing web-first assertions cannot
    express: there is no state to retry towards. So this waits out a full idle poll interval
    (5s) with room to spare and then asserts nothing was fetched.
    """
    given_a_signed_in_operator(page, app_instance)
    given_the_panel_is_shut(page, "traffic")
    when_the_first_status_poll_settles(page)

    page.wait_for_timeout(6_500)  # IDLE_POLL is 5000ms; one tick would have fired by now
    then_the_page_asked_for(api_calls, "traffic", times=0)

    # And now it does -- immediately on opening, not on the next tick.
    with while_watching_for(page, "traffic"):
        when_the_operator_opens(page, "traffic")

    expect(page.locator("#traffic-chart path").first).to_be_visible()
    then_the_page_asked_for(api_calls, "traffic", times=1)


# --- 1.3 the resolver check runs only when somebody is looking --------------


def test_the_rule_count_does_not_drag_the_resolver_check_along_with_it(
    page, api_calls, app_instance
):
    """api.py: /api/dns/status is "kept out of /api/dns so that listing the rules stays a pure
    database read", and is fetched at "three moments the answer can differ" -- when the panel
    opens, after a rule changes, and when the tunnel changes state.

    A shut panel is none of those except the last, so booting must cost exactly one status call:
    the tunnel-state one. The fix for PR #16 fetches the rules for the badge and deliberately
    opts out of the verdict, because nobody is looking at it yet -- and that endpoint shells out
    to resolvectl.
    """
    given_a_signed_in_operator(page, app_instance)
    given_the_panel_is_shut(page, "dns")
    when_the_first_status_poll_settles(page)
    then_the_badge_reads(page, "dns-count", "4 rules")

    then_the_page_asked_for(api_calls, "dns", times=1)
    then_the_page_asked_for(api_calls, "dns/status", times=1)

    # Opening it is one of the three moments, so now the verdict is worth having. Judged on the
    # request going out, not on the headline: the headline is already filled in from the call
    # above, so the DOM would agree before anything had been re-fetched.
    with while_watching_for(page, "dns/status"):
        when_the_operator_opens(page, "dns")

    then_the_page_asked_for(api_calls, "dns/status", times=2)


# --- 1.4 MFA is per-profile, and the profile decides ------------------------


def test_the_code_box_follows_the_profile_not_a_setting(page, app_instance):
    """README: "MFA is per-profile, and the profile decides." A static-challenge line in the .ovpn
    is OpenVPN's own statement that the server will ask for a second field.

    Asserted server-side already; this is the half nobody could see. A hidden field that keeps
    `required` is the specific trap -- the browser then refuses to submit a form while giving the
    user nothing to fix.
    """
    given_a_signed_in_operator(page, app_instance)

    when_the_operator_selects_the_profile(page, "acme-vpn")
    expect(page.locator("#otp-field")).to_be_visible()
    expect(page.locator("#otp")).to_have_js_property("required", True)
    expect(page.locator("#otp-label")).to_have_text("Enter Authenticator Code")

    when_the_operator_selects_the_profile(page, "home-lab")
    expect(page.locator("#otp-field")).to_be_hidden()
    expect(page.locator("#otp")).to_have_js_property("required", False)
    expect(page.locator("#connect-hint")).to_contain_text("asks for no authenticator code")


# --- 1.5 panels remember themselves -----------------------------------------


def test_a_panel_left_open_comes_back_open_and_filled(page, app_instance):
    """app.js: "A panel restored open by the code above never fires shown.bs.collapse, so it
    would sit empty until something else happened to refresh it."

    Two claims in one reload, and the second is the one with a bug in it waiting to happen: the
    panel being open again is worth nothing if its table still says "Loading…".
    """
    given_a_signed_in_operator(page, app_instance)
    given_the_panel_is_shut(page, "dns")

    when_the_operator_opens(page, "dns")
    expect(page.locator("#dns-domain-body tr td").first).to_have_text("acme.example")

    when_the_operator_reloads(page)

    then_the_panel_is_open(page, "dns")
    expect(page.locator("#dns-domain-body tr td").first).to_have_text("acme.example")


# --- 1.6 / 1.7 rejected routes ----------------------------------------------


def test_routes_the_server_asked_for_and_did_not_get_are_counted_before_you_look(
    page, app_instance
):
    """USAGE.md: "The whole block is hidden when there is nothing wrong, and the count next to the
    panel title -- 3 not installed -- is visible with the panel still collapsed."

    The seeded tunnel is pushed nine routes and installs six, which is the shape this panel
    exists for: the tunnel connects, the status is green, and three internal ranges are quietly
    unreachable.
    """
    given_a_signed_in_operator(page, app_instance)
    given_the_panel_is_shut(page, "routes")
    when_the_first_status_poll_settles(page)

    then_the_badge_reads(page, "routes-rejected-count", "3 not installed")
    then_the_panel_is_still_shut(page, "routes")

    when_the_operator_opens(page, "routes")

    expect(page.locator("#routes-rejected")).to_be_visible()
    expect(page.locator("#routes-rejected-body tr")).to_have_count(3)
    expect(page.locator("#routes-rejected-body")).to_contain_text("10.60.0.0/16")
    expect(page.locator("#routes-rejected-body")).to_contain_text("172.31.12.0/22")
    expect(page.locator("#routes-rejected-body")).to_contain_text("192.168.30.0/24")


@pytest.fixture
def every_pushed_route_installed(app_instance):
    """Pose the machine so the routing table holds everything the server asked for."""
    from app.services.routing import Route

    controller = app_instance.controller
    original = list(controller.route_list)
    controller.route_list = original + [
        Route("192.168.30.0/24", "10.20.30.1", "tun0", 101),
        Route("172.31.12.0/22", "10.20.30.1", "tun0", 101),
        Route("10.60.0.0/16", "10.20.30.1", "tun0", 500),
    ]
    yield
    controller.route_list = original


def test_nothing_rejected_says_nothing_at_all(page, app_instance, every_pushed_route_installed):
    """pushed.py is honest by refusal: an empty comparison is never reported as a clean bill of
    health, and a block with nothing in it is not shown at all.

    The inverse of the test above, and the one that matters more -- a panel that cried wolf on a
    healthy tunnel would be worse than no panel.
    """
    given_a_signed_in_operator(page, app_instance)
    when_the_first_status_poll_settles(page)

    then_the_badge_is_hidden(page, "routes-rejected-count")

    when_the_operator_opens(page, "routes")

    expect(page.locator("#routes-rejected")).to_be_hidden()
    expect(page.locator("#routes-body tr")).to_have_count(11)
