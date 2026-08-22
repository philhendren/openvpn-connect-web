"""The vocabulary the scenarios are written in.

Every step here is web-first: it asserts through Playwright's ``expect``, which retries until the
condition holds or the timeout expires. There are no ``wait_for_timeout`` sleeps except the one
place a scenario is about something *not* happening over a period, which cannot be expressed any
other way and is commented where it appears.
"""

from __future__ import annotations

import re

from playwright.sync_api import expect

from tools.screenshots import PASSWORD

#: Bootstrap leaves other classes on a panel (`collapse panel-body`) and adds `collapsing`
#: mid-animation, so membership is the question -- never equality with the whole attribute.
SHOWN = re.compile(r"\bshow\b")


# --- given -----------------------------------------------------------------


def given_a_signed_in_operator(page, app_instance) -> None:
    page.goto(f"{app_instance.url}/login")
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    expect(page.locator("#status-card")).to_be_visible()


def given_the_panel_is_shut(page, panel: str) -> None:
    expect(page.locator(f"#panel-{panel}")).not_to_have_class(SHOWN)


# --- when ------------------------------------------------------------------


def when_the_first_status_poll_settles(page) -> None:
    """The routes badge leaving its placeholder is the page's own signal that a poll landed."""
    expect(page.locator("#routes-count")).not_to_have_text("—")


def when_the_operator_opens(page, panel: str) -> None:
    page.click(f"[data-bs-target='#panel-{panel}']")
    expect(page.locator(f"#panel-{panel}")).to_have_class(SHOWN)


def when_the_operator_reloads(page) -> None:
    page.reload()
    expect(page.locator("#status-card")).to_be_visible()


def when_the_operator_selects_the_profile(page, name: str) -> None:
    page.select_option("#profile", name)


# --- then ------------------------------------------------------------------


def then_the_badge_reads(page, badge: str, text: str) -> None:
    """Visible *and* correct, in that order.

    to_have_text() alone would not do it: it reads textContent, which a hidden element still
    has. A badge carrying the right number behind `hidden` passes that check while showing the
    reader nothing, which is the exact failure these scenarios exist to catch."""
    badge_locator = page.locator(f"#{badge}")
    expect(badge_locator).to_be_visible()
    expect(badge_locator).to_have_text(text)


def then_the_badge_is_hidden(page, badge: str) -> None:
    expect(page.locator(f"#{badge}")).to_be_hidden()


def then_the_panel_is_still_shut(page, panel: str) -> None:
    expect(page.locator(f"#panel-{panel}")).not_to_have_class(SHOWN)


def then_the_panel_is_open(page, panel: str) -> None:
    expect(page.locator(f"#panel-{panel}")).to_have_class(SHOWN)


def then_the_page_asked_for(calls: list[str], path: str, times: int) -> None:
    actual = [call for call in calls if call == path]
    assert len(actual) == times, (
        f"expected /api/{path} to be fetched {times}x, saw {len(actual)}; all calls: {calls}"
    )


def while_watching_for(page, path: str):
    """Context manager that holds the step open until the request actually goes out.

    Needed wherever a step is judged by a *request* rather than by something on the page: the
    rendered result may already look right from an earlier fetch, so waiting on the DOM would
    pass before the new request had left. See the DNS verdict scenario, where the headline is
    already populated by the boot-time call.
    """
    return page.expect_request(f"**/api/{path}")
