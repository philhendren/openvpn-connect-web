"""Fixtures for the browser tests: one seeded instance, one browser, a fresh page per test.

Deliberately not under ``tests/``. ``uv run pytest`` is ten seconds and pyproject.toml says out
loud that it must stay that way; these need a browser and take about a minute. They are also
excluded from ``testpaths``, so the ordinary suite never sees them.

    uv run --group ui pytest uitests/

The instance is the one ``tools/screenshots.py`` builds -- real templates, real CSS, real
JavaScript, real endpoints, a stub only where the machine would be -- so these tests drive the
same world the documentation is photographed from.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.screenshots import instance, serve  # noqa: E402

#: System Chrome by default, which is what a developer already has and what the screenshots are
#: taken with. CI sets this empty to get Playwright's own Chromium instead: that one is pinned by
#: the playwright version in uv.lock, so it moves when the lockfile moves and never otherwise.
CHANNEL = os.environ.get("VPN_UI_CHANNEL", "chrome") or None


def _free_port() -> int:
    """Ask the OS for one, rather than colliding with a screenshot server someone left running."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass(frozen=True)
class Instance:
    url: str
    app: object

    @property
    def controller(self):
        """The stub standing in for the machine. Tests may pose it; see ``posed_routes``."""
        return self.app.config["CONTROLLER"]


@pytest.fixture(scope="session")
def app_instance():
    tmp = Path(tempfile.mkdtemp(prefix="vpn-connect-uitests-"))
    try:
        app = instance(tmp)
        port = _free_port()
        serve(app, port=port)
        yield Instance(url=f"http://127.0.0.1:{port}", app=app)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        browser = driver.chromium.launch(channel=CHANNEL)
        yield browser
        browser.close()


#: Where a failed scenario leaves its evidence. Gitignored; the workflow uploads it.
ARTIFACTS = Path(__file__).resolve().parent / "artifacts"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Stash each phase's result on the item, so a fixture's teardown can see what happened.

    pytest tells fixtures nothing about whether their test passed. Without this the trace below
    would have to be written for every run and thrown away, which on a suite that is mostly green
    is a lot of megabytes to produce in order to delete.
    """
    outcome = yield
    setattr(item, f"report_{call.when}", outcome.get_result())


@pytest.fixture
def page(browser, request):
    """A fresh context per test, so one test's remembered panels cannot reach another's.

    Traced throughout, but the trace is only written out for a failure. A red browser test whose
    only evidence is a stack trace is one people re-run rather than read: the trace holds the DOM
    at each step, the network log and a screenshot, and opens with `playwright show-trace`.
    """
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(10_000)

    yield page

    failed = any(
        getattr(getattr(request.node, f"report_{phase}", None), "failed", False)
        for phase in ("setup", "call")
    )
    if failed:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        stem = request.node.name
        context.tracing.stop(path=ARTIFACTS / f"{stem}.zip")
        page.screenshot(path=ARTIFACTS / f"{stem}.png", full_page=True)
    else:
        context.tracing.stop()
    context.close()


@pytest.fixture
def api_calls(page):
    """Every /api/ path the page asks for, in order. The evidence for "and nothing else"."""
    calls: list[str] = []

    def record(request) -> None:
        marker = "/api/"
        if marker in request.url:
            calls.append(request.url.split(marker, 1)[1].split("?", 1)[0])

    page.on("request", record)
    return calls
