"""Sending to ntfy. The opener is always faked -- no test may reach the network."""

from __future__ import annotations

import urllib.error

import pytest

from app.services import store
from app.services.notifications import (
    Notifier,
    NotifyContext,
    NotifyDeliveryError,
    format_duration,
    render,
)


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False


class FakeOpener:
    """Stands in for urllib.request.urlopen; records requests, never opens a socket."""

    def __init__(self, status: int = 200, raises: Exception | None = None) -> None:
        self.requests: list = []
        self.timeouts: list[float] = []
        self.status = status
        self.raises = raises

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.raises is not None:
            raise self.raises
        return FakeResponse(self.status)

    @property
    def last(self):
        assert self.requests, "nothing was sent"
        return self.requests[-1]

    def body(self) -> str:
        return self.last.data.decode("utf-8")

    def header(self, name: str) -> str:
        return self.last.get_header(name.capitalize(), "")


def _notifier(config, opener, db=None):
    return Notifier(config, db, opener=opener)


def _wait(opener, count=1, timeout=3.0):
    """notify() sends on a daemon thread, so tests wait for the send rather than sleep."""
    from tests.conftest import wait_for

    assert wait_for(lambda: len(opener.requests) >= count, timeout=timeout), "no send happened"


# --- placeholders ----------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "0s"),
        (45, "45s"),
        (90, "1m 30s"),
        (3600, "1h 0m"),
        (86402, "24h 0m"),
        (None, "an unknown time"),
    ],
)
def test_duration_formatting(seconds, expected):
    assert format_duration(seconds) == expected


def test_placeholders_are_substituted():
    context = NotifyContext(
        tun_ip="10.0.0.2", server_ip="52.1.1.1", uptime_seconds=90, when="14:05"
    )
    rendered = render("{ip} via {server} for {duration} at {time}", context)
    assert rendered == "10.0.0.2 via 52.1.1.1 for 1m 30s at 14:05"


def test_missing_details_render_as_unknown():
    assert render("{ip}/{server}", NotifyContext()) == "unknown/unknown"


def test_unknown_braces_are_left_alone():
    """Bodies are operator text; str.format would raise on these or walk the object graph."""
    body = "literal {braces} and {a.__class__} and {} stay put"
    assert render(body, NotifyContext()) == body


# --- sending ---------------------------------------------------------------


def test_notify_posts_to_the_topic(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext(tun_ip="10.0.0.2"))
    _wait(opener)
    assert opener.last.full_url == "https://ntfy.sh/my-topic"
    assert opener.last.method == "POST"


def test_the_body_is_the_configured_message(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    store.save_notify(app_db, bodies={"up": "Tunnel up on {ip}."})
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext(tun_ip="10.0.0.2"))
    _wait(opener)
    assert opener.body() == "Tunnel up on 10.0.0.2."


def test_each_kind_carries_its_title_priority_and_tag(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    notifier = _notifier(config, opener, app_db)

    notifier.notify("down_severed", NotifyContext())
    _wait(opener)
    assert opener.header("title") == "VPN dropped"
    assert opener.header("priority") == "high"
    assert opener.header("tags") == "warning"

    notifier.notify("down_manual", NotifyContext())
    _wait(opener, 2)
    assert opener.header("title") == "VPN disconnected"
    assert opener.header("priority") == "default"


def test_an_empty_topic_sends_nothing(config, app_db):
    store.save_notify(app_db, topic="")
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext())
    assert opener.requests == []


def test_a_self_hosted_server_is_honoured(config, app_db):
    from dataclasses import replace

    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    _notifier(replace(config, NTFY_SERVER="https://ntfy.example.test/"), opener, app_db).notify(
        "up", NotifyContext()
    )
    _wait(opener)
    assert opener.last.full_url == "https://ntfy.example.test/my-topic"


def test_the_send_carries_a_timeout(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext())
    _wait(opener)
    assert opener.timeouts[-1] == config.NOTIFY_TIMEOUT_SECONDS


def test_utf8_bodies_survive(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    store.save_notify(app_db, bodies={"up": "Tunnel up ✓ £"})
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext())
    _wait(opener)
    assert opener.body() == "Tunnel up ✓ £"


# --- failures never escape -------------------------------------------------


def test_a_network_failure_is_swallowed(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener(raises=urllib.error.URLError("no route to host"))
    _notifier(config, opener, app_db).notify("up", NotifyContext())  # must not raise
    _wait(opener)


def test_a_corrupt_message_file_does_not_raise(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    store.save_notify(app_db, bodies={"up": ""})
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext())
    _wait(opener)
    assert opener.body()  # fell back to the default body


def test_an_unknown_kind_does_not_raise(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("not-a-kind", NotifyContext())
    assert opener.requests == []


# --- the test send, which is allowed to fail loudly ------------------------


def test_send_test_reports_the_url(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener()
    assert _notifier(config, opener, app_db).send_test() == "https://ntfy.sh/my-topic"
    assert "notifications are working" in opener.body()


def test_send_test_without_a_topic_explains_why(config, app_db):
    store.save_notify(app_db, topic="")
    with pytest.raises(NotifyDeliveryError, match="Set a topic first"):
        _notifier(config, FakeOpener(), app_db).send_test()


def test_send_test_surfaces_a_network_failure(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    opener = FakeOpener(raises=urllib.error.URLError("no route to host"))
    with pytest.raises(NotifyDeliveryError, match="could not reach"):
        _notifier(config, opener, app_db).send_test()


def test_send_test_surfaces_an_http_error(config, app_db):
    store.save_notify(app_db, topic="my-topic")
    error = urllib.error.HTTPError("https://ntfy.sh/my-topic", 429, "Too Many Requests", {}, None)
    with pytest.raises(NotifyDeliveryError, match="429"):
        _notifier(config, FakeOpener(raises=error), app_db).send_test()


def test_bodies_reach_the_wire_uninterpreted(config, app_db):
    """Whatever the operator typed is data all the way to the socket."""
    store.save_notify(app_db, topic="my-topic")
    hostile = "$(id) `whoami` '; rm -rf / #"
    store.save_notify(app_db, bodies={"up": hostile})
    opener = FakeOpener()
    _notifier(config, opener, app_db).notify("up", NotifyContext())
    _wait(opener)
    assert opener.body() == hostile
    assert store.notify_bodies(app_db)["up"] == hostile
