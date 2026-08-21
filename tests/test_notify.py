"""Notification policy: fixed titles, and what counts as valid text.

Persistence lives in the store, so those tests are in test_store.py.
"""

from __future__ import annotations

import pytest

from app.services.notify import (
    BODY_LIMIT,
    DEFAULT_BODIES,
    MESSAGE_KINDS,
    TITLES,
    NotifyError,
    clean_body,
    validate_topic,
)


def test_every_kind_has_a_title_and_a_default_body():
    assert set(TITLES) == set(MESSAGE_KINDS)
    assert set(DEFAULT_BODIES) == set(MESSAGE_KINDS)


def test_titles_are_ascii():
    """They are sent as an HTTP header, so anything else would need encoding."""
    for title in TITLES.values():
        assert title.isascii()


@pytest.mark.parametrize("topic", ["simple", "with-dash", "with_underscore", "MiXed123"])
def test_good_topics_are_accepted(topic):
    assert validate_topic(topic) == topic


def test_a_topic_is_trimmed():
    assert validate_topic("  spaced  ") == "spaced"


def test_an_empty_topic_means_notifications_are_off():
    assert validate_topic("") == ""
    assert validate_topic(None) == ""


@pytest.mark.parametrize(
    "topic",
    [
        "has space",
        "$(whoami)",
        "a;rm -rf /",
        "'; curl evil.test #",
        "back`tick`",
        "topic\nNTFY_TOPIC=evil",
        "a" * 65,
        "emoji-\U0001f389",
        "with/slash",
    ],
)
def test_bad_topics_are_refused(topic):
    """The topic becomes a URL path segment, so it stays strictly bounded."""
    with pytest.raises(NotifyError):
        validate_topic(topic)


def test_a_body_may_span_lines():
    assert clean_body("one\r\ntwo") == "one\ntwo"


def test_control_characters_are_stripped():
    assert clean_body("d\x07e\x00f") == "def"


def test_long_bodies_are_truncated():
    assert len(clean_body("b" * 5000)) == BODY_LIMIT


def test_shell_metacharacters_survive_verbatim():
    """Nothing interprets a body -- it is a POST payload, not a command."""
    hostile = "$(id) `whoami` '; rm -rf / #"
    assert clean_body(hostile) == hostile
