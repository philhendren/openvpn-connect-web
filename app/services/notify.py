"""Notification policy: what the three messages are called, and what counts as valid text.

Persistence lives in :mod:`app.services.store`; this module holds only the rules, so the
titles, the placeholder list and the body sanitiser have one home and no dependency on where
the settings happen to be kept.
"""

from __future__ import annotations

import re

#: ntfy topic names are ASCII letters, digits, '-' and '_'. The topic is a URL path segment, so
#: this keeps it unambiguous without escaping.
TOPIC = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: Used when no server is configured -- the public ntfy instance.
DEFAULT_SERVER = "https://ntfy.sh"


class NotifyError(ValueError):
    """Raised when a topic is malformed."""


# --- the three messages ----------------------------------------------------
#
# Only the *body* is configurable. Titles are fixed: they are what makes a push scannable on a
# lock screen, and because the ntfy title is sent as an HTTP header, keeping it out of editable
# text removes header injection as a concern rather than leaving it to be sanitised.

#: The three occasions we notify on. ``down_manual`` and ``down_severed`` are told apart by the
#: controller, which knows whether the shutdown came from disconnect().
MESSAGE_KINDS = ("up", "down_manual", "down_severed")

TITLES: dict[str, str] = {
    "up": "VPN connected",
    "down_manual": "VPN disconnected",
    "down_severed": "VPN dropped",
}

DEFAULT_BODIES: dict[str, str] = {
    "up": "Tunnel is up on {ip}.",
    "down_manual": "You disconnected the tunnel. It was up for {duration}.",
    "down_severed": (
        "The tunnel went down on its own after {duration}. "
        "If that is about 24h it is the concentrator timeout -- reconnect when you can."
    ),
}

#: Placeholders the notifier substitutes. Documented here because the UI lists them.
PLACEHOLDERS = ("{ip}", "{server}", "{duration}", "{time}")

BODY_LIMIT = 500

#: C0 controls minus tab, newline and carriage return; the last two are normalised separately so
#: a body may span lines.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_body(value: object) -> str:
    """Strip control characters, normalise newlines and cap the length."""
    text = _CONTROL.sub("", str(value if value is not None else ""))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()[:BODY_LIMIT]


def validate_topic(topic: str) -> str:
    """Return the cleaned topic, or raise. An empty topic means notifications are off."""
    topic = (topic or "").strip()
    if topic and not TOPIC.match(topic):
        raise NotifyError(
            "A topic may only contain letters, digits, '-' and '_', up to 64 characters."
        )
    return topic
