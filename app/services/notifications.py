"""Sending notifications to ntfy.

This used to live in the OpenVPN ``--up``/``--down`` hooks, which ran as root and had to be told
*why* the tunnel went down through a marker file. The app has always known why, so the sending
moved here and the marker went away with it.

Two rules shape this module:

* **A notification must never affect the tunnel.** Every send is fire-and-forget on its own
  thread, with a hard timeout, and every failure is logged rather than raised. Losing a push is
  an annoyance; failing a disconnect because a push timed out is a fault.
* **Message bodies are operator text, so they are never interpreted.** Placeholders are
  substituted by literal replacement -- not ``str.format``, which would raise on any stray brace
  in the text and would expose attribute access.
"""

from __future__ import annotations

import logging
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass

from app.services import store
from app.services.notify import TITLES

log = logging.getLogger(__name__)


class NotifyDeliveryError(RuntimeError):
    """Raised only by the synchronous test send, which reports back to the operator."""


#: ntfy's own priority scale and emoji tags, chosen per event. A drop we did not ask for is the
#: only one worth waking a phone for.
PRIORITIES = {"up": "default", "down_manual": "default", "down_severed": "high"}
TAGS = {"up": "white_check_mark", "down_manual": "wave", "down_severed": "warning"}


@dataclass(frozen=True)
class NotifyContext:
    """What the placeholders in a message body can refer to."""

    tun_ip: str | None = None
    server_ip: str | None = None
    uptime_seconds: int | None = None
    when: str = ""


def format_duration(seconds: int | None) -> str:
    """A short human duration: ``1h 12m``, ``45s``."""
    if seconds is None or seconds < 0:
        return "an unknown time"
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def render(body: str, context: NotifyContext) -> str:
    """Substitute the documented placeholders.

    Literal replacement on purpose: ``str.format`` would raise ``KeyError`` on any brace the
    operator typed for other reasons, and would let ``{a.__class__}`` walk the object graph.
    """
    replacements = {
        "{ip}": context.tun_ip or "unknown",
        "{server}": context.server_ip or "unknown",
        "{duration}": format_duration(context.uptime_seconds),
        "{time}": context.when,
    }
    for token, value in replacements.items():
        body = body.replace(token, value)
    return body


class Notifier:
    """Posts to an ntfy topic. Injectable ``opener`` so tests never touch the network."""

    def __init__(self, config, db, *, opener=None) -> None:
        self._config = config
        self._db = db
        self._opener = opener or urllib.request.urlopen

    def _url_for(self, topic: str) -> str:
        return f"{self._config.NTFY_SERVER.rstrip('/')}/{topic}"

    # -- public -----------------------------------------------------------

    def notify(self, kind: str, context: NotifyContext) -> None:
        """Send the message for ``kind`` in the background. Never raises, never blocks."""
        try:
            topic = store.notify_topic(self._db)
            if not topic:
                return
            body = render(store.notify_bodies(self._db)[kind], context)
            title = TITLES[kind]
        except Exception:  # noqa: BLE001 - a broken config must not break the tunnel
            log.exception("could not build the %s notification", kind)
            return

        thread = threading.Thread(
            target=self._send_quietly,
            args=(topic, title, body, PRIORITIES.get(kind, "default"), TAGS.get(kind, "bell")),
            name=f"vpn-notify-{kind}",
            daemon=True,
        )
        thread.start()

    def send_test(self) -> str:
        """Send a test notification synchronously and report the outcome to the operator.

        The one place a delivery failure is worth surfacing: the operator asked, and is waiting.
        """
        topic = store.notify_topic(self._db)
        if not topic:
            raise NotifyDeliveryError("Set a topic first -- notifications are currently off.")
        self._send(
            topic,
            "VPN Connect test",
            "If you can read this, notifications are working.",
            "default",
            "bell",
        )
        return self._url_for(topic)

    # -- internals --------------------------------------------------------

    def _send_quietly(self, *args: str) -> None:
        try:
            self._send(*args)
        except Exception as exc:  # noqa: BLE001 - background thread must never die noisily
            log.warning("notification not delivered: %s", exc)

    def _send(self, topic: str, title: str, body: str, priority: str, tags: str) -> None:
        url = self._url_for(topic)
        request = urllib.request.Request(  # noqa: S310 - scheme is fixed by NTFY_SERVER
            url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                # Titles are fixed ASCII constants, so they are safe in a header.
                "Title": title,
                "Priority": priority,
                "Tags": tags,
                "Content-Type": "text/plain; charset=utf-8",
            },
        )
        try:
            with self._opener(request, timeout=self._config.NOTIFY_TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    raise NotifyDeliveryError(f"{url} returned HTTP {status}")
        except urllib.error.HTTPError as exc:
            raise NotifyDeliveryError(f"{url} returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise NotifyDeliveryError(f"could not reach {url}: {exc.reason}") from exc
        except OSError as exc:
            raise NotifyDeliveryError(f"could not reach {url}: {exc}") from exc
