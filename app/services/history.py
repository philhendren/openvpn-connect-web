"""Per-attempt history: the event log, the OpenVPN log, and the byte-counter samples.

The two kinds of record are written differently, on purpose:

* **Log lines** arrive in bursts on the management dispatcher thread, so they are buffered and
  flushed in batches -- one transaction per line would put a write on the hot path of every log
  message. The buffer is flushed on any state transition, which is when a failed attempt's tail
  matters most.
* **Traffic samples** arrive one at a time on a fixed interval, so they are written through. A
  buffered sample is one the live graph cannot see, and a single insert every few seconds costs
  nothing.
"""

from __future__ import annotations

import logging
import threading
import time

from app.services import store

log = logging.getLogger(__name__)

#: Flush once this many lines are waiting, so a chatty connect does not hold them all in memory.
FLUSH_AT = 50


class History:
    """Events and per-attempt logs. Every method swallows storage failures.

    Losing a log line must never fail a connect, which is the same rule the notifier follows.
    """

    def __init__(self, db) -> None:
        self._db = db
        self._lock = threading.Lock()
        self._session_id: int | None = None
        self._pending: list[str] = []

    # -- events -----------------------------------------------------------

    def record_event(self, kind: str, reason: str = "", connection: str | None = None) -> None:
        try:
            store.record_event(self._db, kind, reason, connection)
        except Exception:  # noqa: BLE001 - history is never worth failing a tunnel operation
            log.exception("could not record the %s event", kind)

    def recent_events(self, limit: int = 10) -> list[str]:
        try:
            return store.recent_events(self._db, limit)
        except Exception:  # noqa: BLE001
            log.exception("could not read the event history")
            return []

    # -- log sessions -----------------------------------------------------

    def start_session(self, connection: str | None) -> None:
        """Begin a new attempt's log. Any unfinished previous session is closed first."""
        self.end_session("interrupted")
        try:
            session_id = store.start_log_session(self._db, connection)
        except Exception:  # noqa: BLE001
            log.exception("could not open a log session")
            return
        with self._lock:
            self._session_id = session_id
            self._pending = []
        try:
            store.prune_sessions(self._db)
        except Exception:  # noqa: BLE001
            log.exception("could not prune old log sessions")

    def append(self, line: str) -> None:
        with self._lock:
            if self._session_id is None:
                return
            self._pending.append(line)
            if len(self._pending) < FLUSH_AT:
                return
        self.flush()

    def flush(self) -> None:
        with self._lock:
            session_id, pending = self._session_id, self._pending
            self._pending = []
        if session_id is None or not pending:
            return
        try:
            store.append_lines(self._db, session_id, pending)
        except Exception:  # noqa: BLE001
            log.exception("could not write %d log lines", len(pending))

    def end_session(self, outcome: str) -> None:
        self.flush()
        with self._lock:
            session_id = self._session_id
            self._session_id = None
        if session_id is None:
            return
        try:
            store.end_log_session(self._db, session_id, outcome)
        except Exception:  # noqa: BLE001
            log.exception("could not close the log session")

    # -- traffic ----------------------------------------------------------

    def record_sample(self, bytes_in: int, bytes_out: int) -> None:
        """Store one cumulative byte-counter reading against the current attempt."""
        with self._lock:
            session_id = self._session_id
        if session_id is None:
            return
        try:
            store.record_sample(self._db, session_id, time.time(), bytes_in, bytes_out)
        except Exception:  # noqa: BLE001 - a dropped sample is never worth failing a tunnel
            log.exception("could not record a traffic sample")

    def samples(self, session_id: int) -> list[tuple[float, int, int]]:
        try:
            return store.session_samples(self._db, session_id)
        except Exception:  # noqa: BLE001
            log.exception("could not read traffic for session %s", session_id)
            return []

    # -- reading ----------------------------------------------------------

    @property
    def session_id(self) -> int | None:
        """The attempt currently being recorded, if any."""
        with self._lock:
            return self._session_id

    def recent_sessions(self, limit: int = 10) -> list[dict[str, object]]:
        try:
            return store.recent_sessions(self._db, limit)
        except Exception:  # noqa: BLE001
            log.exception("could not list log sessions")
            return []

    def session_lines(self, session_id: int, limit: int = 500) -> list[str]:
        try:
            return store.session_lines(self._db, session_id, limit)
        except Exception:  # noqa: BLE001
            log.exception("could not read log session %s", session_id)
            return []

    def last_session_lines(self, limit: int = 500) -> list[str]:
        """The most recent attempt's log, including one that failed and exited.

        This is what the in-memory ring buffer could never do: it emptied when the process died,
        which is precisely when the operator wanted to read it.
        """
        sessions = self.recent_sessions(limit=1)
        if not sessions:
            return []
        return self.session_lines(int(sessions[0]["id"]), limit)
