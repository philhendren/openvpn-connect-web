"""Reading a week of connection attempts back: shaping them, searching them, summing them up.

Pure functions over rows that :mod:`app.services.store` has already fetched, in the same spirit
as :mod:`app.services.traffic`: nothing here opens a database, a socket or a subprocess, so the
part of the feature with all the judgement in it -- what counts as a drop, what counts as time
connected -- is also the part that is trivial to be sure about.

The judgement worth stating: **a drop and a failure are different events**, and lumping them
together is what makes a reliability number useless. A tunnel that was cut off after nine hours
says something about the concentrator; an attempt that never got past the credential prompt says
something about the code you typed. Both are recorded at the moment they happen (see migration
0006), so this module classifies rather than guesses.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime

#: Sessions per page. The panel pages by *session*, never by date: "the last twenty-five attempts"
#: is a question with an answer, where "the last two days" on a machine that was off for both is
#: a question with an empty one.
DEFAULT_LIMIT = 25
MAX_LIMIT = 200

#: How an attempt ended, in the words the panel uses. ``DROPPED`` and ``MANUAL`` are the pair the
#: whole panel exists to separate; the controller already tells them apart to choose between its
#: two notifications, and migration 0006 keeps that verdict instead of discarding it.
LIVE = "live"
DROPPED = "dropped"
MANUAL = "disconnected"
FAILED = "failed"
INTERRUPTED = "interrupted"
ENDED = "ended"

#: The controller's words for why a tunnel went down, as stored in ``log_sessions.reason``.
REASON_MANUAL = "operator-requested"
REASON_SEVERED = "link-lost"


def _moment(value: object) -> datetime | None:
    """Parse one stored timestamp, or give up quietly.

    Rows are written by ``store._now()``, so the format is known -- but a database that has been
    edited by hand should make the history slightly less informative, not five hundred.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # Everything stored carries an offset, but a value that somehow does not is local time by
    # definition here -- and comparing a naive datetime with an aware one raises rather than
    # returning a wrong answer, so normalising is the difference between one odd row and none.
    return parsed if parsed.tzinfo is not None else parsed.astimezone()


def _elapsed(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return max(0.0, (end - start).total_seconds())


@dataclass(frozen=True)
class Session:
    """One connection attempt, as the history panel needs to show it."""

    id: int
    connection: str | None
    started_at: str | None
    connected_at: str | None
    ended_at: str | None
    outcome: str
    reason: str
    lines: int
    bytes_in: int
    bytes_out: int
    live: bool
    kind: str
    duration_seconds: float | None
    up_seconds: float | None

    @property
    def connected(self) -> bool:
        """Did this attempt ever come up? A stored fact, not an inference from side effects."""
        return self.connected_at is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "connection": self.connection,
            "started_at": self.started_at,
            "connected_at": self.connected_at,
            "ended_at": self.ended_at,
            "outcome": self.outcome,
            "reason": self.reason,
            "lines": self.lines,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "live": self.live,
            "kind": self.kind,
            "connected": self.connected,
            "duration_seconds": _round(self.duration_seconds),
            "up_seconds": _round(self.up_seconds),
        }


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 1)


def _kind(*, live: bool, ended: bool, connected: bool, outcome: str, reason: str) -> str:
    if live:
        return LIVE
    if reason == REASON_SEVERED:
        return DROPPED
    if reason == REASON_MANUAL:
        return MANUAL
    if not ended:
        # No end time and not the attempt running now: the app stopped without closing it, which
        # is what a restart mid-tunnel looks like from here.
        return INTERRUPTED
    if outcome == INTERRUPTED:
        return INTERRUPTED
    if not connected:
        return FAILED
    return ENDED


def from_row(row: dict[str, object], *, live: bool = False, now: datetime | None = None) -> Session:
    """Turn one stored row into a session, filling in what only a clock can answer."""
    moment = now or datetime.now().astimezone()
    started = _moment(row.get("started_at"))
    connected = _moment(row.get("connected_at"))
    ended = _moment(row.get("ended_at"))
    outcome = str(row.get("outcome") or "")
    reason = str(row.get("reason") or "")
    return Session(
        id=int(row["id"]),
        connection=row.get("connection") or None,  # type: ignore[arg-type]
        started_at=row.get("started_at") or None,  # type: ignore[arg-type]
        connected_at=row.get("connected_at") or None,  # type: ignore[arg-type]
        ended_at=row.get("ended_at") or None,  # type: ignore[arg-type]
        outcome=outcome,
        reason=reason,
        lines=int(row.get("lines") or 0),
        bytes_in=int(row.get("bytes_in") or 0),
        bytes_out=int(row.get("bytes_out") or 0),
        live=live,
        kind=_kind(
            live=live,
            ended=ended is not None,
            connected=connected is not None,
            outcome=outcome,
            reason=reason,
        ),
        # An attempt that has not ended is still running its clock, so both spans measure to
        # *now* rather than reporting nothing at all for the session you are sitting in.
        duration_seconds=_elapsed(started, ended or moment),
        up_seconds=_elapsed(connected, ended or moment),
    )


def from_rows(
    rows: list[dict[str, object]], *, live_id: int | None = None, now: datetime | None = None
) -> list[Session]:
    moment = now or datetime.now().astimezone()
    return [from_row(row, live=int(row["id"]) == live_id, now=moment) for row in rows]


def matches(session: Session, query: str) -> bool:
    """Does this session match a search?

    Every whitespace-separated term has to hit, so ``dropped client`` narrows rather than widens.
    The haystack is what someone can see in the row -- its number, the connection, how it ended --
    because a search that matched hidden fields would look broken from the outside.
    """
    haystack = " ".join(
        part.lower()
        for part in (
            f"#{session.id}",
            str(session.id),
            session.connection or "",
            session.kind,
            session.outcome,
            session.reason,
        )
        if part
    )
    return all(term in haystack for term in query.lower().split())


def search(sessions: list[Session], query: str) -> list[Session]:
    query = (query or "").strip()
    if not query:
        return list(sessions)
    return [session for session in sessions if matches(session, query)]


def page(
    sessions: list[Session], *, before: int | None = None, limit: int = DEFAULT_LIMIT
) -> tuple[list[Session], int | None]:
    """One page of sessions, newest first, plus the cursor for the page after it.

    The cursor is a session id rather than an offset or a timestamp: rows can be swept away by
    retention between one request and the next, and an offset would silently skip a session when
    that happened.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    remaining = [s for s in sessions if before is None or s.id < before]
    window = remaining[:limit]
    following = remaining[limit:]
    return window, (window[-1].id if following else None)


@dataclass(frozen=True)
class Summary:
    """What the retained sessions add up to. The heading of the panel, in numbers."""

    sessions: int
    connected: int
    failed: int
    drops: int
    manual: int
    up_seconds: float
    longest_up_seconds: float
    median_up_seconds: float
    bytes_in: int
    bytes_out: int
    first_started_at: str | None
    span_days: float

    def to_dict(self) -> dict[str, object]:
        return {
            "sessions": self.sessions,
            "connected": self.connected,
            "failed": self.failed,
            "drops": self.drops,
            "manual": self.manual,
            "up_seconds": round(self.up_seconds, 1),
            "longest_up_seconds": round(self.longest_up_seconds, 1),
            "median_up_seconds": round(self.median_up_seconds, 1),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "first_started_at": self.first_started_at,
            "span_days": round(self.span_days, 1),
        }


EMPTY = Summary(
    sessions=0,
    connected=0,
    failed=0,
    drops=0,
    manual=0,
    up_seconds=0.0,
    longest_up_seconds=0.0,
    median_up_seconds=0.0,
    bytes_in=0,
    bytes_out=0,
    first_started_at=None,
    span_days=0.0,
)


def summarise(sessions: list[Session], *, now: datetime | None = None) -> Summary:
    """Aggregate the whole retained window -- never a filtered page.

    Summarising the search results instead would produce a number that changes as you type, and
    "three drops" means nothing without knowing it is three out of how many.

    Durations are counted over sessions that actually came up. An attempt that failed at the
    credential prompt contributes to the failure count and to nothing else: folding its
    fifteen seconds into a median uptime would drag the answer towards zero every time a code
    was mistyped.
    """
    if not sessions:
        return EMPTY

    moment = now or datetime.now().astimezone()
    ups = [s.up_seconds for s in sessions if s.connected and s.up_seconds is not None]
    dated = [
        (moment_, text) for text in (s.started_at for s in sessions) if (moment_ := _moment(text))
    ]
    first = min(dated, default=None)
    return Summary(
        sessions=len(sessions),
        connected=sum(1 for s in sessions if s.connected),
        failed=sum(1 for s in sessions if s.kind == FAILED),
        drops=sum(1 for s in sessions if s.kind == DROPPED),
        manual=sum(1 for s in sessions if s.kind == MANUAL),
        up_seconds=sum(ups),
        longest_up_seconds=max(ups, default=0.0),
        median_up_seconds=statistics.median(ups) if ups else 0.0,
        bytes_in=sum(s.bytes_in for s in sessions),
        bytes_out=sum(s.bytes_out for s in sessions),
        first_started_at=first[1] if first else None,
        # Reported rather than assumed to be seven: a session is kept whole back to its
        # beginning, so the window legitimately reaches further than the retention period, and
        # a machine that has been off all week legitimately covers less.
        span_days=(_elapsed(first[0] if first else None, moment) or 0.0) / 86400.0,
    )
