"""The history's arithmetic: what a stored attempt means, and what a week of them adds up to.

No database and no clock -- every test hands in the rows and the moment, which is the point of
keeping this module pure. The cases that matter are the ones where a naive summary would lie:
an attempt that never came up, a session still running, and a session that started before the
window it is being reported in.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services import sessions

TZ = timezone(timedelta(hours=1))
NOW = datetime(2026, 8, 21, 12, 0, 0, tzinfo=TZ)


def _at(**delta) -> str:
    return (NOW - timedelta(**delta)).isoformat(timespec="seconds")


def _row(**overrides) -> dict:
    """One stored row, shaped exactly as ``store.list_sessions`` returns it."""
    row = {
        "id": 7,
        "connection": "client",
        "started_at": _at(hours=3),
        "connected_at": _at(hours=3),
        "ended_at": _at(hours=1),
        "outcome": "disconnected",
        "reason": sessions.REASON_SEVERED,
        "lines": 12,
        "bytes_in": 2048,
        "bytes_out": 1024,
    }
    row.update(overrides)
    return row


def _session(**overrides) -> sessions.Session:
    live = overrides.pop("live", False)
    return sessions.from_row(_row(**overrides), live=live, now=NOW)


# --- one session -----------------------------------------------------------


def test_a_finished_session_measures_between_its_own_timestamps():
    session = _session()
    assert session.duration_seconds == pytest.approx(2 * 3600)
    assert session.up_seconds == pytest.approx(2 * 3600)
    assert session.connected is True


def test_time_connected_starts_when_the_tunnel_came_up_not_when_the_attempt_did():
    """Ten minutes of negotiating is not ten minutes of tunnel."""
    session = _session(started_at=_at(hours=3, minutes=10), connected_at=_at(hours=3))
    assert session.duration_seconds == pytest.approx(2 * 3600 + 600)
    assert session.up_seconds == pytest.approx(2 * 3600)


def test_an_attempt_that_never_came_up_has_no_connected_time():
    session = _session(
        connected_at=None, ended_at=_at(hours=2, minutes=59), outcome="failed", reason=""
    )
    assert session.connected is False
    assert session.up_seconds is None
    assert session.kind == sessions.FAILED


def test_a_live_session_is_measured_to_now():
    session = _session(ended_at=None, reason="", outcome="", live=True)
    assert session.kind == sessions.LIVE
    assert session.up_seconds == pytest.approx(3 * 3600)


def test_an_unfinished_session_that_is_not_live_was_interrupted():
    """No end time and not the attempt running now: the app stopped mid-tunnel."""
    assert _session(ended_at=None, reason="", outcome="").kind == sessions.INTERRUPTED


@pytest.mark.parametrize(
    ("reason", "outcome", "expected"),
    [
        (sessions.REASON_SEVERED, "disconnected", sessions.DROPPED),
        (sessions.REASON_MANUAL, "disconnected", sessions.MANUAL),
        ("", "failed", sessions.FAILED),
        ("", "interrupted", sessions.INTERRUPTED),
    ],
)
def test_how_a_session_ended_is_read_from_what_was_recorded(reason, outcome, expected):
    assert _session(reason=reason, outcome=outcome, connected_at=None).kind == expected


def test_a_session_that_ended_without_a_recorded_reason_still_reads_as_ended():
    """Rows written before migration 0006 have no reason, and guessing one would be a lie."""
    assert _session(reason="", outcome="disconnected").kind == sessions.ENDED


def test_a_timestamp_without_an_offset_does_not_break_the_comparison():
    """Mixing a naive datetime with an aware one raises, so one odd row would take the panel
    with it. Treating it as local time is the only reading that can be right here."""
    naive = (NOW - timedelta(hours=1)).replace(tzinfo=None).isoformat(timespec="seconds")
    session = _session(started_at=naive, connected_at=naive)
    assert isinstance(session.up_seconds, float)
    assert sessions.summarise([session], now=NOW).span_days >= 0


def test_an_unparseable_timestamp_costs_a_duration_not_the_request():
    session = _session(started_at="not a time", connected_at="also not a time")
    assert session.duration_seconds is None
    assert session.up_seconds is None
    assert session.to_dict()["duration_seconds"] is None


def test_a_row_with_nothing_in_it_survives():
    session = sessions.from_row({"id": 3}, now=NOW)
    assert (session.connection, session.bytes_in, session.lines) == (None, 0, 0)


def test_the_wire_format_carries_what_the_panel_shows():
    payload = _session().to_dict()
    assert payload["kind"] == sessions.DROPPED
    assert payload["connected"] is True
    assert payload["up_seconds"] == pytest.approx(7200)
    assert payload["bytes_in"] == 2048


def test_from_rows_marks_only_the_live_session():
    rows = [_row(id=2, ended_at=None, reason="", outcome=""), _row(id=1)]
    shaped = sessions.from_rows(rows, live_id=2, now=NOW)
    assert [s.live for s in shaped] == [True, False]


# --- searching -------------------------------------------------------------


def _three() -> list[sessions.Session]:
    return [
        _session(id=3, connection="work", reason=sessions.REASON_SEVERED),
        _session(id=2, connection="work", reason=sessions.REASON_MANUAL),
        _session(id=1, connection="home", reason="", outcome="failed", connected_at=None),
    ]


def test_an_empty_search_matches_everything():
    assert len(sessions.search(_three(), "")) == 3
    assert len(sessions.search(_three(), "   ")) == 3


def test_searching_by_connection_name():
    assert [s.id for s in sessions.search(_three(), "work")] == [3, 2]


def test_searching_by_how_it_ended():
    assert [s.id for s in sessions.search(_three(), "dropped")] == [3]
    assert [s.id for s in sessions.search(_three(), "FAILED")] == [1]


def test_searching_by_session_number():
    assert [s.id for s in sessions.search(_three(), "#2")] == [2]
    assert [s.id for s in sessions.search(_three(), "2")] == [2]


def test_every_term_has_to_match():
    assert [s.id for s in sessions.search(_three(), "work dropped")] == [3]
    assert sessions.search(_three(), "home dropped") == []


# --- paging ----------------------------------------------------------------


def _many(count: int) -> list[sessions.Session]:
    return [_session(id=index) for index in range(count, 0, -1)]


def test_a_page_stops_at_the_limit_and_hands_back_a_cursor():
    window, cursor = sessions.page(_many(10), limit=4)
    assert [s.id for s in window] == [10, 9, 8, 7]
    assert cursor == 7


def test_the_cursor_continues_where_the_page_stopped():
    window, cursor = sessions.page(_many(10), before=7, limit=4)
    assert [s.id for s in window] == [6, 5, 4, 3]
    assert cursor == 3


def test_the_last_page_has_no_cursor():
    """A cursor on the final page would offer a "show older" button with nothing behind it."""
    window, cursor = sessions.page(_many(3), limit=10)
    assert len(window) == 3
    assert cursor is None


def test_the_page_size_is_clamped():
    assert len(sessions.page(_many(300), limit=99_999)[0]) == sessions.MAX_LIMIT
    assert len(sessions.page(_many(10), limit=0)[0]) == 1


# --- summarising -----------------------------------------------------------


def test_nothing_recorded_summarises_to_zeroes():
    assert sessions.summarise([]) == sessions.EMPTY
    assert sessions.summarise([]).to_dict()["sessions"] == 0


def test_the_summary_separates_a_drop_from_a_disconnect_from_a_failure():
    summary = sessions.summarise(_three(), now=NOW)
    assert (summary.sessions, summary.drops, summary.manual, summary.failed) == (3, 1, 1, 1)
    assert summary.connected == 2


def test_uptime_ignores_attempts_that_never_came_up():
    """Otherwise a mistyped code drags the median towards zero and the total is meaningless."""
    summary = sessions.summarise(
        [
            _session(
                id=2, started_at=_at(hours=5), connected_at=_at(hours=5), ended_at=_at(hours=1)
            ),
            _session(id=1, connected_at=None, outcome="failed", reason=""),
        ],
        now=NOW,
    )
    assert summary.up_seconds == pytest.approx(4 * 3600)
    assert summary.median_up_seconds == pytest.approx(4 * 3600)
    assert summary.longest_up_seconds == pytest.approx(4 * 3600)


def test_the_median_is_the_middle_session_not_the_mean():
    summary = sessions.summarise(
        [
            _session(id=3, connected_at=_at(hours=9), ended_at=_at(hours=1)),  # 8h
            _session(id=2, connected_at=_at(hours=2), ended_at=_at(hours=1)),  # 1h
            _session(id=1, connected_at=_at(hours=3), ended_at=_at(hours=1)),  # 2h
        ],
        now=NOW,
    )
    assert summary.median_up_seconds == pytest.approx(2 * 3600)
    assert summary.longest_up_seconds == pytest.approx(8 * 3600)


def test_the_totals_add_up_what_was_carried():
    summary = sessions.summarise([_session(id=2), _session(id=1)], now=NOW)
    assert (summary.bytes_in, summary.bytes_out) == (4096, 2048)


def test_the_window_reported_is_the_one_actually_covered():
    """Retention keeps a session whole, so the history can legitimately reach past seven days."""
    summary = sessions.summarise(
        [_session(id=2), _session(id=1, started_at=_at(days=8), connected_at=_at(days=8))],
        now=NOW,
    )
    assert summary.span_days == pytest.approx(8.0, abs=0.1)
    assert summary.first_started_at == _at(days=8)


def test_a_summary_of_one_switched_off_week_covers_less_than_seven_days():
    summary = sessions.summarise([_session(id=1, started_at=_at(hours=3))], now=NOW)
    assert summary.span_days == pytest.approx(0.125, abs=0.01)
