"""Turning cumulative byte counters into a drawable series.

Pure arithmetic with no I/O, so these are the tests that can be exhaustive about the awkward
cases: a counter that resets, a sample that never arrived, a clock that did not advance.
"""

from __future__ import annotations

import pytest

from app.services.traffic import DEFAULT_POINTS, Point, downsample, rates, series


def steady(count: int, *, step: float = 5.0, rx: int = 1024, tx: int = 512, start: float = 1000.0):
    """`count` readings of a tunnel moving `rx`/`tx` bytes per second."""
    return [
        (start + index * step, int(index * step * rx), int(index * step * tx))
        for index in range(count)
    ]


# --- differentiating -------------------------------------------------------


def test_a_steady_stream_gives_a_flat_rate():
    points = rates(steady(5))
    assert [round(point.rx) for point in points] == [1024] * 4
    assert [round(point.tx) for point in points] == [512] * 4


def test_one_reading_yields_no_rate():
    """A rate needs two readings; inventing one would spike the graph on every re-attach."""
    assert rates([(1000.0, 5_000_000, 0)]) == []


def test_no_readings_yield_nothing():
    assert rates([]) == []


def test_a_counter_reset_is_not_a_negative_rate():
    """OpenVPN restarts its counters; the graph must not dip below the axis."""
    points = rates([(0.0, 5_000_000, 900), (5.0, 100, 0)])
    assert points[0].rx == 0.0
    assert points[0].tx == 0.0


def test_a_stalled_clock_is_skipped_rather_than_dividing_by_zero():
    assert rates([(1000.0, 0, 0), (1000.0, 500, 0)]) == []


def test_a_missed_sample_averages_over_the_gap():
    """A late reading must not become a spike -- the rate simply covers the longer interval."""
    points = rates([(0.0, 0, 0), (60.0, 60 * 1024, 0)])
    assert round(points[0].rx) == 1024


def test_the_point_is_timestamped_at_the_end_of_its_interval():
    assert rates(steady(2))[0].t == 1005.0


# --- bucketing -------------------------------------------------------------


def test_a_short_series_is_left_alone():
    points = rates(steady(10))
    assert downsample(points, 100) is points


def test_a_long_series_is_reduced_to_the_limit():
    points = [Point(float(i), i, i) for i in range(1000)]
    assert len(downsample(points, 50)) == 50


def test_bucketing_averages_rather_than_taking_the_maximum():
    """The area under the curve should still correspond to the bytes actually moved."""
    points = [Point(float(i), 0 if i % 2 else 100, 0) for i in range(100)]
    assert downsample(points, 1)[0].rx == pytest.approx(50, abs=1)


def test_bucketing_keeps_the_last_reading_visible():
    points = [Point(float(i), i, i) for i in range(100)]
    assert downsample(points, 10)[-1].rx > downsample(points, 10)[0].rx


def test_bucketing_covers_the_whole_span():
    points = [Point(float(i), i, i) for i in range(100)]
    reduced = downsample(points, 10)
    assert reduced[0].t < reduced[-1].t
    assert reduced[-1].t >= 90


# --- the whole series ------------------------------------------------------


def test_an_empty_session_is_an_empty_series():
    result = series([])
    assert result.points == []
    assert result.bytes_in == 0
    assert result.span_seconds == 0


def test_totals_come_from_the_last_reading_not_the_sum_of_rates():
    """Re-attaching mid-session means the first reading is already large; it still counts."""
    result = series([(0.0, 1_000_000, 500_000), (5.0, 1_005_120, 502_560)])
    assert result.bytes_in == 1_005_120
    assert result.bytes_out == 502_560


def test_peaks_survive_bucketing():
    """A brief spike is averaged out of the drawn line, so it is reported separately."""
    samples = steady(60)
    spike_at = samples[30][0] + 5
    samples = samples[:31] + [(spike_at, samples[30][1] + 50 * 1024 * 5, samples[30][2])]
    result = series(samples, limit=5)
    assert result.peak_rx > 40 * 1024
    assert max(point.rx for point in result.points) < result.peak_rx


def test_the_span_is_the_wall_clock_length():
    assert series(steady(13)).span_seconds == 60.0


def test_serialising_rounds_for_the_wire():
    point = Point(t=1000.123456, rx=1.987654, tx=0.5)
    assert point.to_dict() == {"t": 1000.1, "rx": 2.0, "tx": 0.5}


def test_a_days_worth_of_samples_is_bounded_before_it_is_served():
    """The payload must not grow with session length -- that is the point of bucketing."""
    result = series(steady(17_280))
    assert len(result.points) <= DEFAULT_POINTS
