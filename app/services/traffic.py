"""Turning cumulative byte counters into a series a graph can draw.

Pure arithmetic, deliberately separate from storage: OpenVPN reports totals since the tunnel came
up, and everything a chart wants -- rates, peaks, a bounded number of points -- is derived from
those on read. Nothing here touches the database or the network, which is why it is the easiest
part of the feature to be sure about.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Points sent to the browser. A panel a few hundred pixels wide cannot show more, and a day of
#: samples is thousands of readings, so the series is bucketed down to this before it is served.
DEFAULT_POINTS = 240


@dataclass(frozen=True)
class Point:
    """One plotted moment: a time, and the two rates in bytes per second."""

    t: float
    rx: float
    tx: float

    def to_dict(self) -> dict[str, float]:
        # Rounded because the browser draws these; full float precision is noise on the wire.
        return {"t": round(self.t, 1), "rx": round(self.rx, 1), "tx": round(self.tx, 1)}


@dataclass(frozen=True)
class Series:
    points: list[Point]
    bytes_in: int
    bytes_out: int
    peak_rx: float
    peak_tx: float
    span_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "points": [point.to_dict() for point in self.points],
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "peak_rx": round(self.peak_rx, 1),
            "peak_tx": round(self.peak_tx, 1),
            "span_seconds": round(self.span_seconds, 1),
        }


EMPTY = Series(points=[], bytes_in=0, bytes_out=0, peak_rx=0.0, peak_tx=0.0, span_seconds=0.0)


def rates(samples: list[tuple[float, int, int]]) -> list[Point]:
    """Differentiate cumulative readings into per-second rates.

    Three things are guarded, all of which happen in practice:

    * The first reading yields no rate -- a rate needs two readings, and inventing one by
      assuming the counter started at zero would spike the graph whenever the app re-adopted a
      tunnel that was already running.
    * A counter that goes *backwards* means the tunnel restarted underneath us. That is recorded
      as zero rather than a negative rate.
    * A non-advancing timestamp is skipped, rather than dividing by zero.
    """
    points: list[Point] = []
    for (t0, in0, out0), (t1, in1, out1) in zip(samples, samples[1:], strict=False):
        elapsed = t1 - t0
        if elapsed <= 0:
            continue
        points.append(
            Point(
                t=t1,
                rx=max(0, in1 - in0) / elapsed,
                tx=max(0, out1 - out0) / elapsed,
            )
        )
    return points


def downsample(points: list[Point], limit: int = DEFAULT_POINTS) -> list[Point]:
    """Bucket into at most ``limit`` points by averaging.

    Mean rather than max on purpose: the area under an averaged curve still corresponds to the
    bytes actually transferred, where a max-per-bucket curve would overstate every quiet period.
    The true peak is reported separately in :class:`Series`, so a brief spike is not lost.
    """
    if limit < 1 or len(points) <= limit:
        return points

    # Equal-count buckets. Samples arrive on a fixed interval, so these are equal-time in
    # practice, and the arithmetic stays simple enough to check by eye.
    size = len(points) / limit
    buckets: list[Point] = []
    for index in range(limit):
        start = int(index * size)
        end = int((index + 1) * size) if index < limit - 1 else len(points)
        chunk = points[start:end]
        if not chunk:
            continue
        count = len(chunk)
        buckets.append(
            Point(
                t=sum(point.t for point in chunk) / count,
                rx=sum(point.rx for point in chunk) / count,
                tx=sum(point.tx for point in chunk) / count,
            )
        )
    return buckets


def series(samples: list[tuple[float, int, int]], limit: int = DEFAULT_POINTS) -> Series:
    """The whole thing: raw readings in, a drawable series out."""
    if not samples:
        return EMPTY

    full = rates(samples)
    # Totals come from the last *reading*, not from summing the rates: OpenVPN's counters are
    # already the session total, and re-adding differences would lose whatever accumulated
    # before the app attached.
    _, bytes_in, bytes_out = samples[-1]
    return Series(
        points=downsample(full, limit),
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        peak_rx=max((point.rx for point in full), default=0.0),
        peak_tx=max((point.tx for point in full), default=0.0),
        span_seconds=samples[-1][0] - samples[0][0],
    )
