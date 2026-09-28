"""
DRRA-008 — Trustworthy time and clock-sync checks.

Verifies monotonic timestamping survives a backward wall-clock jump, and that
cross-host skew is classified into ok / warn / reject correctly.
"""

from __future__ import annotations

import os
import sys

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_REPO, os.path.join(_REPO, "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

from utils.trusted_time import (  # noqa: E402
    TrustedClock,
    assess_skew,
    monotonic_timestamp,
    rfc3339,
    stamp,
)


class _FakeTime:
    """Injectable wall/mono sources driven by a script of values."""

    def __init__(self, wall_values, mono_values):
        self._wall = list(wall_values)
        self._mono = list(mono_values)

    def wall(self):
        return self._wall.pop(0)

    def mono(self):
        return self._mono.pop(0)


def test_default_clock_is_strictly_increasing():
    vals = [monotonic_timestamp() for _ in range(200)]
    assert all(b > a for a, b in zip(vals, vals[1:])), "timestamps not strictly increasing"


def test_backward_wall_clock_does_not_regress_timestamps():
    # Wall clock jumps backward by 60s between the 2nd and 3rd reading, but the
    # monotonic reference keeps advancing by 1s each step.
    ft = _FakeTime(
        wall_values=[1000.0, 1001.0, 941.0, 942.0],   # <- 941 is a 60s regression
        mono_values=[500.0, 501.0, 502.0, 503.0],
    )
    clk = TrustedClock(wall=ft.wall, mono=ft.mono)
    t0 = clk.timestamp()
    t1 = clk.timestamp()
    t2 = clk.timestamp()   # wall regressed here
    t3 = clk.timestamp()
    assert t0 == 1000.0
    assert t1 == 1001.0
    # Despite the wall going back to 941, the emitted time must not regress; it
    # advances by the ~1s of real (monotonic) elapsed time instead.
    assert t2 > t1
    assert t3 > t2


def test_forward_wall_clock_is_tracked():
    ft = _FakeTime(
        wall_values=[1000.0, 1005.0],
        mono_values=[500.0, 501.0],
    )
    clk = TrustedClock(wall=ft.wall, mono=ft.mono)
    assert clk.timestamp() == 1000.0
    # A genuine 5s forward step is tracked, not clamped.
    assert clk.timestamp() == 1005.0


def test_equal_wall_still_advances_strictly():
    ft = _FakeTime(
        wall_values=[1000.0, 1000.0, 1000.0],
        mono_values=[500.0, 500.0, 500.0],
    )
    clk = TrustedClock(wall=ft.wall, mono=ft.mono)
    a, b, c = clk.timestamp(), clk.timestamp(), clk.timestamp()
    assert a < b < c


def test_skew_ok():
    a = assess_skew(source_time=1000.0, receiver_time=1000.5, warn_seconds=5, reject_seconds=300)
    assert a.status == "ok"
    assert a.trusted is True


def test_skew_warn():
    a = assess_skew(source_time=1010.0, receiver_time=1000.0, warn_seconds=5, reject_seconds=300)
    assert a.status == "warn"
    assert a.trusted is True
    assert round(a.skew_seconds, 3) == 10.0


def test_skew_reject_is_symmetric():
    ahead = assess_skew(1000.0 + 400, 1000.0, warn_seconds=5, reject_seconds=300)
    behind = assess_skew(1000.0 - 400, 1000.0, warn_seconds=5, reject_seconds=300)
    assert ahead.status == "reject" and not ahead.trusted
    assert behind.status == "reject" and not behind.trusted


def test_stamp_without_source():
    rec = stamp()
    assert "wall" in rec and "sequence" in rec
    assert "source" not in rec
    # wall is a parseable RFC 3339 string
    from datetime import datetime
    datetime.fromisoformat(rec["wall"])


def test_stamp_with_trusted_source():
    clk = TrustedClock()
    seq = clk.timestamp()
    rec = stamp(source_time=seq, clock=clk)
    assert rec["source"] and rec["skew"]["status"] in ("ok", "warn")
    assert isinstance(rec["skew"]["trusted"], bool)


def test_rfc3339_roundtrip():
    from datetime import datetime, timezone
    ts = 1_700_000_000.5
    s = rfc3339(ts)
    parsed = datetime.fromisoformat(s)
    assert parsed.tzinfo is not None
    assert abs(parsed.timestamp() - ts) < 1e-3
    assert parsed.astimezone(timezone.utc)
