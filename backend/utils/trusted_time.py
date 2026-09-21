"""
DRRA-008 — Trustworthy time and clock-synchronization checks.

Detection, containment, and recovery decisions are only defensible if their
timestamps are trustworthy and correctly ordered. Two failure modes matter:

  1. **Wall-clock jumps.** NTP corrections, VM pauses, and manual clock changes
     can make the system wall clock move backward, which would let a later event
     carry an earlier timestamp and corrupt incident ordering (and any
     hash-chained audit built on it — DRRA-007).
  2. **Cross-host skew.** An endpoint's clock can differ from the control
     plane's. When an event carries a source timestamp (`occurred_at`) and the
     receiver stamps arrival (`ingested_at`), a large skew means the source time
     cannot be trusted at face value.

This module provides:
  * ``monotonic_timestamp()`` — a strictly non-decreasing wall-clock timestamp,
    so event ordering is stable even if the wall clock jumps backward.
  * ``TrustedClock`` — the same behavior with injectable time sources (so it is
    testable and can be driven by a replay harness).
  * ``assess_skew()`` — classify source-vs-receiver skew as ok / warn / reject
    against configurable thresholds.
  * ``stamp()`` — a ready-to-attach event time record (RFC 3339 wall time, a
    monotonic sequence value, and the skew posture for a given source time).

It has no external dependencies and does not import the app, so watchers,
scripts, and the backend can all share one time vocabulary.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

# Default skew thresholds (seconds). A deployment tightens these once NTP is
# guaranteed; the defaults are deliberately generous so ordinary drift is "ok".
DEFAULT_SKEW_WARN_SECONDS = 5.0
DEFAULT_SKEW_REJECT_SECONDS = 300.0  # 5 min: beyond this the source time is untrusted


def rfc3339(ts: float) -> str:
    """Format a POSIX timestamp as an RFC 3339 UTC string (matches the watcher)."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class TrustedClock:
    """Emits strictly non-decreasing timestamps despite wall-clock regressions.

    ``wall`` returns POSIX seconds (default ``time.time``); ``mono`` returns a
    monotonic reference (default ``time.monotonic``). The returned timestamp
    tracks the wall clock when it advances normally, but never goes backward:
    if the wall clock regresses, the monotonic reference is used to carry the
    sequence forward by the elapsed real time.
    """

    def __init__(
        self,
        wall: Optional[Callable[[], float]] = None,
        mono: Optional[Callable[[], float]] = None,
    ) -> None:
        self._wall = wall or time.time
        self._mono = mono or time.monotonic
        self._lock = threading.Lock()
        self._last_ts: Optional[float] = None
        self._last_mono: Optional[float] = None

    def timestamp(self) -> float:
        with self._lock:
            wall = self._wall()
            mono = self._mono()
            if self._last_ts is None:
                ts = wall
            else:
                # Candidate from the wall clock, and a floor derived from real
                # elapsed time so we never emit a value below the last one.
                elapsed = max(0.0, mono - self._last_mono)
                floor = self._last_ts + elapsed
                ts = wall if wall >= floor else floor
                # Guarantee strict monotonicity even if both agree exactly.
                if ts <= self._last_ts:
                    ts = self._last_ts + 1e-6
            self._last_ts = ts
            self._last_mono = mono
            return ts

    def now_rfc3339(self) -> str:
        return rfc3339(self.timestamp())


# Process-wide default clock for callers that just want a trustworthy timestamp.
_DEFAULT_CLOCK = TrustedClock()


def monotonic_timestamp() -> float:
    """A strictly non-decreasing POSIX timestamp from the process default clock."""
    return _DEFAULT_CLOCK.timestamp()


def monotonic_rfc3339() -> str:
    return _DEFAULT_CLOCK.now_rfc3339()


@dataclass
class SkewAssessment:
    skew_seconds: float          # source - receiver (positive => source ahead)
    status: str                  # "ok" | "warn" | "reject"
    warn_threshold: float
    reject_threshold: float

    @property
    def trusted(self) -> bool:
        return self.status != "reject"


def assess_skew(
    source_time: float,
    receiver_time: float,
    warn_seconds: float = DEFAULT_SKEW_WARN_SECONDS,
    reject_seconds: float = DEFAULT_SKEW_REJECT_SECONDS,
) -> SkewAssessment:
    """Classify the skew between a source clock and the receiver clock.

    ``ok`` within the warn threshold, ``warn`` between warn and reject, and
    ``reject`` beyond the reject threshold (the source timestamp should not be
    trusted at face value). The magnitude is symmetric — a source clock that is
    far behind is as untrustworthy as one far ahead.
    """
    skew = source_time - receiver_time
    magnitude = abs(skew)
    if magnitude > reject_seconds:
        status = "reject"
    elif magnitude > warn_seconds:
        status = "warn"
    else:
        status = "ok"
    return SkewAssessment(
        skew_seconds=skew,
        status=status,
        warn_threshold=warn_seconds,
        reject_threshold=reject_seconds,
    )


def stamp(source_time: Optional[float] = None, clock: Optional[TrustedClock] = None) -> dict:
    """Return an event time record.

    ``wall`` is the trustworthy monotonic receiver time (RFC 3339), ``sequence``
    is the raw monotonic value for ordering, and — when a ``source_time`` is
    supplied — ``source`` and ``skew`` describe the source clock's posture
    relative to the receiver.
    """
    clk = clock or _DEFAULT_CLOCK
    seq = clk.timestamp()
    record = {"wall": rfc3339(seq), "sequence": seq}
    if source_time is not None:
        assessment = assess_skew(source_time, seq)
        record["source"] = rfc3339(source_time)
        record["skew"] = {
            "seconds": round(assessment.skew_seconds, 6),
            "status": assessment.status,
            "trusted": assessment.trusted,
        }
    return record
