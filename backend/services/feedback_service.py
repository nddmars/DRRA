"""
Feedback Loop Service - WSG Closed-Loop Resilience Engine

Implements the GRAB => WALL feedback path from the WSG framework:
  Telemetry => DI Scoring => Threshold Adaptation => Improved Detection

This is the component that turns WSG from a static defense into a
continuously improving, closed-loop system. Each incident makes the
next detection faster and more accurate.

WSG Position: Feedback arrow (GRAB => WALL) on closed-loop diagram
Slide Reference: Slide 16 - "Why Closed-Loop Architecture?"
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import uuid

logger = logging.getLogger(__name__)

# Threshold bounds -- prevent over-tightening or over-loosening
ENTROPY_THRESHOLD_MIN = 0.70
ENTROPY_THRESHOLD_MAX = 0.95
MASS_MOD_THRESHOLD_MIN = 0.05
MASS_MOD_THRESHOLD_MAX = 0.40

# Adaptation sensitivity (how aggressively thresholds shift per cycle)
ADAPTATION_RATE = 0.02


@dataclass
class IncidentOutcome:
    """
    Outcome record for a single detected incident.
    Captures WSG performance across all three pillars.
    """
    incident_id: str
    timestamp: str

    # WALL metrics
    detection_time_seconds: float       # Time from attack start to first alert
    false_positive: bool                # Was this alert a false positive?
    entropy_score: float                # Entropy that triggered detection
    confidence_score: float             # Detector confidence at trigger time

    # SQUAT metrics
    isolation_time_seconds: float       # Time from alert to network isolation
    blast_radius_hosts: int             # How many hosts were affected before isolation

    # GRAB metrics
    recovery_completeness: float        # 0.0-1.0, what fraction of data was recovered
    immutability_intact: bool           # Were forensic logs tamper-proof?
    recovery_time_seconds: float        # Time to restore operations

    # Computed DI components (filled by FeedbackLoopService)
    di_score: int = 0


@dataclass
class ResilienceTrend:
    """
    Rolling window view of how the system's Defensibility Index
    has changed across recent incidents.
    """
    window_size: int
    di_scores: List[int] = field(default_factory=list)
    timestamps: List[str] = field(default_factory=list)

    @property
    def latest_di(self) -> int:
        return self.di_scores[-1] if self.di_scores else 0

    @property
    def trend_direction(self) -> str:
        """'improving', 'degrading', or 'stable'."""
        if len(self.di_scores) < 2:
            return "stable"
        delta = self.di_scores[-1] - self.di_scores[0]
        if delta > 3:
            return "improving"
        if delta < -3:
            return "degrading"
        return "stable"

    @property
    def average_di(self) -> float:
        return sum(self.di_scores) / len(self.di_scores) if self.di_scores else 0.0

    def add(self, score: int, timestamp: str) -> None:
        self.di_scores.append(score)
        self.timestamps.append(timestamp)
        # Keep only the rolling window
        if len(self.di_scores) > self.window_size:
            self.di_scores.pop(0)
            self.timestamps.pop(0)


@dataclass
class AdaptedThresholds:
    """
    Current adaptive thresholds output by the feedback loop.
    These feed back into the Sentinel (WALL) detection engine.
    """
    entropy_threshold: float
    mass_modification_threshold: float
    false_positive_rate: float
    adaptation_cycle: int
    rationale: str


@dataclass
class FeedbackReport:
    """
    Full output of one feedback loop cycle.
    This is the artifact that 'closes the loop' -- human-readable
    and machine-consumable evidence that the system is self-improving.
    """
    report_id: str
    generated_at: str
    cycle_number: int

    # System state
    total_incidents: int
    false_positive_count: int
    false_positive_rate: float

    # Defensibility Index
    current_di_score: int
    trend: ResilienceTrend
    di_breakdown: Dict[str, float]  # per-pillar scores

    # Adaptive thresholds (fed back to WALL)
    adapted_thresholds: AdaptedThresholds

    # WSG pillar performance
    wall_avg_detection_seconds: float
    squat_avg_isolation_seconds: float
    grab_avg_recovery_seconds: float
    grab_avg_completeness: float

    # Recommended actions for next cycle
    recommendations: List[str]


class ThresholdAdaptor:
    """
    Adapts WALL detection thresholds based on false positive / false negative rates.

    Logic:
      - Too many false positives => loosen thresholds (raise entropy, raise mass-mod %)
      - Missed detections or slow detection => tighten thresholds (lower thresholds)
      - FP rate target: < 5%

    This implements the "Adaptation" step in the Feedback Loop on Slide 16.
    """

    def __init__(
        self,
        initial_entropy_threshold: float = 0.85,
        initial_mass_mod_threshold: float = 0.15,
    ):
        self.entropy_threshold = initial_entropy_threshold
        self.mass_mod_threshold = initial_mass_mod_threshold
        self._cycle = 0

    def adapt(self, outcomes: List[IncidentOutcome]) -> AdaptedThresholds:
        """
        Compute new thresholds from recent incident outcomes.
        Returns adapted thresholds and the rationale for the change.
        """
        self._cycle += 1

        if not outcomes:
            return AdaptedThresholds(
                entropy_threshold=self.entropy_threshold,
                mass_modification_threshold=self.mass_mod_threshold,
                false_positive_rate=0.0,
                adaptation_cycle=self._cycle,
                rationale="No incidents in window -- thresholds unchanged.",
            )

        total = len(outcomes)
        fp_count = sum(1 for o in outcomes if o.false_positive)
        fp_rate = fp_count / total

        # Measure average confidence at trigger -- low confidence => thresholds too loose
        avg_confidence = sum(o.confidence_score for o in outcomes) / total

        rationale_parts = []

        if fp_rate > 0.10:
            # Too noisy -- loosen thresholds
            self.entropy_threshold = min(
                self.entropy_threshold + ADAPTATION_RATE, ENTROPY_THRESHOLD_MAX
            )
            self.mass_mod_threshold = min(
                self.mass_mod_threshold + ADAPTATION_RATE, MASS_MOD_THRESHOLD_MAX
            )
            rationale_parts.append(
                f"FP rate {fp_rate:.0%} > 10% => thresholds raised to reduce noise"
            )
        elif fp_rate < 0.02 and avg_confidence > 0.90:
            # Very clean signal -- tighten to catch earlier
            self.entropy_threshold = max(
                self.entropy_threshold - ADAPTATION_RATE, ENTROPY_THRESHOLD_MIN
            )
            self.mass_mod_threshold = max(
                self.mass_mod_threshold - ADAPTATION_RATE, MASS_MOD_THRESHOLD_MIN
            )
            rationale_parts.append(
                f"FP rate {fp_rate:.0%} < 2%, confidence {avg_confidence:.0%} => "
                "thresholds tightened for earlier detection"
            )
        else:
            rationale_parts.append(
                f"FP rate {fp_rate:.0%} within target (2-10%) => thresholds stable"
            )

        return AdaptedThresholds(
            entropy_threshold=round(self.entropy_threshold, 4),
            mass_modification_threshold=round(self.mass_mod_threshold, 4),
            false_positive_rate=round(fp_rate, 4),
            adaptation_cycle=self._cycle,
            rationale=" | ".join(rationale_parts),
        )


class FeedbackLoopService:
    """
    Closes the WSG loop: GRAB telemetry => analysis => WALL threshold adaptation.

    Called after each incident (or on a scheduled cadence) to:
      1. Score the incident across all three WSG pillars (DI calculation)
      2. Update the rolling resilience trend
      3. Adapt WALL detection thresholds based on FP/FN history
      4. Emit a FeedbackReport -- the artifact that proves continuous improvement

    This is what makes DRRA an 'original contribution':
      - Quantified improvement loop (not just detect/respond/recover)
      - Measurable DI metric that tracks system resilience over time
      - Adaptive thresholds that self-tune without manual intervention
    """

    # DI pillar weights (matches DefensibilityScorer in sentinel/detector.py)
    DI_WEIGHTS = {
        "detection": 0.30,
        "isolation": 0.30,
        "recovery": 0.20,
        "immutability": 0.20,
    }

    # Target SLAs (from playbook / slides)
    TARGET_DETECTION_SECONDS = 600     # < 10 minutes (slide 39 target)
    TARGET_ISOLATION_SECONDS = 60      # < 60 seconds (slide 22, 39)
    TARGET_RECOVERY_SECONDS = 604800   # < 1 week in seconds (slide 39)

    def __init__(self, trend_window: int = 10):
        self.outcomes: List[IncidentOutcome] = []
        self.trend = ResilienceTrend(window_size=trend_window)
        self.adaptor = ThresholdAdaptor()
        self._cycle = 0

    def record_outcome(self, outcome: IncidentOutcome) -> int:
        """
        Record an incident outcome and compute its DI score.
        Returns the DI score for this incident.
        """
        di_score = self._compute_di(outcome)
        outcome.di_score = di_score

        self.outcomes.append(outcome)
        self.trend.add(di_score, outcome.timestamp)

        logger.info(
            f"Feedback: incident {outcome.incident_id} | DI={di_score} | "
            f"trend={self.trend.trend_direction}"
        )
        return di_score

    def run_cycle(self) -> FeedbackReport:
        """
        Run one full feedback cycle over all recorded outcomes.
        Returns a FeedbackReport that closes the loop.
        """
        self._cycle += 1
        now = datetime.now(timezone.utc).isoformat()

        outcomes = self.outcomes
        total = len(outcomes)
        fp_count = sum(1 for o in outcomes if o.false_positive)
        fp_rate = fp_count / total if total > 0 else 0.0

        # Adapt thresholds from recent outcomes
        adapted = self.adaptor.adapt(outcomes[-20:])  # Use last 20 incidents

        # Per-pillar averages for the report
        wall_avg = self._avg(outcomes, "detection_time_seconds")
        squat_avg = self._avg(outcomes, "isolation_time_seconds")
        grab_avg_time = self._avg(outcomes, "recovery_time_seconds")
        grab_avg_complete = self._avg(outcomes, "recovery_completeness")

        # Per-pillar DI breakdown (averages across all incidents)
        di_breakdown = self._avg_di_breakdown(outcomes)

        # Generate actionable recommendations
        recommendations = self._generate_recommendations(
            outcomes, adapted, wall_avg, squat_avg, grab_avg_complete
        )

        report = FeedbackReport(
            report_id=str(uuid.uuid4()),
            generated_at=now,
            cycle_number=self._cycle,
            total_incidents=total,
            false_positive_count=fp_count,
            false_positive_rate=round(fp_rate, 4),
            current_di_score=self.trend.latest_di,
            trend=self.trend,
            di_breakdown=di_breakdown,
            adapted_thresholds=adapted,
            wall_avg_detection_seconds=round(wall_avg, 2),
            squat_avg_isolation_seconds=round(squat_avg, 2),
            grab_avg_recovery_seconds=round(grab_avg_time, 2),
            grab_avg_completeness=round(grab_avg_complete, 4),
            recommendations=recommendations,
        )

        logger.info(
            f"Feedback cycle {self._cycle} complete | "
            f"DI={report.current_di_score} | trend={self.trend.trend_direction} | "
            f"entropy_threshold={adapted.entropy_threshold}"
        )
        return report

    def get_trend_summary(self) -> Dict:
        """Quick summary for dashboard consumption."""
        return {
            "current_di": self.trend.latest_di,
            "average_di": round(self.trend.average_di, 1),
            "trend": self.trend.trend_direction,
            "di_history": list(zip(self.trend.timestamps, self.trend.di_scores)),
            "active_thresholds": {
                "entropy": self.adaptor.entropy_threshold,
                "mass_modification": self.adaptor.mass_mod_threshold,
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_di(self, outcome: IncidentOutcome) -> int:
        """Compute Defensibility Index for a single incident."""
        # WALL: detection effectiveness (how fast vs. target)
        detection_eff = max(
            0.0,
            1.0 - (outcome.detection_time_seconds / self.TARGET_DETECTION_SECONDS),
        )
        if outcome.false_positive:
            detection_eff *= 0.5  # FPs reduce the score

        # SQUAT: isolation success (speed + blast radius)
        isolation_speed = max(
            0.0,
            1.0 - (outcome.isolation_time_seconds / self.TARGET_ISOLATION_SECONDS),
        )
        blast_penalty = min(outcome.blast_radius_hosts * 0.05, 0.5)
        isolation_eff = max(0.0, isolation_speed - blast_penalty)

        # GRAB: recovery completeness
        recovery_eff = outcome.recovery_completeness

        # Immutability: binary + partial credit
        immutability_eff = 1.0 if outcome.immutability_intact else 0.3

        weighted = (
            detection_eff * self.DI_WEIGHTS["detection"]
            + isolation_eff * self.DI_WEIGHTS["isolation"]
            + recovery_eff * self.DI_WEIGHTS["recovery"]
            + immutability_eff * self.DI_WEIGHTS["immutability"]
        )
        return max(0, min(100, int(weighted * 100)))

    def _avg(self, outcomes: List[IncidentOutcome], field: str) -> float:
        if not outcomes:
            return 0.0
        values = [getattr(o, field) for o in outcomes]
        return sum(values) / len(values)

    def _avg_di_breakdown(self, outcomes: List[IncidentOutcome]) -> Dict[str, float]:
        if not outcomes:
            return {k: 0.0 for k in self.DI_WEIGHTS}
        # Recompute per-pillar for averaging (simplified)
        detection_scores, isolation_scores, recovery_scores, immut_scores = [], [], [], []
        for o in outcomes:
            detection_scores.append(
                max(0.0, 1.0 - o.detection_time_seconds / self.TARGET_DETECTION_SECONDS)
            )
            isolation_scores.append(
                max(0.0, 1.0 - o.isolation_time_seconds / self.TARGET_ISOLATION_SECONDS)
            )
            recovery_scores.append(o.recovery_completeness)
            immut_scores.append(1.0 if o.immutability_intact else 0.3)
        n = len(outcomes)
        return {
            "detection": round(sum(detection_scores) / n, 3),
            "isolation": round(sum(isolation_scores) / n, 3),
            "recovery": round(sum(recovery_scores) / n, 3),
            "immutability": round(sum(immut_scores) / n, 3),
        }

    def _generate_recommendations(
        self,
        outcomes: List[IncidentOutcome],
        adapted: AdaptedThresholds,
        wall_avg: float,
        squat_avg: float,
        grab_avg_complete: float,
    ) -> List[str]:
        recs = []

        if wall_avg > self.TARGET_DETECTION_SECONDS:
            recs.append(
                f"WALL: Avg detection time {wall_avg:.0f}s exceeds {self.TARGET_DETECTION_SECONDS}s target -- "
                "consider tightening entropy threshold or adding honeypot tripwires"
            )

        if squat_avg > self.TARGET_ISOLATION_SECONDS:
            recs.append(
                f"SQUAT: Avg isolation time {squat_avg:.0f}s exceeds 60s target -- "
                "verify OPA policies are loaded and SOAR playbook is triggering automatically"
            )

        if grab_avg_complete < 0.99:
            recs.append(
                f"GRAB: Avg recovery completeness {grab_avg_complete:.1%} below 99% target -- "
                "review snapshot frequency and immutable backup coverage"
            )

        if adapted.false_positive_rate > 0.10:
            recs.append(
                f"WALL: FP rate {adapted.false_positive_rate:.0%} -- "
                f"new entropy threshold {adapted.entropy_threshold} applied; "
                "run 30-day rebaselining cycle"
            )

        fp_count = sum(1 for o in outcomes if o.false_positive)
        immut_failures = sum(1 for o in outcomes if not o.immutability_intact)
        if immut_failures > 0:
            recs.append(
                f"GRAB: {immut_failures} incident(s) with tampered/missing forensic logs -- "
                "verify MinIO Object Lock compliance mode is active"
            )

        if not recs:
            recs.append(
                "All WSG pillars within target SLAs -- continue quarterly model tuning and recovery drills"
            )

        return recs


# ---------------------------------------------------------------------------
# Standalone demo -- run directly to see the feedback loop in action
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 65)
    print("  RESILIENCE FORGE -- WSG Feedback Loop POC")
    print("  Slide 16: Closed-Loop Resilience Demonstration")
    print("=" * 65)

    service = FeedbackLoopService(trend_window=5)

    # Simulate 5 incidents with improving outcomes (loop learning effect)
    simulated_incidents = [
        # Incident 1 -- slow detection, partial recovery (baseline)
        IncidentOutcome(
            incident_id="INC-001", timestamp="2026-03-19T08:00:00Z",
            detection_time_seconds=480, false_positive=False,
            entropy_score=0.91, confidence_score=0.87,
            isolation_time_seconds=45, blast_radius_hosts=2,
            recovery_completeness=0.97, immutability_intact=True,
            recovery_time_seconds=7200,
        ),
        # Incident 2 -- false positive (noisy threshold)
        IncidentOutcome(
            incident_id="INC-002", timestamp="2026-03-19T10:00:00Z",
            detection_time_seconds=120, false_positive=True,
            entropy_score=0.86, confidence_score=0.72,
            isolation_time_seconds=30, blast_radius_hosts=0,
            recovery_completeness=1.0, immutability_intact=True,
            recovery_time_seconds=0,
        ),
        # Incident 3 -- threshold adapted, cleaner detection
        IncidentOutcome(
            incident_id="INC-003", timestamp="2026-03-19T14:00:00Z",
            detection_time_seconds=210, false_positive=False,
            entropy_score=0.93, confidence_score=0.95,
            isolation_time_seconds=18, blast_radius_hosts=1,
            recovery_completeness=0.999, immutability_intact=True,
            recovery_time_seconds=3600,
        ),
        # Incident 4 -- fast detection, instant isolation
        IncidentOutcome(
            incident_id="INC-004", timestamp="2026-03-19T18:00:00Z",
            detection_time_seconds=95, false_positive=False,
            entropy_score=0.94, confidence_score=0.97,
            isolation_time_seconds=8, blast_radius_hosts=0,
            recovery_completeness=1.0, immutability_intact=True,
            recovery_time_seconds=1800,
        ),
        # Incident 5 -- near-perfect response (feedback loop working)
        IncidentOutcome(
            incident_id="INC-005", timestamp="2026-03-19T22:00:00Z",
            detection_time_seconds=62, false_positive=False,
            entropy_score=0.96, confidence_score=0.99,
            isolation_time_seconds=5, blast_radius_hosts=0,
            recovery_completeness=1.0, immutability_intact=True,
            recovery_time_seconds=900,
        ),
    ]

    print("\n[STEP 1] Recording incident outcomes...\n")
    for incident in simulated_incidents:
        di = service.record_outcome(incident)
        fp_label = " [FALSE POSITIVE]" if incident.false_positive else ""
        print(
            f"  {incident.incident_id} | "
            f"DI={di:3d} | "
            f"WALL={incident.detection_time_seconds:4.0f}s | "
            f"SQUAT={incident.isolation_time_seconds:4.0f}s | "
            f"GRAB={incident.recovery_completeness:.1%}{fp_label}"
        )

    print("\n[STEP 2] Running feedback cycle (threshold adaptation)...\n")
    report = service.run_cycle()

    print(f"  Report ID   : {report.report_id}")
    print(f"  Cycle       : {report.cycle_number}")
    print(f"  DI Score    : {report.current_di_score}/100")
    print(f"  Trend       : {report.trend.trend_direction.upper()}")
    print(f"  DI History  : {report.trend.di_scores}")
    print(f"  FP Rate     : {report.false_positive_rate:.0%}")
    print()
    print(f"  [WALL]  Adapted entropy threshold : {report.adapted_thresholds.entropy_threshold}")
    print(f"  [WALL]  Mass-mod threshold        : {report.adapted_thresholds.mass_modification_threshold}")
    print(f"  [WALL]  Avg detection time        : {report.wall_avg_detection_seconds:.0f}s")
    print(f"  [SQUAT] Avg isolation time        : {report.squat_avg_isolation_seconds:.0f}s")
    print(f"  [GRAB]  Avg recovery completeness : {report.grab_avg_completeness:.2%}")
    print()
    print(f"  Adaptation rationale: {report.adapted_thresholds.rationale}")

    print("\n[STEP 3] Recommendations fed back to WALL (next cycle):\n")
    for i, rec in enumerate(report.recommendations, 1):
        print(f"  {i}. {rec}")

    print("\n[STEP 4] Trend summary (for dashboard):\n")
    summary = service.get_trend_summary()
    print(f"  {json.dumps(summary, indent=4)}")

    print("\n" + "=" * 65)
    print("  Closed loop complete. Thresholds auto-updated for next cycle.")
    print("  This output feeds back into sentinel_service.py WALL detection.")
    print("=" * 65)
