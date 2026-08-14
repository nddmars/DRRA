"""
Defensibility Index (DI) — canonical, formal implementation.

This module is the single source of truth for the Defensibility Index described
in the WSG paper (Section 4.4). Prior to this module the DI existed in three
disconnected, mutually inconsistent places (``vigil/detector.py``,
``backend/services/feedback_service.py``, and hard-coded literals in the
dashboard routes). Those are now thin callers of the formula defined here.

Formal definition (paper Section 4.4)
-------------------------------------
DI is a scalar in [0, 1] computed as a *weighted harmonic mean* of four
normalized component scores, each in (0, 1]:

    D_mttd = 1 - (MTTD / T_drrt)      detection efficiency
    C_mttc = 1 - (MTTC / T_mttc)      containment efficiency  (T_mttc = 90 s SLA)
    P_apcr = 1 - APCR                 prevention score (complement of the
                                      Attack Path Completion Rate)
    R_fid  = recovery_fidelity        proportion of recovery points passing all
                                      four GRAB validation stages

    DI = (Σ w_i) / Σ (w_i / x_i)      weighted harmonic mean

The harmonic mean is deliberate: a catastrophic failure in any single
component (e.g. APCR = 1.0 → P_apcr → 0) collapses the whole index, which a
weighted arithmetic mean would mask. This makes DI a conservative,
"penalizing" resilience metric.

The False Positive Rate (FPR) is *reported* alongside DI and, optionally,
folded into the detection component as a multiplicative penalty
(``fpr_penalty=True``). By default it is reported but not folded, so the
returned DI matches the four-term formula above exactly.

All weights and thresholds are configurable so the metric can be re-tuned per
threat model (paper: "tunable per threat model"). Defaults come from
``backend.config.settings`` when importable, otherwise from the constants
below — this keeps the module usable from standalone scripts and unit tests
without the FastAPI application context.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import mean, stdev
from typing import Dict, List, Optional, Sequence

# --- Defaults (used when backend.config.settings is unavailable) -------------
DEFAULT_WEIGHTS: Dict[str, float] = {
    "detection": 0.30,   # alpha  — D_mttd
    "containment": 0.30, # beta   — C_mttc
    "prevention": 0.25,  # gamma  — P_apcr
    "recovery": 0.15,    # delta  — R_fid
}
DEFAULT_MTTC_SLA_SECONDS = 90.0          # SHIELD containment SLA
DEFAULT_DETECTION_DEADLINE_SECONDS = 300.0  # T_drrt (threat response deadline)

# Small epsilon so a zero component does not divide-by-zero; it instead drives
# the harmonic mean toward (but not exactly) zero.
_EPS = 1e-6


def _load_config():
    """Best-effort load of weights/thresholds from the app settings."""
    weights = dict(DEFAULT_WEIGHTS)
    mttc_sla = DEFAULT_MTTC_SLA_SECONDS
    deadline = DEFAULT_DETECTION_DEADLINE_SECONDS
    try:  # pragma: no cover - exercised only inside the app context
        from config import settings  # type: ignore

        weights = {
            "detection": float(settings.DI_WEIGHT_DETECTION),
            "containment": float(settings.DI_WEIGHT_ISOLATION),
            "prevention": float(settings.DI_WEIGHT_RECOVERY),  # see note below
            "recovery": float(settings.DI_WEIGHT_IMMUTABILITY),
        }
        # NOTE: the legacy config keys are named detection/isolation/recovery/
        # immutability. We keep reading them for backwards compatibility but the
        # canonical mapping is detection/containment/prevention/recovery. When
        # the four legacy weights do not sum to ~1 for the new mapping we fall
        # back to the paper defaults to avoid a silently mis-weighted index.
        if not math.isclose(sum(weights.values()), 1.0, abs_tol=0.05):
            weights = dict(DEFAULT_WEIGHTS)
        mttc_sla = float(getattr(settings, "MTTC_TARGET_SECONDS", DEFAULT_MTTC_SLA_SECONDS))
    except Exception:
        pass
    return weights, mttc_sla, deadline


@dataclass
class IncidentRecord:
    """
    One incident's measured outcome across the three WSG pillars.

    These are *measurements*, not scores — the DI is derived from them. Every
    field is produced by the running system (or a replay harness), never
    hand-authored for display.
    """

    incident_id: str
    # WALL / VIGIL
    detected: bool                     # did VIGIL raise an alert at all?
    true_positive: bool                # was the alert a real threat?
    mttd_seconds: float                # time from attack start to detection
    # SQUAT / SHIELD
    mttc_seconds: float                # time from alert to full containment
    # Prevention
    apcr: float                        # Attack Path Completion Rate in [0, 1]
                                       # (fraction of the kill-chain completed
                                       #  before containment; 0 = fully blocked)
    # GRAB
    recovery_fidelity: float           # [0, 1] recovery points passing all 4 stages
    immutability_intact: bool = True   # forensic/backup store tamper-proof?
    timestamp: str = ""
    scenario: str = ""


@dataclass
class DefensibilityComponents:
    detection: float
    containment: float
    prevention: float
    recovery: float

    def as_dict(self) -> Dict[str, float]:
        return {
            "detection": round(self.detection, 4),
            "containment": round(self.containment, 4),
            "prevention": round(self.prevention, 4),
            "recovery": round(self.recovery, 4),
        }


@dataclass
class DefensibilityResult:
    """Full DI computation output, safe to serialise to JSON for the API."""

    defensibility_index: float          # [0, 1]
    score_0_100: int                    # convenience integer for the dashboard
    components: DefensibilityComponents
    weights: Dict[str, float]
    # Reported operational metrics (aggregate)
    mttd_seconds: float
    mttc_seconds: float
    apcr: float
    false_positive_rate: float
    recovery_fidelity: float
    sample_size: int

    def as_dict(self) -> Dict:
        return {
            "defensibility_index": round(self.defensibility_index, 4),
            "score_0_100": self.score_0_100,
            "components": self.components.as_dict(),
            "weights": {k: round(v, 4) for k, v in self.weights.items()},
            "metrics": {
                "mttd_seconds": round(self.mttd_seconds, 3),
                "mttc_seconds": round(self.mttc_seconds, 3),
                "apcr": round(self.apcr, 4),
                "false_positive_rate": round(self.false_positive_rate, 4),
                "recovery_fidelity": round(self.recovery_fidelity, 4),
            },
            "sample_size": self.sample_size,
        }


class DefensibilityIndex:
    """Computes the Defensibility Index from raw operational metrics."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        mttc_sla_seconds: Optional[float] = None,
        detection_deadline_seconds: Optional[float] = None,
        fpr_penalty: bool = False,
    ) -> None:
        cfg_weights, cfg_sla, cfg_deadline = _load_config()
        self.weights = self._normalize_weights(weights or cfg_weights)
        self.mttc_sla = float(mttc_sla_seconds or cfg_sla)
        self.detection_deadline = float(detection_deadline_seconds or cfg_deadline)
        self.fpr_penalty = fpr_penalty

    # -- component normalisation ---------------------------------------------
    @staticmethod
    def _normalize_weights(weights: Dict[str, float]) -> Dict[str, float]:
        required = ("detection", "containment", "prevention", "recovery")
        w = {k: max(0.0, float(weights.get(k, 0.0))) for k in required}
        total = sum(w.values())
        if total <= 0:
            return dict(DEFAULT_WEIGHTS)
        return {k: v / total for k, v in w.items()}

    @staticmethod
    def _clamp_unit(x: float) -> float:
        """Clamp a component score into (EPS, 1.0]."""
        if x != x:  # NaN guard
            return _EPS
        return max(_EPS, min(1.0, x))

    def compute_components(
        self,
        mttd_seconds: float,
        mttc_seconds: float,
        apcr: float,
        recovery_fidelity: float,
        false_positive_rate: float = 0.0,
    ) -> DefensibilityComponents:
        detection = 1.0 - (mttd_seconds / self.detection_deadline)
        if self.fpr_penalty:
            detection *= (1.0 - self._clamp_unit(false_positive_rate) if false_positive_rate < 1 else _EPS)
        containment = 1.0 - (mttc_seconds / self.mttc_sla)
        prevention = 1.0 - apcr
        recovery = recovery_fidelity
        return DefensibilityComponents(
            detection=self._clamp_unit(detection),
            containment=self._clamp_unit(containment),
            prevention=self._clamp_unit(prevention),
            recovery=self._clamp_unit(recovery),
        )

    def weighted_harmonic_mean(self, components: DefensibilityComponents) -> float:
        w = self.weights
        denom = (
            w["detection"] / components.detection
            + w["containment"] / components.containment
            + w["prevention"] / components.prevention
            + w["recovery"] / components.recovery
        )
        if denom <= 0:
            return 0.0
        return sum(w.values()) / denom

    def score(
        self,
        mttd_seconds: float,
        mttc_seconds: float,
        apcr: float,
        recovery_fidelity: float,
        false_positive_rate: float = 0.0,
        sample_size: int = 1,
    ) -> DefensibilityResult:
        components = self.compute_components(
            mttd_seconds, mttc_seconds, apcr, recovery_fidelity, false_positive_rate
        )
        di = self.weighted_harmonic_mean(components)
        return DefensibilityResult(
            defensibility_index=di,
            score_0_100=int(round(di * 100)),
            components=components,
            weights=self.weights,
            mttd_seconds=mttd_seconds,
            mttc_seconds=mttc_seconds,
            apcr=apcr,
            false_positive_rate=false_positive_rate,
            recovery_fidelity=recovery_fidelity,
            sample_size=sample_size,
        )

    # -- aggregation over many incidents -------------------------------------
    def score_incidents(self, incidents: Sequence[IncidentRecord]) -> DefensibilityResult:
        """
        Aggregate a batch of incident measurements into a single DI.

        FPR is computed over incidents that produced an alert
        (detected == True): FPR = false_positives / alerts. MTTD/MTTC are
        averaged over detected/contained incidents; APCR and recovery fidelity
        are averaged over all incidents.
        """
        if not incidents:
            # No data → an honest zero, not a fabricated score.
            return self.score(
                mttd_seconds=self.detection_deadline,
                mttc_seconds=self.mttc_sla,
                apcr=1.0,
                recovery_fidelity=0.0,
                false_positive_rate=0.0,
                sample_size=0,
            )

        agg = MetricsAggregator(incidents)
        return self.score(
            mttd_seconds=agg.mttd,
            mttc_seconds=agg.mttc,
            apcr=agg.apcr,
            recovery_fidelity=agg.recovery_fidelity,
            false_positive_rate=agg.false_positive_rate,
            sample_size=len(incidents),
        )


@dataclass
class MetricsAggregator:
    """Derives the aggregate operational metrics used by the DI from incidents."""

    incidents: Sequence[IncidentRecord]
    mttd: float = field(init=False)
    mttc: float = field(init=False)
    apcr: float = field(init=False)
    recovery_fidelity: float = field(init=False)
    false_positive_rate: float = field(init=False)

    def __post_init__(self) -> None:
        detected = [i for i in self.incidents if i.detected]
        alerts = detected  # every detection is an alert
        true_positives = [i for i in detected if i.true_positive]

        # MTTD/MTTC only meaningful for true-positive detections that were contained.
        contained = [i for i in true_positives if i.mttc_seconds is not None]

        self.mttd = mean([i.mttd_seconds for i in true_positives]) if true_positives else 0.0
        self.mttc = mean([i.mttc_seconds for i in contained]) if contained else 0.0
        self.apcr = mean([i.apcr for i in self.incidents]) if self.incidents else 1.0
        self.recovery_fidelity = (
            mean([i.recovery_fidelity for i in self.incidents]) if self.incidents else 0.0
        )
        self.false_positive_rate = (
            (len(alerts) - len(true_positives)) / len(alerts) if alerts else 0.0
        )


def confidence_interval_95(values: Sequence[float]) -> Dict[str, float]:
    """Mean and 95% CI half-width for a small sample (normal approximation)."""
    vals = list(values)
    n = len(vals)
    if n == 0:
        return {"mean": 0.0, "ci95": 0.0, "n": 0}
    m = mean(vals)
    if n < 2:
        return {"mean": round(m, 4), "ci95": 0.0, "n": n}
    sd = stdev(vals)
    ci = 1.96 * sd / math.sqrt(n)
    return {"mean": round(m, 4), "ci95": round(ci, 4), "n": n}
