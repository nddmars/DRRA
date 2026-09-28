"""
DRRA-019 — Explainable detection outputs.

The VIGIL model already ranks which Indicators-of-Behaviour drove an anomaly
score (``Detection.contributing_features``). This module turns that ranking plus
the raw feature vector into an analyst-facing *explanation*: each alert cites the
contributing signals in plain language, with the observed value and its relative
contribution, so a SOC analyst can triage without reading model internals.

It is a thin, dependency-free layer over ``vigil.ml_model`` — it does not change
scoring, so an explanation always matches the score it accompanies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from vigil.ml_model import FEATURES, Detection, IoBVector

# Plain-language meaning of each IoB feature, for the analyst. Kept in lockstep
# with FEATURES by a test so a new feature cannot ship without a description.
FEATURE_DESCRIPTIONS = {
    "file_rename_rate":
        "Rapid file renames/rewrites — the core signature of bulk encryption.",
    "lateral_movement_score":
        "Novel SMB/remote authentication to new peers — spread across hosts.",
    "privilege_escalation":
        "Token impersonation / LSASS access / Kerberoast — credential theft.",
    "shadow_copy_deletion_rate":
        "Shadow-copy or backup deletion — recovery inhibition before encryption.",
}


@dataclass
class Driver:
    feature: str
    description: str
    value: float
    contribution: float          # share of total positive signal, [0, 1]
    rank: int                    # 1 = strongest driver


@dataclass
class Explanation:
    is_anomaly: bool
    anomaly_score: float
    threshold: float
    backend: str
    summary: str
    drivers: List[Driver] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "threshold": self.threshold,
            "backend": self.backend,
            "summary": self.summary,
            "drivers": [
                {
                    "feature": d.feature,
                    "description": d.description,
                    "value": round(d.value, 4),
                    "contribution": round(d.contribution, 4),
                    "rank": d.rank,
                }
                for d in self.drivers
            ],
        }


def _ordered_features(detection: Detection, positive: List[str]) -> List[str]:
    """Authoritative order: the model's ranked contributors first (those with a
    positive value), then any remaining positive features by input order."""
    ranked = [f for f in detection.contributing_features if f in positive]
    rest = [f for f in positive if f not in ranked]
    return ranked + rest


def explain(detection: Detection, iob: IoBVector) -> Explanation:
    """Build an analyst-facing explanation for a Detection over an IoBVector."""
    values = dict(zip(FEATURES, iob.as_list()))
    positive = [f for f in FEATURES if values.get(f, 0.0) > 0.0]
    total = sum(values[f] for f in positive) or 1.0

    ordered = _ordered_features(detection, positive)
    drivers: List[Driver] = []
    for rank, feature in enumerate(ordered, start=1):
        drivers.append(
            Driver(
                feature=feature,
                description=FEATURE_DESCRIPTIONS.get(feature, feature),
                value=values[feature],
                contribution=values[feature] / total,
                rank=rank,
            )
        )

    if not drivers:
        summary = "No abnormal indicators of behaviour observed."
    elif detection.is_anomaly:
        top = drivers[0]
        others = f" (+{len(drivers) - 1} more signal(s))" if len(drivers) > 1 else ""
        summary = (
            f"Anomaly (score {detection.anomaly_score:.2f} ≥ {detection.threshold:.2f}); "
            f"primary driver: {top.feature}{others}."
        )
    else:
        summary = (
            f"Below threshold (score {detection.anomaly_score:.2f} < {detection.threshold:.2f}); "
            f"{len(drivers)} indicator(s) present but not alerting."
        )

    return Explanation(
        is_anomaly=detection.is_anomaly,
        anomaly_score=detection.anomaly_score,
        threshold=detection.threshold,
        backend=detection.backend,
        summary=summary,
        drivers=drivers,
    )


def explain_to_text(explanation: Explanation) -> str:
    """Render an explanation as a compact multi-line string for logs/alerts."""
    lines = [explanation.summary]
    for d in explanation.drivers:
        lines.append(
            f"  {d.rank}. {d.feature}={d.value:.3f} "
            f"({d.contribution * 100:.0f}% of signal) — {d.description}"
        )
    return "\n".join(lines)
