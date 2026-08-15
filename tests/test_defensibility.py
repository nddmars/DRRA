"""Unit tests for the canonical Defensibility Index engine."""

import math

import pytest

from services.defensibility import (
    DefensibilityIndex,
    IncidentRecord,
    MetricsAggregator,
    confidence_interval_95,
)


def _perfect_incident(iid="i"):
    return IncidentRecord(
        incident_id=iid, detected=True, true_positive=True,
        mttd_seconds=1.0, mttc_seconds=1.0, apcr=0.0,
        recovery_fidelity=1.0, immutability_intact=True,
    )


def test_di_in_unit_range():
    di = DefensibilityIndex()
    r = di.score(mttd_seconds=5, mttc_seconds=5, apcr=0.1, recovery_fidelity=0.95)
    assert 0.0 <= r.defensibility_index <= 1.0
    assert 0 <= r.score_0_100 <= 100


def test_perfect_defense_scores_high():
    di = DefensibilityIndex()
    r = di.score(mttd_seconds=0.0, mttc_seconds=0.0, apcr=0.0, recovery_fidelity=1.0)
    assert r.defensibility_index > 0.99


def test_harmonic_mean_penalizes_single_failure():
    """A catastrophic APCR (=1.0) must collapse DI even if all else is perfect."""
    di = DefensibilityIndex()
    strong = di.score(mttd_seconds=1, mttc_seconds=1, apcr=0.0, recovery_fidelity=1.0)
    collapsed = di.score(mttd_seconds=1, mttc_seconds=1, apcr=1.0, recovery_fidelity=1.0)
    assert collapsed.defensibility_index < 0.1
    assert collapsed.defensibility_index < strong.defensibility_index


def test_harmonic_below_arithmetic():
    """Weighted harmonic mean <= weighted arithmetic mean for the same inputs."""
    di = DefensibilityIndex()
    comp = di.compute_components(mttd_seconds=60, mttc_seconds=45, apcr=0.5, recovery_fidelity=0.8)
    hmean = di.weighted_harmonic_mean(comp)
    w = di.weights
    amean = (
        w["detection"] * comp.detection + w["containment"] * comp.containment
        + w["prevention"] * comp.prevention + w["recovery"] * comp.recovery
    )
    assert hmean <= amean + 1e-9


def test_weights_normalized():
    di = DefensibilityIndex(weights={"detection": 3, "containment": 3, "prevention": 2, "recovery": 2})
    assert math.isclose(sum(di.weights.values()), 1.0, abs_tol=1e-9)


def test_empty_incidents_is_honest_zero():
    di = DefensibilityIndex()
    r = di.score_incidents([])
    assert r.sample_size == 0
    assert r.defensibility_index < 0.05  # not a fabricated high score


def test_false_positive_rate_computation():
    incidents = [
        IncidentRecord("a", detected=True, true_positive=True, mttd_seconds=2, mttc_seconds=3,
                       apcr=0.2, recovery_fidelity=1.0),
        IncidentRecord("b", detected=True, true_positive=False, mttd_seconds=1, mttc_seconds=1,
                       apcr=0.0, recovery_fidelity=1.0),
    ]
    agg = MetricsAggregator(incidents)
    assert agg.false_positive_rate == pytest.approx(0.5)


def test_aggregate_over_incidents():
    di = DefensibilityIndex()
    r = di.score_incidents([_perfect_incident("a"), _perfect_incident("b")])
    assert r.sample_size == 2
    assert r.defensibility_index > 0.9


def test_confidence_interval():
    ci = confidence_interval_95([1.0, 1.0, 1.0])
    assert ci["mean"] == 1.0 and ci["ci95"] == 0.0 and ci["n"] == 3
    ci2 = confidence_interval_95([])
    assert ci2["n"] == 0
