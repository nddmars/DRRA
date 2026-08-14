"""Unit tests for the in-process metrics store and its DI aggregation."""

from services.defensibility import IncidentRecord
from services.metrics_store import MetricsStore


def test_empty_store_reports_zero():
    store = MetricsStore()
    summary = store.summary()
    assert summary["incidents_total"] == 0
    assert summary["defensibility"]["score_0_100"] <= 5  # honest, not fabricated


def test_records_and_aggregates():
    store = MetricsStore()
    store.record_incident(IncidentRecord(
        "i1", detected=True, true_positive=True, mttd_seconds=2.0, mttc_seconds=5.0,
        apcr=0.2, recovery_fidelity=1.0,
    ))
    summary = store.summary()
    assert summary["incidents_total"] == 1
    assert summary["mttc_seconds"] == 5.0
    assert summary["defensibility"]["score_0_100"] > 0


def test_live_timing():
    store = MetricsStore()
    store.mark_attack_start("i1", ts=100.0)
    mttd = store.mark_detected("i1", ts=104.0)
    mttc = store.mark_contained("i1", ts=112.0)
    assert mttd == 4.0
    assert mttc == 8.0


def test_clear():
    store = MetricsStore()
    store.record_incident(IncidentRecord(
        "i1", detected=True, true_positive=True, mttd_seconds=1, mttc_seconds=1,
        apcr=0.0, recovery_fidelity=1.0,
    ))
    store.clear()
    assert store.summary()["incidents_total"] == 0
