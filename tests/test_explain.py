"""
DRRA-019 — Explainable detection outputs.

Each alert must cite the contributing signals for the analyst. These tests build
Detection objects directly (no training needed) so they are fast and
deterministic, and verify the explanation layer over vigil.ml_model.
"""

from __future__ import annotations

import os
import sys

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from vigil.ml_model import FEATURES, Detection, IoBVector  # noqa: E402
from vigil.explain import (  # noqa: E402
    FEATURE_DESCRIPTIONS,
    explain,
    explain_to_text,
)


def _detection(score, contributing, threshold=0.85, backend="isolation_forest"):
    return Detection(
        anomaly_score=score,
        is_anomaly=score >= threshold,
        threshold=threshold,
        contributing_features=contributing,
        backend=backend,
    )


def test_every_feature_has_a_description():
    # A new IoB feature cannot ship without an analyst-facing description.
    assert set(FEATURE_DESCRIPTIONS) == set(FEATURES)


def test_anomaly_cites_contributing_signals():
    iob = IoBVector(file_rename_rate=8.0, lateral_movement_score=0.0,
                    privilege_escalation=2.0, shadow_copy_deletion_rate=1.0)
    det = _detection(0.93, ["file_rename_rate", "privilege_escalation", "shadow_copy_deletion_rate"])
    exp = explain(det, iob)
    assert exp.is_anomaly is True
    driver_features = [d.feature for d in exp.drivers]
    # only positive features appear, in the model's ranked order
    assert driver_features == ["file_rename_rate", "privilege_escalation", "shadow_copy_deletion_rate"]
    assert "lateral_movement_score" not in driver_features
    # each driver cites a plain-language description
    assert all(d.description for d in exp.drivers)
    # primary driver is named in the summary
    assert "file_rename_rate" in exp.summary


def test_contributions_sum_to_one():
    iob = IoBVector(file_rename_rate=3.0, lateral_movement_score=1.0,
                    privilege_escalation=0.0, shadow_copy_deletion_rate=0.0)
    det = _detection(0.9, ["file_rename_rate", "lateral_movement_score"])
    exp = explain(det, iob)
    assert abs(sum(d.contribution for d in exp.drivers) - 1.0) < 1e-9
    ranks = [d.rank for d in exp.drivers]
    assert ranks == [1, 2]


def test_benign_all_zero_vector_has_no_drivers():
    iob = IoBVector()
    det = _detection(0.05, [])
    exp = explain(det, iob)
    assert exp.drivers == []
    assert exp.is_anomaly is False
    assert "No abnormal" in exp.summary


def test_below_threshold_but_signals_present():
    iob = IoBVector(privilege_escalation=1.0)
    det = _detection(0.40, ["privilege_escalation"])
    exp = explain(det, iob)
    assert exp.is_anomaly is False
    assert len(exp.drivers) == 1
    assert "not alerting" in exp.summary


def test_ranked_order_falls_back_to_input_order_for_unranked_positives():
    # Model omitted a positive feature from its ranking; it should still appear,
    # after the ranked ones, so the analyst sees every active signal.
    iob = IoBVector(file_rename_rate=5.0, shadow_copy_deletion_rate=2.0)
    det = _detection(0.95, ["file_rename_rate"])  # shadow omitted from ranking
    exp = explain(det, iob)
    features = [d.feature for d in exp.drivers]
    assert features == ["file_rename_rate", "shadow_copy_deletion_rate"]


def test_explain_to_text_is_human_readable():
    iob = IoBVector(file_rename_rate=4.0, privilege_escalation=1.0)
    det = _detection(0.9, ["file_rename_rate", "privilege_escalation"])
    text = explain_to_text(explain(det, iob))
    assert "file_rename_rate" in text
    assert "% of signal" in text
    # one summary line + one line per driver
    assert len(text.splitlines()) == 3


def test_as_dict_is_json_safe():
    import json
    iob = IoBVector(file_rename_rate=4.0)
    det = _detection(0.9, ["file_rename_rate"])
    d = explain(det, iob).as_dict()
    json.dumps(d)  # must not raise
    assert d["drivers"][0]["feature"] == "file_rename_rate"
