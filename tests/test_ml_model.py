"""Unit tests for the VIGIL IsolationForest anomaly model."""

import pytest

from vigil.ml_model import (
    FEATURES,
    IoBVector,
    VigilAnomalyModel,
    load_or_train_default,
    _synthetic_benign_baseline,
)


@pytest.fixture(scope="module")
def trained_model():
    return load_or_train_default()


def test_model_trains(trained_model):
    assert trained_model.backend in ("isolation_forest", "zscore_fallback")


def test_benign_input_scores_low(trained_model):
    """A quiet, baseline-like vector should not be flagged."""
    benign = IoBVector(file_rename_rate=0.5, lateral_movement_score=0.3,
                       privilege_escalation=0.0, shadow_copy_deletion_rate=0.0)
    d = trained_model.score(benign)
    assert d.anomaly_score < trained_model.threshold
    assert d.is_anomaly is False


def test_ransomware_pattern_flagged(trained_model):
    """Mass renames + shadow-copy deletion + privesc must trip the detector."""
    attack = IoBVector(file_rename_rate=25.0, lateral_movement_score=7.0,
                       privilege_escalation=6.0, shadow_copy_deletion_rate=4.0)
    d = trained_model.score(attack)
    assert d.is_anomaly is True
    assert d.anomaly_score >= trained_model.threshold
    assert len(d.contributing_features) > 0


def test_feature_vector_roundtrip():
    m = {f: float(i + 1) for i, f in enumerate(FEATURES)}
    vec = IoBVector.from_mapping(m)
    assert vec.as_list() == [1.0, 2.0, 3.0, 4.0]


def test_wrong_feature_count_raises(trained_model):
    with pytest.raises(ValueError):
        trained_model.score([1.0, 2.0])  # only 2 of 4 features


def test_contamination_default(trained_model):
    # Model targets <= 2% FPR via contamination=0.02
    assert trained_model.contamination == pytest.approx(0.02)


def test_synthetic_baseline_shape():
    base = _synthetic_benign_baseline(50)
    assert len(base) == 50
    assert all(len(row) == len(FEATURES) for row in base)
