"""Unit tests for the VIGIL IsolationForest anomaly model."""

import pytest

from vigil.ml_model import (
    FEATURES,
    IoBVector,
    VigilAnomalyModel,
    SecondaryClassifier,
    TwoStageDetector,
    load_or_train_default,
    load_or_train_ensemble,
    _synthetic_benign_baseline,
    _synthetic_ransomware_positives,
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


# ---- two-stage ensemble ----------------------------------------------------

@pytest.fixture(scope="module")
def ensemble():
    return load_or_train_ensemble()


def test_secondary_classifier_separates_classes():
    clf = SecondaryClassifier().train(
        _synthetic_benign_baseline(400), _synthetic_ransomware_positives(400)
    )
    assert clf.backend in ("tensorflow_mlp", "sklearn_mlp", "logistic_heuristic")
    benign = clf.predict_proba([0.5, 0.3, 0.0, 0.0])
    ransom = clf.predict_proba([25.0, 7.0, 6.0, 4.0])
    assert ransom > benign


def test_ensemble_flags_ransomware(ensemble):
    d = ensemble.score(IoBVector(25.0, 7.0, 6.0, 4.0))
    assert d.primary_flag is True
    assert d.secondary_flag is True
    assert d.is_anomaly is True
    assert "+" in d.backend  # e.g. isolation_forest+sklearn_mlp


def test_ensemble_suppresses_benign(ensemble):
    d = ensemble.score(IoBVector(0.5, 0.3, 0.0, 0.0))
    assert d.is_anomaly is False


def test_ensemble_requires_both_stages(ensemble):
    """Final decision is the AND of stage 1 and stage 2."""
    d = ensemble.score(IoBVector(25.0, 7.0, 6.0, 4.0))
    assert d.is_anomaly == (d.primary_flag and d.secondary_flag)


def test_ensemble_type(ensemble):
    assert isinstance(ensemble, TwoStageDetector)
