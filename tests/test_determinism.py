"""Tests for DRRA-085 (deterministic, backend-independent model training).

Two trainings on identical data with the same seed must produce identical
predictions. This holds for the seeded scikit-learn MLP (local default) and the
seeded Keras/TensorFlow backend (CI), so the detector is reproducible regardless
of which secondary backend is active.
"""

from vigil.ml_model import (
    SecondaryClassifier,
    _synthetic_benign_baseline,
    _synthetic_ransomware_positives,
)


def _probe_set():
    # deterministic probe vectors spanning benign and ransomware-like regions
    return [
        [2.0, 0.5, 0.0, 0.0],
        [14.0, 0.8, 0.0, 0.0],
        [22.0, 5.0, 4.0, 2.5],
        [28.0, 7.0, 6.0, 3.5],
        [1.0, 3.0, 1.0, 0.0],
    ]


def test_secondary_training_is_reproducible():
    benign = _synthetic_benign_baseline(300)
    ransomware = _synthetic_ransomware_positives(400)

    a = SecondaryClassifier().train(benign, ransomware)
    b = SecondaryClassifier().train(benign, ransomware)

    assert a.backend == b.backend  # same backend selected both times
    for v in _probe_set():
        pa, pb = a.predict_proba(v), b.predict_proba(v)
        assert abs(pa - pb) < 1e-9, f"non-deterministic on {v}: {pa} != {pb}"


def test_decisions_are_reproducible():
    benign = _synthetic_benign_baseline(300)
    ransomware = _synthetic_ransomware_positives(400)
    a = SecondaryClassifier().train(benign, ransomware)
    b = SecondaryClassifier().train(benign, ransomware)
    for v in _probe_set():
        assert a.is_ransomware(v) == b.is_ransomware(v)
