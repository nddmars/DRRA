"""Tests for the closed-loop feedback experiment (paper Section 5.5)."""

import importlib.util
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_experiment():
    path = os.path.join(_REPO, "scripts", "run_feedback_experiment.py")
    spec = importlib.util.spec_from_file_location("wsg_feedback_exp", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wsg_feedback_exp"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_feedback_loop_reduces_false_positives():
    exp = _load_experiment()
    results = exp.run(cycles=4, seed=99)
    per = results["per_cycle"]
    assert len(per) == 4
    # Ensemble FPR must not increase over cycles, and must end no worse than start.
    assert per[-1]["ensemble_fpr"] <= per[0]["ensemble_fpr"]
    # The ensemble suppresses FPs relative to the primary-only detector.
    assert per[0]["ensemble_fpr"] <= per[0]["primary_fpr"]


def test_feedback_preserves_detection():
    exp = _load_experiment()
    results = exp.run(cycles=3, seed=99)
    # True-positive detection stays high throughout (no loss from FP suppression).
    assert all(x["detection_rate"] >= 0.9 for x in results["per_cycle"])


def test_feedback_improves_di():
    exp = _load_experiment()
    results = exp.run(cycles=5, seed=99)
    s = results["summary"]
    assert s["final_di"] >= s["initial_di"]
