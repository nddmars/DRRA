"""Tests for DRRA-079 (benign FPR) and DRRA-080 (leakage-free feedback eval)."""

import importlib.util
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_wilson_ci_valid_at_zero():
    fpr = _load("wsg_fpr", "scripts/run_fpr_eval.py")
    lo, hi = fpr.wilson_ci(0, 400)
    assert lo == 0.0 and 0.0 < hi < 0.05   # 0 successes still yields a finite upper bound
    lo2, hi2 = fpr.wilson_ci(20, 400)
    assert lo2 < 0.05 < hi2


def test_fpr_eval_has_valid_denominator_and_recall():
    fpr = _load("wsg_fpr2", "scripts/run_fpr_eval.py")
    r = fpr.evaluate(n_benign=200, n_pos=100, seed=4242)
    assert r["n_benign"] == 200                     # real denominator, not adversarial-only
    assert 0.0 <= r["fpr"] <= 1.0
    assert r["false_positives"] == round(r["fpr"] * r["n_benign"])
    assert r["fpr"] <= r["primary_only_fpr"] + 1e-9  # ensemble suppresses primary FPs
    assert r["recall"] >= 0.8                        # still catches ransomware windows


def test_benign_workloads_have_no_shadow_signal():
    fpr = _load("wsg_fpr3", "scripts/run_fpr_eval.py")
    import random
    rows = fpr.benign_workloads(100, random.Random(1))
    assert all(v[3] == 0.0 for v in rows)           # benign never deletes shadow copies


def test_leakfree_feedback_is_disjoint_and_converges():
    fb = _load("wsg_fb_lf", "scripts/run_feedback_experiment.py")
    res = fb.run_leakfree(cycles=4, seed=99)
    assert res["eval_is_heldout"] is True
    per = res["per_cycle"]
    assert len(per) == 4
    # FPR measured on the fixed held-out set must not increase over cycles
    assert per[-1]["heldout_fpr"] <= per[0]["heldout_fpr"]
    # recall on held-out attacks stays high (no collapse from FP suppression)
    assert all(x["heldout_recall"] >= 0.8 for x in per)


def test_leakfree_eval_set_is_fixed():
    fb = _load("wsg_fb_lf2", "scripts/run_feedback_experiment.py")
    a = fb.run_leakfree(cycles=3, seed=7)
    b = fb.run_leakfree(cycles=3, seed=7)
    # The held-out evaluation set is the DRRA-080 leakage-free invariant: it is
    # generated once from a fixed seed and never trained on, so its fingerprint
    # must be identical run-to-run regardless of the secondary-classifier backend
    # (the trained model itself may be nondeterministic under TensorFlow).
    assert a["heldout_fingerprint"] == b["heldout_fingerprint"]
    assert a["n_heldout_benign"] == b["n_heldout_benign"]
