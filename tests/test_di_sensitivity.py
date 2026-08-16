"""Tests for DRRA-082 (Defensibility Index sensitivity & robustness).

The DI engine is pure arithmetic (no ML backend), so these assertions are exact
and deterministic across environments.
"""

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


def test_ranking_is_robust_to_weight_choice():
    s = _load("wsg_di_s1", "scripts/run_di_sensitivity.py")
    wr = s.weight_robustness(s.STRONG, s.WEAK, samples=1500, seed=7)
    # a clearly-stronger operating point must out-score a clearly-weaker one for
    # every reasonable weighting, not just the paper defaults
    assert wr["ordering_preserved_fraction"] == 1.0
    assert wr["min_margin"] > 0.0


def test_di_is_monotonic_in_every_input():
    s = _load("wsg_di_s2", "scripts/run_di_sensitivity.py")
    mo = s.monotonicity_scan(samples=800, seed=11)
    assert mo["checks"] > 0
    assert mo["violations"] == 0


def test_harmonic_mean_penalizes_weakest_component():
    s = _load("wsg_di_s3", "scripts/run_di_sensitivity.py")
    pe = s.penalization_test()
    # improving the weakest component raises DI far more than improving a strong
    # one — the reason a weighted harmonic mean is used instead of an average
    assert pe["weak_dominates"] is True
    assert (pe["gain_from_improving_weak_component"]
            > pe["gain_from_improving_strong_component"])


def test_simplex_weights_sum_to_one():
    s = _load("wsg_di_s4", "scripts/run_di_sensitivity.py")
    import random
    rng = random.Random("unit")
    for _ in range(100):
        w = s.simplex_weights(rng)
        assert abs(sum(w.values()) - 1.0) < 1e-9
        assert all(v >= 0.0 for v in w.values())
