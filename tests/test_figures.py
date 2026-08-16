"""Sanity tests for the figure-generation data logic (no rendering)."""

import importlib.util
import os
import sys

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_figs():
    pytest.importorskip("matplotlib")
    path = os.path.join(_REPO, "scripts", "generate_figures.py")
    spec = importlib.util.spec_from_file_location("wsg_figures", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wsg_figures"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_comparative_di_ordering():
    """WSG must lead; single-pillar architectures collapse under the harmonic DI."""
    figs = _load_figs()
    di = [figs._di_row(i) for i in range(len(figs.ARCHS))]
    conventional, soar, backup, wsg = di
    assert wsg > soar > 0.0
    assert conventional < 0.05 and backup < 0.05  # miss the 90s SLA → ~0


def test_profiles_aligned():
    figs = _load_figs()
    n = len(figs.ARCHS)
    assert all(len(figs.PROFILE[k]) == n for k in figs.PROFILE)


def test_wsg_profile_comes_from_measured_output_not_constants():
    """PR review: Figures 3–5 must load the WSG operating point from measured
    experiment output, never from hard-coded constants."""
    figs = _load_figs()
    # every metric's WSG slot (index 3) is a None sentinel in the static table
    assert all(figs.PROFILE[k][-1] is None for k in figs.PROFILE)
    wsg = figs.measured_wsg()
    for key in ("mttd", "mttc", "apcr", "rf_pct", "fpr_pct"):
        assert isinstance(wsg[key], (int, float))
    # a provenance manifest is written with the source file + its SHA-256
    import json
    man = json.load(open(os.path.join(figs._OUT, "figure_manifest.json")))
    assert man["results_file"] == "results/paper_metrics.json"
    assert len(man["results_sha256"]) == 64
    assert man["comparators_are_illustrative"] is True


def test_figure_generation_fails_when_measurement_missing():
    figs = _load_figs()
    figs._MEASURED = None
    orig = figs.experiment.run_experiment
    figs.experiment.run_experiment = lambda reps, seed: {"conditions": {}}
    try:
        with pytest.raises(RuntimeError):
            figs.measured_wsg()
    finally:
        figs.experiment.run_experiment = orig
        figs._MEASURED = None
