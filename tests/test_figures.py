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
