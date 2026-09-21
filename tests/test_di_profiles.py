"""
DRRA-048 — Versioned DI weighting profiles by business context.

Verifies the profile registry (well-formedness, versioning, lookup) and that
selecting a profile changes the weighting while preserving the DI scale and
attaching a comparability tag to the result.
"""

from __future__ import annotations

import math
import os
import sys

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_REPO, os.path.join(_REPO, "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

from services.di_profiles import (  # noqa: E402
    DEFAULT_PROFILE_ID,
    WeightingProfile,
    active_profile_id,
    get_profile,
    list_profiles,
)
from services.defensibility import DefensibilityIndex, DEFAULT_WEIGHTS  # noqa: E402


# --- registry integrity -----------------------------------------------------

def test_every_profile_is_wellformed():
    profiles = list_profiles()
    assert profiles, "no profiles registered"
    for p in profiles:
        assert set(p.weights) == {"detection", "containment", "prevention", "recovery"}
        assert math.isclose(sum(p.weights.values()), 1.0, abs_tol=1e-6)
        assert all(w >= 0 for w in p.weights.values())
        assert p.version  # semantic version present
        assert p.key == f"{p.profile_id}@{p.version}"


def test_default_profile_matches_paper_weights():
    p = get_profile(DEFAULT_PROFILE_ID)
    assert p.weights == DEFAULT_WEIGHTS


def test_malformed_profile_is_rejected():
    with pytest.raises(ValueError):
        WeightingProfile("bad", "1.0.0", "weights don't sum to 1",
                         {"detection": 0.5, "containment": 0.2,
                          "prevention": 0.2, "recovery": 0.2})
    with pytest.raises(ValueError):
        WeightingProfile("bad2", "1.0.0", "missing a component",
                         {"detection": 0.5, "containment": 0.5})


def test_unknown_profile_raises():
    with pytest.raises(KeyError):
        get_profile("does-not-exist")


def test_version_mismatch_raises():
    known = list_profiles()[0]
    with pytest.raises(ValueError):
        get_profile(known.profile_id, version="9.9.9")


# --- effect on scoring ------------------------------------------------------

def _score_with(profile_id):
    di = DefensibilityIndex.from_profile(profile_id)
    return di.score(
        mttd_seconds=30.0, mttc_seconds=30.0, apcr=0.2,
        recovery_fidelity=0.9, false_positive_rate=0.05, sample_size=10,
    )


def test_profile_is_recorded_on_result():
    res = _score_with("recovery_critical")
    assert res.profile_id == "recovery_critical"
    assert res.profile_version == "1.0.0"
    assert res.as_dict()["profile"] == {"id": "recovery_critical", "version": "1.0.0"}


def test_from_profile_uses_profile_weights():
    di = DefensibilityIndex.from_profile("detection_critical")
    assert math.isclose(di.weights["detection"], 0.40, abs_tol=1e-9)
    assert math.isclose(di.weights["recovery"], 0.10, abs_tol=1e-9)


def test_different_profiles_change_di_but_stay_in_unit_interval():
    # Same measured incident, different business weightings.
    balanced = _score_with("balanced")
    recovery = _score_with("recovery_critical")
    detection = _score_with("detection_critical")
    for r in (balanced, recovery, detection):
        assert 0.0 <= r.defensibility_index <= 1.0
        assert 0 <= r.score_0_100 <= 100
    # Components are identical across profiles (only weights differ) — this is
    # what keeps the metric comparable in principle across profiles.
    assert balanced.components.as_dict() == recovery.components.as_dict()
    # Weighting recovery (the strong component here, 0.9) more should not lower
    # the index relative to balanced.
    assert recovery.defensibility_index >= balanced.defensibility_index


def test_weakest_component_still_dominates_under_any_profile():
    # A catastrophic prevention failure (apcr=1.0 -> prevention ~ 0) must
    # collapse the index regardless of how little weight prevention carries.
    for pid in ("balanced", "detection_critical", "recovery_critical"):
        di = DefensibilityIndex.from_profile(pid)
        res = di.score(mttd_seconds=1.0, mttc_seconds=1.0, apcr=1.0,
                       recovery_fidelity=1.0, false_positive_rate=0.0)
        assert res.defensibility_index < 0.1, pid


def test_active_profile_id_selection(monkeypatch):
    monkeypatch.delenv("DI_PROFILE", raising=False)
    assert active_profile_id() == DEFAULT_PROFILE_ID
    monkeypatch.setenv("DI_PROFILE", "recovery_critical")
    assert active_profile_id() == "recovery_critical"
    # An unknown value degrades to the documented default, not an error.
    monkeypatch.setenv("DI_PROFILE", "nonsense")
    assert active_profile_id() == DEFAULT_PROFILE_ID


def test_default_constructor_is_unchanged_and_tagged_balanced():
    # Back-compat: constructing DI without a profile still works and reports the
    # balanced identity, so existing callers keep the paper weighting.
    di = DefensibilityIndex()
    res = di.score(mttd_seconds=30.0, mttc_seconds=30.0, apcr=0.2,
                   recovery_fidelity=0.9)
    assert res.profile_id == "balanced"
    assert res.profile_version == "1.0.0"
