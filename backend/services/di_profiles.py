"""
DRRA-048 — Versioned Defensibility Index weighting profiles by business context.

The Defensibility Index (backend/services/defensibility.py) combines four
component scores with a set of weights. Different organizations legitimately
weight resilience differently: a data-centric business cares most about
recoverability, a high-velocity environment about fast detection/containment, a
regulated one about immutability. This module provides *named, versioned*
weighting profiles so a deployment can select a business-appropriate weighting
without editing code or forking the metric.

Comparability guarantee (the reason profiles are versioned)
-----------------------------------------------------------
The DI remains a weighted harmonic mean of the SAME four component definitions
on the SAME [0, 1] scale regardless of profile — only the weights differ. That
means two DI scores are directly comparable **only when they were produced by
the same (profile_id, profile_version)**. Every profile therefore carries an
immutable id + semantic version, and a computed score records which profile
produced it (see DefensibilityResult.profile_id / profile_version). Changing a
profile's weights is a version bump, never an in-place edit, so historical
scores stay attributable to the exact weighting that produced them. The registry
is keyed by ``(profile_id, version)`` so multiple versions coexist and a
historical score can always be reproduced against the exact weighting it names.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Tuple

# The four canonical component keys the DI expects.
_COMPONENTS = ("detection", "containment", "prevention", "recovery")


@dataclass(frozen=True)
class WeightingProfile:
    """An immutable, versioned set of DI component weights for a business context.

    ``weights`` is stored as an immutable mapping so a caller cannot mutate a
    registered profile in place (which would silently change historical scores
    without a version bump)."""

    profile_id: str
    version: str
    description: str
    weights: Mapping[str, float]

    def __post_init__(self) -> None:
        keys = set(self.weights)
        if keys != set(_COMPONENTS):
            raise ValueError(
                f"profile {self.profile_id!r} must weight exactly {_COMPONENTS}, got {sorted(keys)}"
            )
        if any(w < 0 for w in self.weights.values()):
            raise ValueError(f"profile {self.profile_id!r} has a negative weight")
        if not math.isclose(sum(self.weights.values()), 1.0, abs_tol=1e-6):
            raise ValueError(
                f"profile {self.profile_id!r} weights must sum to 1.0 (got {sum(self.weights.values())})"
            )
        # Freeze the weights so the registered profile is truly immutable.
        object.__setattr__(self, "weights", MappingProxyType(dict(self.weights)))

    @property
    def key(self) -> str:
        return f"{self.profile_id}@{self.version}"


# All registered profile versions. Each is a distinct business posture; the
# weights sum to 1.0 and cover exactly the four components so the DI scale is
# preserved. Add a NEW WeightingProfile entry (new version) rather than editing
# an existing one — historical scores must stay reproducible.
_ALL_PROFILES: List[WeightingProfile] = [
    WeightingProfile(
        "balanced", "1.0.0",
        "Paper default. Even emphasis across detect / contain / prevent / recover.",
        {"detection": 0.30, "containment": 0.30, "prevention": 0.25, "recovery": 0.15},
    ),
    WeightingProfile(
        "detection_critical", "1.0.0",
        "High-velocity environments: weight fast detection and containment.",
        {"detection": 0.40, "containment": 0.35, "prevention": 0.15, "recovery": 0.10},
    ),
    WeightingProfile(
        "recovery_critical", "1.0.0",
        "Data-centric business: recoverability dominates.",
        {"detection": 0.20, "containment": 0.20, "prevention": 0.20, "recovery": 0.40},
    ),
    WeightingProfile(
        "prevention_critical", "1.0.0",
        "Segmented / least-privilege estates: weight blocking attack-path completion.",
        {"detection": 0.25, "containment": 0.30, "prevention": 0.35, "recovery": 0.10},
    ),
    WeightingProfile(
        "regulated_data", "1.0.0",
        "Compliance-driven: weight immutability / recovery fidelity.",
        {"detection": 0.20, "containment": 0.25, "prevention": 0.20, "recovery": 0.35},
    ),
]

# Registry keyed by (profile_id, version) so multiple versions coexist.
_PROFILES: Dict[Tuple[str, str], WeightingProfile] = {
    (p.profile_id, p.version): p for p in _ALL_PROFILES
}

DEFAULT_PROFILE_ID = "balanced"


def _semver(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


# Active (latest) version per profile id, chosen by highest semantic version.
_ACTIVE_VERSION: Dict[str, str] = {}
for _p in _ALL_PROFILES:
    _cur = _ACTIVE_VERSION.get(_p.profile_id)
    if _cur is None or _semver(_p.version) > _semver(_cur):
        _ACTIVE_VERSION[_p.profile_id] = _p.version


def list_profiles() -> List[WeightingProfile]:
    """Return the active (latest) version of each profile, stable order by id."""
    return [get_profile(pid) for pid in sorted(_ACTIVE_VERSION)]


def list_all_versions() -> List[WeightingProfile]:
    """Return every registered profile version (stable order by id, then version)."""
    return [_PROFILES[k] for k in sorted(_PROFILES)]


def get_profile(profile_id: str, version: Optional[str] = None) -> WeightingProfile:
    """Look up a profile by id, optionally pinning an exact version.

    With no version, the active (latest) version is returned. Raises KeyError for
    an unknown id and ValueError for an unknown version, so a caller cannot
    silently score against a different weighting than intended.
    """
    if profile_id not in _ACTIVE_VERSION:
        raise KeyError(
            f"unknown DI weighting profile {profile_id!r}; known: {sorted(_ACTIVE_VERSION)}"
        )
    resolved = version or _ACTIVE_VERSION[profile_id]
    key = (profile_id, resolved)
    if key not in _PROFILES:
        have = sorted(ver for (pid, ver) in _PROFILES if pid == profile_id)
        raise ValueError(
            f"profile {profile_id!r} has no version {resolved!r}; available: {have}"
        )
    return _PROFILES[key]


def active_profile_id() -> str:
    """The profile a deployment selects via the ``DI_PROFILE`` env var.

    Falls back to the balanced (paper) profile when unset or unknown, so a
    misconfiguration degrades to the documented default rather than an error.
    """
    pid = os.getenv("DI_PROFILE", DEFAULT_PROFILE_ID)
    return pid if pid in _ACTIVE_VERSION else DEFAULT_PROFILE_ID
