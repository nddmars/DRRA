#!/usr/bin/env python3
"""
DRRA-082 — Defensibility Index sensitivity and robustness analysis.

The Defensibility Index (DI) combines four component scores with weights that
default to 0.30 / 0.30 / 0.25 / 0.15. Any fixed weighting is a modelling choice,
so before the DI can be relied on to *rank* systems we have to show the ranking
is not an artefact of that choice. This harness measures three properties, all
by evaluating the real DI engine (backend/services/defensibility.py):

1. Weight robustness
   Sample weight vectors uniformly from the 4-simplex (Dirichlet(1,1,1,1)) and
   check how often a clearly-stronger operating point out-scores a clearly-weaker
   one. A metric whose ordering flips under reasonable re-weighting is not a safe
   ranking tool; a robust one preserves the ordering for ~all weightings.

2. Monotonicity
   DI must be non-increasing in MTTD, MTTC and APCR (higher = worse) and
   non-decreasing in recovery fidelity (higher = better). We scan random points
   and perturb one metric at a time, counting any violation.

3. Penalization (harmonic-mean property)
   The weighted harmonic mean is chosen so the weakest component dominates. We
   verify that, at a mixed operating point, DI is more sensitive to improving the
   weakest component than the strongest — the behaviour an arithmetic mean would
   not give.

Everything is deterministic under a fixed seed.

Usage:
    python scripts/run_di_sensitivity.py --samples 2000
"""

from __future__ import annotations

import argparse
import importlib.util
import math
import os
import random
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_di = _load("wsg_di_sens", "backend/services/defensibility.py")
DefensibilityIndex = _di.DefensibilityIndex

# A DI operating point: the four raw metrics the index consumes.
# mttd/mttc in seconds, apcr and recovery_fidelity in [0, 1].
STRONG = {"mttd": 2.5, "mttc": 7.8, "apcr": 0.20, "rf": 1.00}
WEAK = {"mttd": 120.0, "mttc": 70.0, "apcr": 0.85, "rf": 0.70}

_KEYS = ("detection", "containment", "prevention", "recovery")


def _di_value(weights, point):
    eng = DefensibilityIndex(weights=weights)
    return eng.score(
        mttd_seconds=point["mttd"], mttc_seconds=point["mttc"],
        apcr=point["apcr"], recovery_fidelity=point["rf"],
    ).defensibility_index


def simplex_weights(rng):
    """One weight vector sampled uniformly from the 4-simplex (Dirichlet 1,1,1,1)."""
    g = [-math.log(1.0 - rng.random()) for _ in _KEYS]   # Exp(1) samples
    s = sum(g)
    return {k: g[i] / s for i, k in enumerate(_KEYS)}


def weight_robustness(strong, weak, samples, seed):
    """Fraction of sampled weightings for which DI(strong) > DI(weak)."""
    rng = random.Random(f"weights-{seed}")
    wins = 0
    strong_vals, weak_vals = [], []
    for _ in range(samples):
        w = simplex_weights(rng)
        ds = _di_value(w, strong)
        dw = _di_value(w, weak)
        strong_vals.append(ds)
        weak_vals.append(dw)
        if ds > dw:
            wins += 1
    return {
        "samples": samples,
        "ordering_preserved_fraction": round(wins / samples, 6),
        "strong_di_range": [round(min(strong_vals), 4), round(max(strong_vals), 4)],
        "weak_di_range": [round(min(weak_vals), 4), round(max(weak_vals), 4)],
        "min_margin": round(min(s - w for s, w in zip(strong_vals, weak_vals)), 6),
    }


def _random_point(rng):
    return {
        "mttd": rng.uniform(1.0, 250.0),
        "mttc": rng.uniform(1.0, 85.0),
        "apcr": rng.uniform(0.0, 1.0),
        "rf": rng.uniform(0.4, 1.0),
    }


def monotonicity_scan(samples, seed):
    """Count monotonicity violations across random points (one metric at a time).

    Expected directions: DI ↓ as mttd/mttc/apcr ↑; DI ↑ as rf ↑.
    Comparisons allow equality (component clamping can saturate DI)."""
    rng = random.Random(f"mono-{seed}")
    w = None  # default paper weights
    violations = 0
    checks = 0
    tol = 1e-9
    for _ in range(samples):
        p = _random_point(rng)
        base = _di_value(w, p)
        # worsen each "higher is worse" metric -> DI must not increase
        for key, bump in (("mttd", 20.0), ("mttc", 5.0), ("apcr", 0.05)):
            q = dict(p)
            q[key] = min(q[key] + bump, {"mttd": 299.0, "mttc": 89.0, "apcr": 1.0}[key])
            checks += 1
            if _di_value(w, q) > base + tol:
                violations += 1
        # improve recovery fidelity -> DI must not decrease
        q = dict(p)
        q["rf"] = min(q["rf"] + 0.05, 1.0)
        checks += 1
        if _di_value(w, q) < base - tol:
            violations += 1
    return {"checks": checks, "violations": violations}


def penalization_test():
    """At a mixed point (one weak, rest strong), improving the weakest component
    must raise DI more than the same relative improvement to the strongest —
    the defining behaviour of the weighted harmonic mean."""
    # containment is the weak component here (mttc near the 90 s SLA)
    base = {"mttd": 2.5, "mttc": 80.0, "apcr": 0.20, "rf": 1.00}
    w = None
    base_di = _di_value(w, base)

    # improve the WEAK component (halve mttc -> containment score roughly doubles)
    weak_better = dict(base, mttc=40.0)
    gain_weak = _di_value(w, weak_better) - base_di

    # improve a STRONG component by a comparable relative amount (halve mttd)
    strong_better = dict(base, mttd=1.25)
    gain_strong = _di_value(w, strong_better) - base_di

    return {
        "base_di": round(base_di, 4),
        "gain_from_improving_weak_component": round(gain_weak, 4),
        "gain_from_improving_strong_component": round(gain_strong, 4),
        "weak_dominates": gain_weak > gain_strong,
    }


def analyze(samples=2000, seed=4242):
    return {
        "weight_robustness": weight_robustness(STRONG, WEAK, samples, seed),
        "monotonicity": monotonicity_scan(max(200, samples // 4), seed),
        "penalization": penalization_test(),
    }


def main():
    ap = argparse.ArgumentParser(description="DI sensitivity/robustness (DRRA-082)")
    ap.add_argument("--samples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=4242)
    args = ap.parse_args()
    r = analyze(args.samples, args.seed)

    wr = r["weight_robustness"]
    mo = r["monotonicity"]
    pe = r["penalization"]
    print("\n## Defensibility Index sensitivity & robustness (DRRA-082)\n")
    print("### 1. Weight robustness (uniform 4-simplex sampling)")
    print(f"  strong point out-scores weak point in "
          f"{wr['ordering_preserved_fraction']*100:.2f}% of {wr['samples']} weightings")
    print(f"  strong DI range across weights : {wr['strong_di_range']}")
    print(f"  weak   DI range across weights : {wr['weak_di_range']}")
    print(f"  smallest strong-minus-weak margin : {wr['min_margin']}")
    print("\n### 2. Monotonicity")
    print(f"  violations: {mo['violations']} / {mo['checks']} directional checks")
    print("\n### 3. Penalization (harmonic-mean property)")
    print(f"  base DI                       : {pe['base_di']}")
    print(f"  gain, improve WEAK component  : +{pe['gain_from_improving_weak_component']}")
    print(f"  gain, improve STRONG component: +{pe['gain_from_improving_strong_component']}")
    print(f"  weak component dominates      : {pe['weak_dominates']}")


if __name__ == "__main__":
    main()
