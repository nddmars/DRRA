#!/usr/bin/env python3
"""
DRRA-079 — False-positive rate on representative held-out benign workloads.

The prior "0% FPR" figure was measured on adversarial-only replay, which has no
benign negatives and therefore no valid FPR denominator. This evaluation instead
scores a diverse set of **held-out benign workloads** (legitimate bulk-file jobs,
admin sessions, software installs) drawn from a different distribution than the
model's training baseline, and reports:

  * FPR = false positives / benign windows, with a Wilson 95% confidence interval
    (the correct interval for a proportion, including when the count is 0);
  * recall on ransomware-chain windows, for context;
  * the primary-only (IsolationForest) FPR, to show the ensemble's suppression.

The benign evaluation set is generated with a seed disjoint from the training
baseline, so it represents unseen hosts/time-windows and does not leak into
training (see also DRRA-080 for the feedback-loop leakage fix).

Usage:
    python scripts/run_fpr_eval.py --benign 400 --positive 200
"""

from __future__ import annotations

import argparse
import math
import os
import random
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from vigil.ml_model import IoBVector, load_or_train_ensemble  # noqa: E402


def wilson_ci(k: int, n: int, z: float = 1.96):
    """Wilson score interval for a binomial proportion (valid at k=0)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def benign_workloads(n, rng):
    """Diverse legitimate operations — NONE are ransomware. Held-out negatives.

    Mixes quiet hosts, nightly bulk-file/backup jobs (high rename, no privesc/
    shadow), admin sessions (network logons, no shadow), and software installs
    (some file + privilege activity, no shadow-copy deletion)."""
    out = []
    for _ in range(n):
        kind = rng.random()
        if kind < 0.4:          # quiet host
            out.append([rng.uniform(0, 1.5), rng.uniform(0, 0.8), 0.0, 0.0])
        elif kind < 0.7:        # bulk file / backup job
            out.append([rng.uniform(12, 28), rng.uniform(0, 1.0), 0.0, 0.0])
        elif kind < 0.9:        # admin session
            out.append([rng.uniform(0, 3), rng.uniform(3, 7), rng.uniform(0, 1), 0.0])
        else:                   # software install / update
            out.append([rng.uniform(4, 10), rng.uniform(0, 1), rng.uniform(1, 3), 0.0])
    return out


def ransomware_windows(n, rng):
    out = []
    for _ in range(n):
        out.append([rng.uniform(18, 30), rng.uniform(3, 8),
                    float(rng.randint(2, 7)), rng.uniform(1.5, 4.0)])
    return out


def evaluate(n_benign=400, n_pos=200, seed=4242):
    model = load_or_train_ensemble()
    rng_b = random.Random(f"benign-{seed}")   # disjoint from training seeds (7/11)
    rng_p = random.Random(f"ranse-{seed}")
    benign = benign_workloads(n_benign, rng_b)
    positive = ransomware_windows(n_pos, rng_p)

    fp = sum(1 for v in benign if model.score(IoBVector(*v)).is_anomaly)
    primary_fp = sum(1 for v in benign if model.primary.score(IoBVector(*v)).is_anomaly)
    tp = sum(1 for v in positive if model.score(IoBVector(*v)).is_anomaly)

    fpr = fp / n_benign
    lo, hi = wilson_ci(fp, n_benign)
    return {
        "backend": model.backend,
        "n_benign": n_benign,
        "n_positive": n_pos,
        "false_positives": fp,
        "fpr": fpr,
        "fpr_95ci": [round(lo, 4), round(hi, 4)],
        "primary_only_fpr": primary_fp / n_benign,
        "recall": tp / n_pos,
    }


def main():
    ap = argparse.ArgumentParser(description="FPR on held-out benign workloads (DRRA-079)")
    ap.add_argument("--benign", type=int, default=400)
    ap.add_argument("--positive", type=int, default=200)
    ap.add_argument("--seed", type=int, default=4242)
    args = ap.parse_args()
    r = evaluate(args.benign, args.positive, args.seed)
    print("\n## FPR on representative held-out benign workloads (DRRA-079)\n")
    print(f"  model backend      : {r['backend']}")
    print(f"  benign windows (N) : {r['n_benign']}")
    print(f"  false positives    : {r['false_positives']}")
    print(f"  FPR                : {r['fpr']*100:.2f}%  (95% CI "
          f"{r['fpr_95ci'][0]*100:.2f}–{r['fpr_95ci'][1]*100:.2f}%)")
    print(f"  primary-only FPR   : {r['primary_only_fpr']*100:.2f}%  (ensemble suppresses this)")
    print(f"  recall on attacks  : {r['recall']*100:.2f}%")
    print("\n[note] FPR is measured on held-out benign negatives, not inferred from an "
          "adversarial-only replay. A real benign endpoint capture would strengthen this "
          "further (representative production traffic).")


if __name__ == "__main__":
    main()
