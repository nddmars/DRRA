#!/usr/bin/env python3
"""
DRRA-081 — Measured comparator harness.

The prior comparator table stated operational values (MTTD/MTTC/FPR) for
external tool *classes* — "conventional ML detection", "SOAR automation",
"backup-centric recovery" — as capability assumptions. Those numbers were never
measured on our bench and must not be presented as measured results or used to
support a superiority claim.

This harness replaces the *measurable* part of that comparison with real
measurement. It compares detector **architectures we can actually run** — the
same VIGIL pipeline in ablated configurations — on one shared held-out
evaluation set, and reports only quantities produced by scoring:

    * primary-only            : unsupervised IsolationForest alone
                                (the "anomaly-detection only" architecture class)
    * two-stage ensemble      : IsolationForest + supervised secondary (VIGIL)
    * two-stage + feedback    : the ensemble after operational feedback
                                (confirmed-benign labels folded back in)

For each configuration it measures, on the SAME held-out benign negatives and
ransomware-chain positives:

    FPR, recall, precision, F1, and false-positive count

with a Wilson 95% interval on FPR. Nothing is hard-coded.

What this harness deliberately does NOT do
------------------------------------------
It does not emit MTTD/MTTC/recovery numbers for external commercial products.
Those operational values are not measurable on this bench (no vendor licences,
no production endpoint capture), so they are excluded here and must remain
labelled illustrative wherever they appear — never used in a superiority claim.
See docs/CLAIM_TRACEABILITY.md (DRRA-081).

Usage:
    python scripts/run_comparator.py --benign 400 --positive 200
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from vigil.ml_model import (  # noqa: E402
    IoBVector,
    SecondaryClassifier,
    TwoStageDetector,
    VigilAnomalyModel,
    _synthetic_benign_baseline,
    _synthetic_ransomware_positives,
)


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Reuse the same held-out benign/positive generators as the FPR evaluation so
# the comparator and the FPR study measure on comparable distributions.
_fpr = _load("wsg_fpr_for_cmp", "scripts/run_fpr_eval.py")
benign_workloads = _fpr.benign_workloads
ransomware_windows = _fpr.ransomware_windows
wilson_ci = _fpr.wilson_ci


def _measure(name, predict, benign, positive):
    """Score one architecture (predict: features->bool) on the shared eval set."""
    fp = sum(1 for v in benign if predict(v))
    tp = sum(1 for v in positive if predict(v))
    n_b, n_p = len(benign), len(positive)
    fpr = fp / n_b
    recall = tp / n_p
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    lo, hi = wilson_ci(fp, n_b)
    return {
        "architecture": name,
        "false_positives": fp,
        "fpr": round(fpr, 4),
        "fpr_95ci": [round(lo, 4), round(hi, 4)],
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
    }


def _feedback_secondary(primary, benign_train, ransomware_train, benign_eval_seed, cycles):
    """Fold confirmed-benign operational batches back into the secondary, the
    way the closed loop does — but drawn from a training seed disjoint from the
    held-out evaluation set, so measurement stays leakage-free (DRRA-080)."""
    import random

    secondary = SecondaryClassifier().train(benign_train, ransomware_train)
    train = list(benign_train)
    for c in range(1, cycles + 1):
        rng = random.Random(f"cmp-train-{benign_eval_seed}-{c}")
        # legitimate high-volume file jobs: high rename, no privesc/shadow
        train += [[rng.uniform(12.0, 26.0), rng.uniform(0.0, 1.5), 0.0, 0.0]
                  for _ in range(60)]
        secondary = SecondaryClassifier().train(train, ransomware_train)
    return secondary


def evaluate(n_benign=400, n_pos=200, seed=4242, feedback_cycles=5):
    import random

    rng_b = random.Random(f"benign-{seed}")   # same seeds as run_fpr_eval
    rng_p = random.Random(f"ranse-{seed}")
    benign = benign_workloads(n_benign, rng_b)
    positive = ransomware_windows(n_pos, rng_p)

    primary = VigilAnomalyModel().train(_synthetic_benign_baseline())
    benign_train = _synthetic_benign_baseline(300)
    ransomware_train = _synthetic_ransomware_positives(400)
    secondary = SecondaryClassifier().train(benign_train, ransomware_train)
    ensemble = TwoStageDetector(primary, secondary)

    fb_secondary = _feedback_secondary(
        primary, benign_train, ransomware_train, seed, feedback_cycles
    )
    fb_ensemble = TwoStageDetector(primary, fb_secondary)

    def p_primary(v):
        return primary.score(IoBVector(*v)).is_anomaly

    def p_ensemble(v):
        return ensemble.score(IoBVector(*v)).is_anomaly

    def p_feedback(v):
        return fb_ensemble.score(IoBVector(*v)).is_anomaly

    rows = [
        _measure("primary-only (IsolationForest)", p_primary, benign, positive),
        _measure("two-stage ensemble (VIGIL)", p_ensemble, benign, positive),
        _measure(f"two-stage + feedback ({feedback_cycles} cycles)",
                 p_feedback, benign, positive),
    ]
    return {
        "n_benign": n_benign,
        "n_positive": n_pos,
        "seed": seed,
        "secondary_backend": secondary.backend,
        "measured_axes": ["fpr", "recall", "precision", "f1"],
        "excluded_axes": {
            "reason": "not measurable on this bench (no vendor licences / "
                      "production endpoint capture)",
            "axes": ["external-tool MTTD", "external-tool MTTC",
                     "external-tool recovery fidelity"],
        },
        "architectures": rows,
    }


def to_markdown(res):
    rows = ["| Architecture | FPR (95% CI) | Recall | Precision | F1 |",
            "|---|---|---|---|---|"]
    for a in res["architectures"]:
        ci = a["fpr_95ci"]
        rows.append(
            f"| {a['architecture']} | {a['fpr']*100:.1f}% "
            f"({ci[0]*100:.1f}–{ci[1]*100:.1f}%) | {a['recall']*100:.1f}% | "
            f"{a['precision']*100:.1f}% | {a['f1']:.3f} |"
        )
    return "\n".join(rows)


def main():
    ap = argparse.ArgumentParser(description="Measured comparator harness (DRRA-081)")
    ap.add_argument("--benign", type=int, default=400)
    ap.add_argument("--positive", type=int, default=200)
    ap.add_argument("--seed", type=int, default=4242)
    ap.add_argument("--cycles", type=int, default=5)
    args = ap.parse_args()
    res = evaluate(args.benign, args.positive, args.seed, args.cycles)

    print("\n## Measured detector-architecture comparison (DRRA-081)\n")
    print(f"_Secondary backend: {res['secondary_backend']}; "
          f"N_benign={res['n_benign']}, N_positive={res['n_positive']}, "
          f"seed={res['seed']}._\n")
    print(to_markdown(res))
    print("\n_Only detection-quality axes are shown; every value is measured by "
          "scoring the shared held-out set. External commercial-tool operational "
          "values (MTTD/MTTC/recovery) are not measurable on this bench and are "
          "excluded from this comparison — they must not be used in a superiority "
          "claim (see docs/CLAIM_TRACEABILITY.md)._")


if __name__ == "__main__":
    main()
