#!/usr/bin/env python3
"""
DRRA-078 — Exact, seeded reproducibility bundle (SYNTHETIC scenario experiment).

Runs the **synthetic scenario** adversarial-replay evaluation at a declared seed
and archives the raw per-run observations (not only aggregates), the 95%
confidence intervals, and the execution environment, with a SHA-256 manifest.
Re-running at the same seed reproduces byte-identical raw observations, so any
reported aggregate can be traced back to individual runs.

IMPORTANT — provenance honesty: the inputs to these runs are produced by the
seeded synthetic scenario generator (``run_scenario_once``), NOT by the OTRF
datasets. This bundle therefore does not, and must not, claim OTRF dataset
provenance for its results. Real-telemetry ingestion has its own path
(``scripts/run_real_data.py`` over ``scripts/fetch_datasets.py``); reproducing
that end to end is separate future work.

Usage:
    python scripts/build_repro_bundle.py --reps 30 --seed 1234
    # -> results/synthetic_scenario_repro_bundle/{raw_runs.json, aggregates.json,
    #    environment.json, MANIFEST.json}
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(REPO, "results", "synthetic_scenario_repro_bundle")


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_exp = _load("wsg_experiment", "scripts/run_experiment.py")
_di = _load("wsg_defensibility", "backend/services/defensibility.py")
DefensibilityIndex = _di.DefensibilityIndex
confidence_interval_95 = _di.confidence_interval_95


def _incident_to_row(inc, run_index, seed_str, di_value):
    return {
        "run_index": run_index,
        "seed": seed_str,
        "detected": inc.detected,
        "true_positive": inc.true_positive,
        "mttd_seconds": round(inc.mttd_seconds, 6),
        "mttc_seconds": round(inc.mttc_seconds, 6),
        "apcr": round(inc.apcr, 6),
        "recovery_fidelity": round(inc.recovery_fidelity, 6),
        "defensibility_index": round(di_value, 6),
    }


def run_bundle(reps: int, seed: int) -> dict:
    """Deterministic: same (reps, seed) yields identical raw runs."""
    import random

    model = _exp._ml_mod.load_or_train_default()
    di_engine = DefensibilityIndex()
    conditions = {
        "A_change_healthcare": True,
        "B_moveit": True,
        "baseline_no_wsg": False,
    }
    out = {"seed": seed, "reps": reps, "model_backend": model.backend, "conditions": {}}

    for cond, det_enabled in conditions.items():
        scenario = "A_change_healthcare" if cond == "baseline_no_wsg" else cond
        runs, incidents = [], []
        for run_index in range(reps):
            seed_str = f"{seed}-{cond}-{run_index}"     # declared per-run seed
            rng = random.Random(seed_str)
            inc = _exp.run_scenario_once(model, scenario, rng, detection_enabled=det_enabled)
            di_value = di_engine.score_incidents([inc]).defensibility_index
            incidents.append(inc)
            runs.append(_incident_to_row(inc, run_index, seed_str, di_value))

        agg = di_engine.score_incidents(incidents)
        out["conditions"][cond] = {
            "runs": runs,
            "aggregate": {
                "mttd_seconds": confidence_interval_95([i.mttd_seconds for i in incidents if i.detected]),
                "mttc_seconds": confidence_interval_95([i.mttc_seconds for i in incidents if i.detected]),
                "apcr": confidence_interval_95([i.apcr for i in incidents]),
                "recovery_fidelity": confidence_interval_95([i.recovery_fidelity for i in incidents]),
                "defensibility_index": confidence_interval_95([r["defensibility_index"] for r in runs]),
                "false_positive_rate": agg.false_positive_rate,
            },
        }
    return out


def _environment() -> dict:
    def ver(mod):
        try:
            return __import__(mod).__version__
        except Exception:
            return "not installed"

    def git(*args):
        try:
            return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()
        except Exception:
            return "unknown"

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": {m: ver(m) for m in ("numpy", "sklearn", "scipy")},
        "git_commit": git("rev-parse", "HEAD"),
        "git_status_clean": git("status", "--porcelain") == "",
        # Inputs are the seeded synthetic scenario generator — NOT OTRF datasets.
        # Do not attach OTRF provenance here; these runs do not consume it.
        "inputs": {
            "source": "synthetic scenario generator (run_scenario_once), seeded",
            "otrf_datasets_used": False,
            "note": "OTRF real-telemetry ingestion is a separate path "
                    "(scripts/run_real_data.py); it is not an input to this bundle.",
        },
    }


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Build the seeded reproducibility bundle (DRRA-078)")
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    bundle = run_bundle(args.reps, args.seed)

    raw = {c: v["runs"] for c, v in bundle["conditions"].items()}
    agg = {c: v["aggregate"] for c, v in bundle["conditions"].items()}
    agg["_meta"] = {"seed": bundle["seed"], "reps": bundle["reps"], "model_backend": bundle["model_backend"]}

    paths = {
        "raw_runs.json": raw,
        "aggregates.json": agg,
        "environment.json": _environment(),
    }
    for name, obj in paths.items():
        with open(os.path.join(OUT, name), "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)

    manifest = {name: _sha256_of(os.path.join(OUT, name)) for name in paths}
    with open(os.path.join(OUT, "MANIFEST.json"), "w") as f:
        json.dump({"seed": args.seed, "reps": args.reps, "sha256": manifest}, f, indent=2, sort_keys=True)

    total = sum(len(v["runs"]) for v in bundle["conditions"].values())
    print(f"[*] Synthetic-scenario reproducibility bundle written to "
          f"results/synthetic_scenario_repro_bundle/ ({total} raw runs, seed={args.seed})")
    for name, digest in manifest.items():
        print(f"    {name}: {digest[:16]}…")


if __name__ == "__main__":
    main()
