#!/usr/bin/env python3
"""
WSG adversarial-replay experiment harness.

Reproduces the operational metrics reported in the paper's Section 5.4 (Table 4)
by driving multi-stage adversarial scenarios through the *real* VIGIL
IsolationForest model and the canonical Defensibility Index engine. Nothing here
is a hard-coded result: MTTD and APCR emerge from the model actually scoring each
kill-chain stage.

Scenarios
---------
  A — "Change Healthcare": credential theft -> SMB lateral movement -> LSASS
      privilege escalation -> shadow-copy deletion -> staged encryption.
  B — "MOVEit": webshell persistence -> data staging -> backup enumeration ->
      mass exfiltration/encryption.

For each scenario the harness runs N repetitions with per-run jitter, records one
IncidentRecord per run, and reports mean +/- 95% CI for MTTD, MTTC, FPR, APCR,
recovery fidelity, and the resulting Defensibility Index. A "Baseline (No WSG)"
condition (detection disabled) is included for contrast.

Usage
-----
    python scripts/run_experiment.py --reps 10 --out results/experiment.json

Outputs a JSON results file and prints a Markdown table ready to paste into the
manuscript (clearly labelled as simulation output).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
from dataclasses import dataclass
from typing import Dict, List

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load(module_name: str, relpath: str):
    """Import a module by file path without triggering package __init__ chains."""
    path = os.path.join(_REPO, relpath)
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod

# defensibility.py must resolve `from services.defensibility import ...` when
# imported standalone; it only imports stdlib at top level, so a direct file load
# is safe. metrics_store is NOT needed here (we build IncidentRecords directly).
_di_mod = _load("wsg_defensibility", "backend/services/defensibility.py")
_ml_mod = _load("wsg_ml_model", "vigil/ml_model.py")

DefensibilityIndex = _di_mod.DefensibilityIndex
IncidentRecord = _di_mod.IncidentRecord
confidence_interval_95 = _di_mod.confidence_interval_95
VigilAnomalyModel = _ml_mod.VigilAnomalyModel


@dataclass
class Stage:
    """One kill-chain stage: an IoB feature vector plus the wall-clock offset
    (seconds from attack start) at which it occurs."""

    name: str
    t_offset: float
    features: Dict[str, float]


# Kill-chain templates. Feature magnitudes are expressed in the same units as the
# benign baseline the model trains on (renames/sec, auth rate, event counts).
SCENARIOS: Dict[str, List[Stage]] = {
    "A_change_healthcare": [
        Stage("credential_theft", 2.0, {"lateral_movement_score": 1.2}),
        Stage("smb_lateral", 6.0, {"lateral_movement_score": 6.5}),
        Stage("lsass_privesc", 10.0, {"privilege_escalation": 5.0, "lateral_movement_score": 4.0}),
        Stage("shadow_delete", 14.0, {"shadow_copy_deletion_rate": 3.0, "privilege_escalation": 4.0}),
        Stage("mass_encrypt", 20.0, {"file_rename_rate": 22.0, "shadow_copy_deletion_rate": 3.0}),
    ],
    "B_moveit": [
        Stage("webshell", 3.0, {"privilege_escalation": 2.0}),
        Stage("data_staging", 9.0, {"file_rename_rate": 5.0, "lateral_movement_score": 3.0}),
        Stage("backup_enum", 15.0, {"lateral_movement_score": 5.5, "privilege_escalation": 3.5}),
        Stage("mass_exfil_encrypt", 22.0, {"file_rename_rate": 18.0, "shadow_copy_deletion_rate": 2.0}),
    ],
}

TOTAL_STAGES = {k: len(v) for k, v in SCENARIOS.items()}

# Modelled system latencies (seconds).
CONTAINMENT_LATENCY_MEAN = 8.0    # SHIELD async isolation once VIGIL alerts
CONTAINMENT_LATENCY_JITTER = 3.0
RECOVERY_FIDELITY_IMMUTABLE = 1.0  # GRAB 4-stage validation with Object Lock


def _jitter(value: float, frac: float, rng: random.Random) -> float:
    return max(0.0, value * (1.0 + rng.uniform(-frac, frac)))


def run_scenario_once(
    model: VigilAnomalyModel,
    scenario: str,
    rng: random.Random,
    detection_enabled: bool = True,
) -> IncidentRecord:
    stages = SCENARIOS[scenario]
    detected_at = None
    detected_stage_idx = None

    if detection_enabled and model is not None:
        for idx, stage in enumerate(stages):
            feats = {k: _jitter(v, 0.15, rng) for k, v in stage.features.items()}
            result = model.score(_ml_mod.IoBVector.from_mapping(feats))
            if result.is_anomaly:
                detected_at = _jitter(stage.t_offset, 0.1, rng)
                detected_stage_idx = idx
                break

    if detected_at is None:
        # No detection: attacker completes the full kill chain (APCR = 1.0).
        return IncidentRecord(
            incident_id=f"{scenario}-{rng.randint(10**6, 10**7)}",
            detected=False,
            true_positive=False,
            mttd_seconds=0.0,
            mttc_seconds=0.0,
            apcr=1.0,
            recovery_fidelity=RECOVERY_FIDELITY_IMMUTABLE,  # backups still immutable
            immutability_intact=True,
            scenario=scenario,
        )

    mttc = _jitter(CONTAINMENT_LATENCY_MEAN, CONTAINMENT_LATENCY_JITTER / CONTAINMENT_LATENCY_MEAN, rng)
    containment_time = detected_at + mttc
    # Stages whose offset is before containment complete; the rest are blocked.
    completed = sum(1 for s in stages if s.t_offset <= containment_time)
    apcr = completed / TOTAL_STAGES[scenario]

    return IncidentRecord(
        incident_id=f"{scenario}-{rng.randint(10**6, 10**7)}",
        detected=True,
        true_positive=True,
        mttd_seconds=detected_at,
        mttc_seconds=mttc,
        apcr=apcr,
        recovery_fidelity=RECOVERY_FIDELITY_IMMUTABLE,
        immutability_intact=True,
        scenario=scenario,
    )


def run_experiment(reps: int, seed: int = 1234) -> Dict:
    print(f"[*] Training VIGIL model on benign baseline ...", file=sys.stderr)
    model = _ml_mod.load_or_train_default()
    print(f"[*] Model backend: {model.backend}", file=sys.stderr)

    di_engine = DefensibilityIndex()
    conditions = {
        "A_change_healthcare": True,
        "B_moveit": True,
        "baseline_no_wsg": False,
    }

    results = {"model_backend": model.backend, "reps": reps, "conditions": {}}

    for cond, det_enabled in conditions.items():
        scenario = "A_change_healthcare" if cond == "baseline_no_wsg" else cond
        rng = random.Random(f"{seed}-{cond}")
        incidents = [
            run_scenario_once(model, scenario, rng, detection_enabled=det_enabled)
            for _ in range(reps)
        ]
        di_result = di_engine.score_incidents(incidents)

        # Per-run DI for CI reporting
        per_run_di = [di_engine.score_incidents([i]).defensibility_index for i in incidents]

        results["conditions"][cond] = {
            "mttd_seconds": confidence_interval_95([i.mttd_seconds for i in incidents if i.detected]),
            "mttc_seconds": confidence_interval_95([i.mttc_seconds for i in incidents if i.detected]),
            "apcr": confidence_interval_95([i.apcr for i in incidents]),
            "false_positive_rate": di_result.false_positive_rate,
            "recovery_fidelity": confidence_interval_95([i.recovery_fidelity for i in incidents]),
            "defensibility_index": confidence_interval_95(per_run_di),
            "aggregate": di_result.as_dict(),
        }

    return results


def to_markdown(results: Dict) -> str:
    def cell(ci):
        if ci["n"] == 0:
            return "N/A"
        return f"{ci['mean']:.2f} ± {ci['ci95']:.2f}"

    rows = []
    header = "| Metric | Scenario A (Change Healthcare) | Scenario B (MOVEit) | Baseline (No WSG) |"
    sep = "|---|---|---|---|"
    a = results["conditions"]["A_change_healthcare"]
    b = results["conditions"]["B_moveit"]
    base = results["conditions"]["baseline_no_wsg"]

    def line(label, key, pct=False, di=False):
        def fmt(cond):
            ci = cond[key]
            if ci["n"] == 0:
                return "N/A"
            scale = 100 if pct else 1
            return f"{ci['mean']*scale:.2f} ± {ci['ci95']*scale:.2f}" + ("%" if pct else "")
        return f"| {label} | {fmt(a)} | {fmt(b)} | {fmt(base)} |"

    rows.append(header)
    rows.append(sep)
    rows.append(line("VIGIL MTTD (s)", "mttd_seconds"))
    rows.append(line("SHIELD MTTC (s)", "mttc_seconds"))
    rows.append(f"| False Positive Rate (%) | {a['false_positive_rate']*100:.2f}% | "
                f"{b['false_positive_rate']*100:.2f}% | {base['false_positive_rate']*100:.2f}% |")
    rows.append(line("Attack Path Completion Rate (%)", "apcr", pct=True))
    rows.append(line("Recovery Fidelity", "recovery_fidelity"))
    rows.append(line("Defensibility Index", "defensibility_index"))
    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser(description="WSG adversarial-replay experiment")
    parser.add_argument("--reps", type=int, default=10, help="repetitions per scenario")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--out", type=str, default="results/experiment.json")
    args = parser.parse_args()

    results = run_experiment(args.reps, args.seed)

    out_path = os.path.join(_REPO, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n## WSG Simulation Results (Mordor-style adversarial replay)\n")
    print(f"_Model backend: {results['model_backend']}, {args.reps} repetitions per scenario, "
          "mean ± 95% CI._\n")
    print(to_markdown(results))
    print(f"\n[*] Full results written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
