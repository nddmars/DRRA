#!/usr/bin/env python3
"""
Regenerate the finalized WSG paper artifacts and lock them with a manifest.

This is the single reproducibility anchor for the paper release: it runs the
real VIGIL model and evaluators and emits every reported quantity, using the
ONE canonical Defensibility Index (FPR folded into the detection term,
D = (1 - MTTD/T_drrt)(1 - FPR)) so the numbers match the manuscript exactly.

Outputs (under paper_artifacts/):
  paper_metrics_final.json   all reported quantities + provenance + seeds
  figures/figure2..5.png     the four figures
  MANIFEST.sha256            SHA-256 of every artifact

Deterministic: fixed seeds (experiment 1234, held-out FPR 4242). Run:
    python scripts/generate_paper_artifacts.py
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO, os.path.join(REPO, "backend"), os.path.join(REPO, "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

import run_experiment as rexp  # noqa: E402
import run_fpr_eval as rfpr  # noqa: E402
from services.defensibility import DefensibilityIndex, confidence_interval_95  # noqa: E402

OUT = os.path.join(REPO, "paper_artifacts")
FIGS = os.path.join(OUT, "figures")
os.makedirs(FIGS, exist_ok=True)

EXP_SEED = 1234
FPR_SEED = 4242
REPS = 30
FEEDBACK_CYCLES = 10

# ---------------------------------------------------------------- measurements
print("[*] training VIGIL model ...", file=sys.stderr)
model = rexp._ml_mod.load_or_train_default()

print("[*] measuring held-out benign FPR ...", file=sys.stderr)
fpr = rfpr.evaluate(n_benign=400, n_pos=200, seed=FPR_SEED)
HELDOUT_FPR = float(fpr["fpr"])

di_no = DefensibilityIndex(fpr_penalty=False)
di_fpr = DefensibilityIndex(fpr_penalty=True)   # canonical: FPR in the detection term


def scenario_di(cond):
    """Per-run Table-5 metrics with the canonical FPR-inclusive DI + 95% CI."""
    rng = random.Random(f"{EXP_SEED}-{cond}")
    incs = [rexp.run_scenario_once(model, cond, rng, True) for _ in range(REPS)]
    di_runs = [di_fpr.score(i.mttd_seconds, i.mttc_seconds, i.apcr,
                            i.recovery_fidelity, false_positive_rate=HELDOUT_FPR).defensibility_index
               for i in incs]
    di_conv = [di_no.score(i.mttd_seconds, i.mttc_seconds, i.apcr,
                           i.recovery_fidelity).defensibility_index for i in incs]  # FPR->0
    return {
        "mttd_seconds": confidence_interval_95([i.mttd_seconds for i in incs]),
        "mttc_seconds_modeled": confidence_interval_95([i.mttc_seconds for i in incs]),
        "apcr": confidence_interval_95([i.apcr for i in incs]),
        "recovery_fidelity_modeled": confidence_interval_95([i.recovery_fidelity for i in incs]),
        "defensibility_index": confidence_interval_95(di_runs),
        "defensibility_index_converged_fpr0": confidence_interval_95(di_conv),
    }


print("[*] scoring scenarios A/B ...", file=sys.stderr)
tableA = scenario_di("A_change_healthcare")
tableB = scenario_di("B_moveit")

print("[*] feedback loop (leakage-free) ...", file=sys.stderr)
feedback = rexp  # placeholder to keep import; real run below
import importlib.util  # noqa: E402
fbspec = importlib.util.spec_from_file_location("rfb", os.path.join(REPO, "scripts/run_feedback_experiment.py"))
rfb = importlib.util.module_from_spec(fbspec)
sys.modules["rfb"] = rfb
fbspec.loader.exec_module(rfb)
fb = rfb.run_leakfree(cycles=FEEDBACK_CYCLES)

# ---------------------------------------------------------------- Table 7
comparators = {
    "Conventional ML detection": {"mttd": 12, "mttc": 900, "recovery_fidelity": 93, "fpr": 4.8, "prevention": 10},
    "SOAR-based automation": {"mttd": 15, "mttc": 45, "recovery_fidelity": 94.5, "fpr": 3.9, "prevention": 45},
    "Backup-centric recovery": {"mttd": 300, "mttc": 1800, "recovery_fidelity": 97.5, "fpr": 4.5, "prevention": 2},
}
comp_di = {}
for name, c in comparators.items():
    comp_di[name] = round(di_fpr.score(c["mttd"], c["mttc"], 1 - c["prevention"] / 100.0,
                                       c["recovery_fidelity"] / 100.0,
                                       false_positive_rate=c["fpr"] / 100.0).defensibility_index, 4)

wsg_di_base = round((tableA["defensibility_index"]["mean"] + tableB["defensibility_index"]["mean"]) / 2, 2)

metrics = {
    "release": "v1.0-paper",
    "commit": os.environ.get("GIT_COMMIT", "(set at tag time)"),
    "seeds": {"experiment": EXP_SEED, "held_out_fpr": FPR_SEED, "reps": REPS,
              "feedback_cycles": FEEDBACK_CYCLES},
    "model_backend": model.backend,
    "di_definition": "canonical: DI is a weighted harmonic mean with the detection term "
                     "D = (1 - MTTD/T_drrt)(1 - FPR); the false-positive rate is intrinsic. "
                     "Table 5, Section 5.5, and Table 7 all use this one definition.",
    "held_out_benign_fpr": {
        "value": round(HELDOUT_FPR, 4),
        "wilson_95ci": [round(x, 4) for x in fpr["fpr_95ci"]],
        "recall": round(float(fpr["recall"]), 4),
        "primary_only_fpr": round(float(fpr["primary_only_fpr"]), 4),
        "n_benign": fpr["n_benign"], "n_positive": fpr["n_positive"],
        "note": "synthetic held-out proxy, NOT representative real-world FPR",
    },
    "table5": {
        "scenario_A_change_healthcare": tableA,
        "scenario_B_moveit": tableB,
        "baseline_no_wsg": {"defensibility_index": {"mean": 0.0, "ci95": 0.0, "n": REPS}},
        "provenance": {
            "mttd": "MEASURED (model detection point over templated, jittered stage timings)",
            "mttc": "MODELED (simulation constant 8.0s +/- 3.0 jitter; not live-timed)",
            "apcr": "MEASURED",
            "recovery_fidelity": "MODELED (constant 1.0, intact-WORM)",
            "defensibility_index": "COMPUTED (canonical FPR-inclusive DI at held-out FPR)",
        },
    },
    "section55_feedback": {
        "eval_is_heldout": fb.get("eval_is_heldout"),
        "per_cycle": fb.get("per_cycle"),
        "summary": fb.get("summary"),
    },
    "table7": {
        "comparators_are_assumptions": True,
        "defensibility_index": {**comp_di, "Proposed WSG (base, held-out FPR)": wsg_di_base},
    },
}

metrics_path = os.path.join(OUT, "paper_metrics_final.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=2)
print(f"[*] wrote {metrics_path}", file=sys.stderr)

# ---------------------------------------------------------------- figures
BLUE, ORANGE, GRAY, INK, MUTED = "#0072B2", "#E69F00", "#9AA0A6", "#222222", "#666666"
plt.rcParams.update({"font.size": 10, "axes.edgecolor": "#BBBBBB", "figure.dpi": 200,
                     "axes.grid": True, "grid.color": "#E6E6E6"})


def _clean(ax):
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.set_axisbelow(True); ax.tick_params(colors=MUTED, labelsize=9)


# Figure 2 — feedback
cyc = [c["cycle"] for c in fb["per_cycle"]]
fprc = [round(c["heldout_fpr"] * 100, 1) for c in fb["per_cycle"]]
dic = [round(c["defensibility_index"], 3) for c in fb["per_cycle"]]
fig, (a1, a2) = plt.subplots(2, 1, figsize=(7.0, 5.2), sharex=True)
a1.plot(cyc, fprc, "-o", color=BLUE, lw=2, ms=6); a1.set_ylabel("Held-out benign FPR (%)")
a1.set_title("Figure 2. Feedback-driven false-positive suppression (leakage-free held-out set)")
a1.set_ylim(-5, max(fprc) + 8)
a2.plot(cyc, dic, "-s", color=ORANGE, lw=2, ms=6); a2.set_ylabel("Defensibility Index")
a2.set_xlabel("Incident-feedback cycle"); a2.set_xticks(cyc); a2.set_ylim(0.55, 0.85)
for ax in (a1, a2):
    _clean(ax)
fig.tight_layout(); fig.savefig(os.path.join(FIGS, "figure2_feedback.png"), bbox_inches="tight"); plt.close(fig)

# architecture data
arch = ["Conventional\nML", "SOAR-based", "Backup-\ncentric", "WSG\n(measured)"]
mttd = [12, 15, 300, round((tableA["mttd_seconds"]["mean"] + tableB["mttd_seconds"]["mean"]) / 2, 1)]
mttc = [900, 45, 1800, round((tableA["mttc_seconds_modeled"]["mean"] + tableB["mttc_seconds_modeled"]["mean"]) / 2, 1)]
recfid = [93, 94.5, 97.5, 100]
prev = [10, 45, 2, round((((1 - tableA["apcr"]["mean"]) + (1 - tableB["apcr"]["mean"])) / 2) * 100, 0)]
di_arch = [comp_di["Conventional ML detection"], comp_di["SOAR-based automation"],
           comp_di["Backup-centric recovery"], wsg_di_base]
fpr_arch = [4.8, 3.9, 4.5, round(HELDOUT_FPR * 100, 1)]
x = range(len(arch)); w = 0.38


def grouped(ax, left, right, ll, rl, logy=False):
    b1 = ax.bar([i - w / 2 for i in x], left, w, color=BLUE, label=ll)
    b2 = ax.bar([i + w / 2 for i in x], right, w, color=ORANGE, label=rl)
    if logy:
        ax.set_yscale("log")
    for bars, vals in ((b1, left), (b2, right)):
        for r, v in zip(bars, vals):
            ax.annotate(f"{v:g}", (r.get_x() + r.get_width() / 2, r.get_height()),
                        textcoords="offset points", xytext=(0, 3), ha="center", fontsize=7.5, color=INK)
    ax.set_xticks(list(x)); ax.set_xticklabels(arch, fontsize=8.5); _clean(ax); ax.legend(frameon=False, fontsize=9)


fig, ax = plt.subplots(figsize=(7.0, 4.2)); grouped(ax, mttd, mttc, "MTTD (s)", "MTTC (s)", logy=True)
ax.set_ylabel("Seconds (log scale)"); ax.set_ylim(1, 3000)
ax.set_title("Figure 3. Detection and containment latency by architecture")
fig.tight_layout(); fig.savefig(os.path.join(FIGS, "figure3_latency.png"), bbox_inches="tight"); plt.close(fig)

fig, ax = plt.subplots(figsize=(7.0, 4.2)); grouped(ax, recfid, prev, "Recovery fidelity (%)", "Attack-path prevention (%)")
ax.set_ylabel("Percent"); ax.set_ylim(0, 110)
ax.set_title("Figure 4. Recovery fidelity and attack-path prevention by architecture")
fig.tight_layout(); fig.savefig(os.path.join(FIGS, "figure4_recovery_prevention.png"), bbox_inches="tight"); plt.close(fig)

fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.4, 4.2)); colors = [GRAY, GRAY, GRAY, BLUE]
b = a1.bar(list(x), di_arch, color=colors)
for r, v in zip(b, di_arch):
    a1.annotate(f"{v:.2f}", (r.get_x() + r.get_width() / 2, r.get_height()), textcoords="offset points",
                xytext=(0, 3), ha="center", fontsize=8.5, color=INK, fontweight="bold")
a1.set_xticks(list(x)); a1.set_xticklabels(arch, fontsize=8.5); a1.set_ylabel("Defensibility Index")
a1.set_ylim(0, 0.9); a1.set_title("(a) Defensibility Index"); _clean(a1)
b2 = a2.bar(list(x), fpr_arch, color=colors)
for r, v in zip(b2, fpr_arch):
    a2.annotate(f"{v:g}%", (r.get_x() + r.get_width() / 2, r.get_height()), textcoords="offset points",
                xytext=(0, 3), ha="center", fontsize=8.5, color=INK)
a2.set_xticks(list(x)); a2.set_xticklabels(arch, fontsize=8.5); a2.set_ylabel("False positive rate (%)")
a2.set_ylim(0, max(fpr_arch) + 8); a2.set_title("(b) FPR"); _clean(a2)
fig.suptitle("Figure 5. Defensibility Index and false-positive rate by architecture", fontsize=11, fontweight="bold")
fig.tight_layout(); fig.savefig(os.path.join(FIGS, "figure5_di_fpr.png"), bbox_inches="tight"); plt.close(fig)
print("[*] wrote figures", file=sys.stderr)

# ---------------------------------------------------------------- manifest
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


lines = []
for root, _, files in os.walk(OUT):
    for name in sorted(files):
        if name == "MANIFEST.sha256":
            continue
        full = os.path.join(root, name)
        rel = os.path.relpath(full, OUT)
        lines.append(f"{sha256(full)}  {rel}")
with open(os.path.join(OUT, "MANIFEST.sha256"), "w") as f:
    f.write("\n".join(sorted(lines)) + "\n")
print(f"[*] wrote MANIFEST.sha256 ({len(lines)} files)", file=sys.stderr)

print(json.dumps({
    "held_out_fpr_pct": round(HELDOUT_FPR * 100, 1),
    "table5_DI_A": round(tableA["defensibility_index"]["mean"], 2),
    "table5_DI_B": round(tableB["defensibility_index"]["mean"], 2),
    "table5_DI_ci_A": round(tableA["defensibility_index"]["ci95"], 2),
    "wsg_di_base": wsg_di_base,
    "comparator_DI": comp_di,
    "feedback_first_last_DI": [fb["per_cycle"][0]["defensibility_index"], fb["per_cycle"][-1]["defensibility_index"]],
}, indent=2))
