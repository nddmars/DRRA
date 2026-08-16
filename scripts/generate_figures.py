#!/usr/bin/env python3
"""
Generate the WSG paper's result figures directly from the DRRA harness output.

Produces (into results/figures/):
  * figure2_di_across_cycles.png   — DI and ensemble FPR vs. feedback cycle (§5.5)
  * figure3_mean_times.png         — MTTD / MTTC across architectures (Table 6)
  * figure4_recovery_protection.png— Recovery fidelity & prevention (Table 6)
  * figure5_fpr_defensibility.png  — False-positive rate & DI (Table 6)

Figure 2 and every WSG data point are computed from the real models / DI engine.
The *comparator* rows in Figures 3–5 (conventional-ML / SOAR / backup-centric)
are illustrative capability assumptions, NOT measured on this bench — the plots
label them as such and they are excluded from superiority claims (DRRA-081). The
WSG false-positive rate is the measured value from scripts/run_fpr_eval.py, not a
placeholder. Run: python scripts/generate_figures.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_OUT = os.path.join(_REPO, "results", "figures")

# Colour-blind-safe palette (Okabe–Ito). WSG is the highlighted series.
C_WSG = "#0072B2"
C_MUTED = ["#999999", "#E69F00", "#56B4E9"]
C_ACCENT = "#D55E00"
C_GREEN = "#009E73"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


di_mod = _load("wsg_defensibility", "backend/services/defensibility.py")
feedback = _load("wsg_feedback", "scripts/run_feedback_experiment.py")
fpr_eval = _load("wsg_fpr_eval_fig", "scripts/run_fpr_eval.py")
experiment = _load("wsg_experiment_fig", "scripts/run_experiment.py")
DefensibilityIndex = di_mod.DefensibilityIndex

# WSG operating point is loaded from MEASURED experiment output (never from
# hard-coded constants). These control that measurement.
WSG_CONDITION = "A_change_healthcare"
_FIG_SEED = 1234
_FIG_REPS = 30
_MEASURED = None


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def measured_wsg():
    """Load the WSG operating point from MEASURED experiment output.

    Runs the seeded synthetic-scenario experiment, extracts the WSG condition's
    measured mean MTTD/MTTC/APCR/recovery, archives the results file, and writes
    a provenance manifest (source + SHA-256). Raises if the measurement is
    missing — figures NEVER silently fall back to constants (review finding).
    Comparator columns remain illustrative."""
    global _MEASURED
    if _MEASURED is not None:
        return _MEASURED

    results = experiment.run_experiment(_FIG_REPS, _FIG_SEED)
    conds = results.get("conditions", {})
    if WSG_CONDITION not in conds:
        raise RuntimeError(f"measured WSG condition {WSG_CONDITION!r} missing — cannot render figures")
    c = conds[WSG_CONDITION]
    for k in ("mttd_seconds", "mttc_seconds", "apcr", "recovery_fidelity"):
        if c.get(k, {}).get("n", 0) == 0:
            raise RuntimeError(f"measured WSG metric {k!r} has no observations — cannot render figures")

    wsg = {
        "mttd": round(c["mttd_seconds"]["mean"], 3),
        "mttc": round(c["mttc_seconds"]["mean"], 3),
        "apcr": round(c["apcr"]["mean"], 4),
        "rf_pct": round(c["recovery_fidelity"]["mean"] * 100, 2),
        "fpr_pct": round(fpr_eval.evaluate(n_benign=400, n_pos=200)["fpr"] * 100, 1),
    }

    # archive measured results + provenance manifest
    os.makedirs(_OUT, exist_ok=True)
    res_path = os.path.join(_REPO, "results", "paper_metrics.json")
    os.makedirs(os.path.dirname(res_path), exist_ok=True)
    with open(res_path, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    def _git(*a):
        try:
            import subprocess
            return subprocess.check_output(["git", *a], cwd=_REPO, text=True).strip()
        except Exception:
            return "unknown"

    manifest = {
        "generated_from": f"scripts/run_experiment.py run_experiment(reps={_FIG_REPS}, seed={_FIG_SEED})",
        "results_file": "results/paper_metrics.json",
        "results_sha256": _sha256_file(res_path),
        "git_commit": _git("rev-parse", "HEAD"),
        "model_backend": results.get("model_backend"),
        "wsg_condition": WSG_CONDITION,
        "wsg_operating_point": wsg,
        "wsg_fpr_source": "scripts/run_fpr_eval.py evaluate(n_benign=400, n_pos=200)",
        "comparators_are_illustrative": True,
    }
    with open(os.path.join(_OUT, "figure_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    _MEASURED = wsg
    return wsg


def _style():
    plt.rcParams.update({
        "figure.dpi": 150, "savefig.dpi": 150, "font.size": 11,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.25, "grid.linestyle": "--",
        "figure.autolayout": True,
    })


# --- Comparator profiles ------------------------------------------------------
# The three comparator columns are ILLUSTRATIVE capability assumptions for
# architecture *classes* — not measured on this bench, and excluded from any
# superiority claim (DRRA-081). The WSG column (index 3) is None here and is
# filled at render time from measured_wsg() — measured experiment output, not
# constants — with the provenance recorded in results/figures/figure_manifest.json.
ARCHS = ["Conventional\nML detection", "SOAR-based\nautomation", "Backup-centric\nrecovery", "Proposed\nWSG"]
PROFILE = {
    "mttd": [12.0, 15.0, 300.0, None],
    "mttc": [900.0, 45.0, 1800.0, None],
    "rf":   [93.0, 94.5, 97.5, None],
    "fpr":  [4.8, 3.9, 4.5, None],
    "apcr": [0.90, 0.55, 0.98, None],
}
# map PROFILE key -> measured_wsg() key
_WSG_KEY = {"mttd": "mttd", "mttc": "mttc", "rf": "rf_pct", "fpr": "fpr_pct", "apcr": "apcr"}


def _series(profile_key):
    """4-element series for a metric: comparators illustrative, WSG measured."""
    s = list(PROFILE[profile_key])
    s[-1] = measured_wsg()[_WSG_KEY[profile_key]]
    return s


def _fpr_series():
    return _series("fpr")


def _di_row(i, series=None):
    series = series or {k: _series(k) for k in ("mttd", "mttc", "apcr", "rf", "fpr")}
    r = DefensibilityIndex().score(
        mttd_seconds=series["mttd"][i], mttc_seconds=series["mttc"][i],
        apcr=series["apcr"][i], recovery_fidelity=series["rf"][i] / 100.0,
        false_positive_rate=series["fpr"][i] / 100.0,
    )
    return r.defensibility_index


def _bar_colors():
    return C_MUTED + [C_WSG]


def _label_bars(ax, bars, fmt="{:.1f}"):
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt.format(h), (b.get_x() + b.get_width() / 2, h),
                    ha="center", va="bottom", fontsize=8, xytext=(0, 2), textcoords="offset points")


def figure2():
    # Leakage-free evaluation (DRRA-080): a fixed held-out set that is never
    # trained on. FPR is measured on that set; DI is computed from the measured
    # FPR at a fixed reference operating point (see run_leakfree).
    res = feedback.run_leakfree(cycles=10, seed=99)
    cycles = [x["cycle"] for x in res["per_cycle"]]
    fpr = [x["heldout_fpr"] * 100 for x in res["per_cycle"]]
    di = [x["defensibility_index"] for x in res["per_cycle"]]

    fig, ax1 = plt.subplots(figsize=(7, 4))
    ax2 = ax1.twinx()
    ax2.grid(False)
    l1, = ax1.plot(cycles, di, "o-", color=C_WSG, lw=2, label="Defensibility Index")
    l2, = ax2.plot(cycles, fpr, "s--", color=C_ACCENT, lw=2, label="Held-out false-positive rate")
    ax1.set_xlabel("Incident–feedback cycle")
    ax1.set_ylabel("Defensibility Index", color=C_WSG)
    ax2.set_ylabel("Held-out false-positive rate (%)", color=C_ACCENT)
    ax1.set_ylim(0.55, 0.9)
    ax2.set_ylim(-2, max(55, max(fpr) + 5))
    ax1.set_xticks(cycles)
    ax1.set_title("Figure 2. Compounding resilience across feedback cycles\n"
                  "(leakage-free held-out evaluation)")
    ax1.legend(handles=[l1, l2], loc="center right", frameon=False)
    _save(fig, "figure2_di_across_cycles.png")


def figure3():
    import numpy as np
    x = np.arange(len(ARCHS)); w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    b1 = ax.bar(x - w / 2, _series("mttd"), w, label="MTTD (s)", color=C_GREEN)
    b2 = ax.bar(x + w / 2, _series("mttc"), w, label="MTTC (s)", color=C_ACCENT)
    ax.set_yscale("log")
    ax.set_ylabel("Seconds (log scale)")
    ax.set_xticks(x); ax.set_xticklabels(ARCHS)
    ax.set_title("Figure 3. Detection and containment latency by architecture\n"
                 "(comparators illustrative; WSG measured)")
    ax.legend(frameon=False)
    _label_bars(ax, b1); _label_bars(ax, b2)
    _save(fig, "figure3_mean_times.png")


def figure4():
    import numpy as np
    prevention = [(1 - a) * 100 for a in _series("apcr")]
    x = np.arange(len(ARCHS)); w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    b1 = ax.bar(x - w / 2, _series("rf"), w, label="Recovery fidelity (%)", color=C_GREEN)
    b2 = ax.bar(x + w / 2, prevention, w, label="Attack-path prevention (%) = 1 − APCR", color=C_WSG)
    ax.set_ylabel("Percent")
    ax.set_ylim(0, 110)
    ax.set_xticks(x); ax.set_xticklabels(ARCHS)
    ax.set_title("Figure 4. Recovery and prevention performance\n"
                 "(comparators illustrative; WSG measured)")
    ax.legend(frameon=False)
    _label_bars(ax, b1); _label_bars(ax, b2)
    _save(fig, "figure4_recovery_protection.png")


def figure5():
    fpr_series = _fpr_series()   # WSG entry is the measured FPR, not 0
    di = [_di_row(i) for i in range(len(ARCHS))]   # DI from measured WSG series
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(9, 4))
    b1 = axL.bar(ARCHS, fpr_series, color=_bar_colors())
    axL.set_ylabel("False-positive rate (%)"); axL.set_title("False-positive rate")
    axL.set_xticklabels(ARCHS, fontsize=8)
    _label_bars(axL, b1)
    b2 = axR.bar(ARCHS, di, color=_bar_colors())
    axR.set_ylabel("Defensibility Index"); axR.set_title("Defensibility Index")
    axR.set_ylim(0, 1.0)
    axR.set_xticklabels(ARCHS, fontsize=8)
    _label_bars(axR, b2, fmt="{:.2f}")
    fig.suptitle("Figure 5. False-positive rate and Defensibility Index by architecture\n"
                 "(comparators illustrative; WSG FPR measured on held-out benign)")
    _save(fig, "figure5_fpr_defensibility.png")


def _save(fig, name):
    os.makedirs(_OUT, exist_ok=True)
    path = os.path.join(_OUT, name)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.relpath(path, _REPO))


def main():
    _style()
    figure2(); figure3(); figure4(); figure5()
    print(f"\n[*] Figures written to {os.path.relpath(_OUT, _REPO)}/")


if __name__ == "__main__":
    main()
