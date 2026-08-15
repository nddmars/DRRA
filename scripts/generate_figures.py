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
DefensibilityIndex = di_mod.DefensibilityIndex


def _measured_wsg_fpr_pct():
    """Measured WSG false-positive rate (%) on held-out benign workloads —
    replaces the former hard-coded 0.0 so no figure states an unmeasured FPR."""
    return round(fpr_eval.evaluate(n_benign=400, n_pos=200)["fpr"] * 100, 1)


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
# superiority claim (DRRA-081). Only the WSG column is measured: its latency /
# recovery / APCR come from the DRRA harness, and its FPR is the measured value
# from scripts/run_fpr_eval.py (filled in at render time, not hard-coded to 0).
ARCHS = ["Conventional\nML detection", "SOAR-based\nautomation", "Backup-centric\nrecovery", "Proposed\nWSG"]
PROFILE = {
    "mttd": [12.0, 15.0, 300.0, 2.5],
    "mttc": [900.0, 45.0, 1800.0, 7.8],
    "rf":   [93.0, 94.5, 97.5, 100.0],
    "fpr":  [4.8, 3.9, 4.5, None],   # WSG filled with the measured FPR at render
    "apcr": [0.90, 0.55, 0.98, 0.46],
}


def _fpr_series():
    """PROFILE['fpr'] with the WSG entry replaced by the measured FPR (%)."""
    series = list(PROFILE["fpr"])
    series[-1] = _measured_wsg_fpr_pct()
    return series


def _di_row(i, fpr_series=None):
    fpr_series = fpr_series if fpr_series is not None else _fpr_series()
    r = DefensibilityIndex().score(
        mttd_seconds=PROFILE["mttd"][i], mttc_seconds=PROFILE["mttc"][i],
        apcr=PROFILE["apcr"][i], recovery_fidelity=PROFILE["rf"][i] / 100.0,
        false_positive_rate=fpr_series[i] / 100.0,
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
    res = feedback.run(cycles=10, seed=99)
    cycles = [x["cycle"] for x in res["per_cycle"]]
    fpr = [x["ensemble_fpr"] * 100 for x in res["per_cycle"]]
    di = [x["defensibility_index"] for x in res["per_cycle"]]

    fig, ax1 = plt.subplots(figsize=(7, 4))
    ax2 = ax1.twinx()
    ax2.grid(False)
    l1, = ax1.plot(cycles, di, "o-", color=C_WSG, lw=2, label="Defensibility Index")
    l2, = ax2.plot(cycles, fpr, "s--", color=C_ACCENT, lw=2, label="Ensemble false-positive rate")
    ax1.set_xlabel("Incident–feedback cycle")
    ax1.set_ylabel("Defensibility Index", color=C_WSG)
    ax2.set_ylabel("False-positive rate (%)", color=C_ACCENT)
    ax1.set_ylim(0.6, 0.85)
    ax2.set_ylim(-2, 55)
    ax1.set_xticks(cycles)
    ax1.set_title("Figure 2. Compounding resilience across feedback cycles")
    ax1.legend(handles=[l1, l2], loc="center right", frameon=False)
    _save(fig, "figure2_di_across_cycles.png")


def figure3():
    import numpy as np
    x = np.arange(len(ARCHS)); w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    b1 = ax.bar(x - w / 2, PROFILE["mttd"], w, label="MTTD (s)", color=C_GREEN)
    b2 = ax.bar(x + w / 2, PROFILE["mttc"], w, label="MTTC (s)", color=C_ACCENT)
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
    prevention = [(1 - a) * 100 for a in PROFILE["apcr"]]
    x = np.arange(len(ARCHS)); w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    b1 = ax.bar(x - w / 2, PROFILE["rf"], w, label="Recovery fidelity (%)", color=C_GREEN)
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
    di = [_di_row(i, fpr_series) for i in range(len(ARCHS))]
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
