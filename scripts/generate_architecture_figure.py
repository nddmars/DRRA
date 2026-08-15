#!/usr/bin/env python3
"""Generate Figure 1 — the WSG closed-loop architecture diagram."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(REPO, "results", "figures", "figure1_architecture.png")

C_WALL = "#0072B2"
C_SQUAT = "#D55E00"
C_GRAB = "#009E73"
C_FB = "#7F3FBF"
C_DI = "#1F4E79"


def box(ax, x, y, w, h, title, sub, color):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                linewidth=1.6, edgecolor=color, facecolor=color + "22"))
    ax.text(x + w / 2, y + h * 0.62, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color=color)
    ax.text(x + w / 2, y + h * 0.26, sub, ha="center", va="center", fontsize=8, color="#333333")


def arrow(ax, xy1, xy2, color="#333333", style="-|>", rad=0.0, lw=1.8, ls="-"):
    ax.add_patch(FancyArrowPatch(xy1, xy2, arrowstyle=style, mutation_scale=16,
                                 connectionstyle=f"arc3,rad={rad}", color=color, lw=lw, linestyle=ls))


fig, ax = plt.subplots(figsize=(11, 5.2))
ax.set_xlim(0, 11); ax.set_ylim(0, 5.2); ax.axis("off")

# Threat actor
box(ax, 0.2, 2.1, 1.5, 1.0, "Threat Actor", "adversarial\nreplay (Mordor)", "#555555")

# Pillars
box(ax, 2.2, 2.0, 2.1, 1.2, "WALL — VIGIL", "IsolationForest +\nsecondary classifier", C_WALL)
box(ax, 4.7, 2.0, 2.1, 1.2, "SQUAT — SHIELD", "async containment\n90 s MTTC SLA", C_SQUAT)
box(ax, 7.2, 2.0, 2.1, 1.2, "GRAB", "immutable backup +\n4-stage validation", C_GRAB)

# DI output
box(ax, 9.7, 2.1, 1.1, 1.0, "DI", "Defensibility\nIndex", C_DI)

# Forward arrows
arrow(ax, (1.7, 2.6), (2.2, 2.6))
arrow(ax, (4.3, 2.6), (4.7, 2.6))
arrow(ax, (6.8, 2.6), (7.2, 2.6))
arrow(ax, (9.3, 2.6), (9.7, 2.6))

# Feedback loop (below): GRAB + SHIELD -> VIGIL retraining
ax.text(5.5, 0.95, "Bidirectional telemetry feedback  →  VIGIL retraining, SHIELD tuning, GRAB point selection",
        ha="center", va="center", fontsize=9, color=C_FB, fontstyle="italic")
arrow(ax, (8.25, 2.0), (3.25, 1.35), color=C_FB, rad=0.28, ls="--", lw=1.6)
arrow(ax, (5.75, 2.0), (3.25, 1.5), color=C_FB, rad=0.18, ls="--", lw=1.6)

# AGT gap labels at pillar entry points
ax.text(3.25, 3.45, "Gap 1: Identity/MFA", ha="center", fontsize=7.5, color=C_WALL)
ax.text(5.75, 3.45, "Gap 2: Flat network", ha="center", fontsize=7.5, color=C_SQUAT)
ax.text(8.25, 3.45, "Gap 3: Backup integrity", ha="center", fontsize=7.5, color=C_GRAB)

ax.text(5.5, 4.7, "Figure 1. WSG closed-loop architecture", ha="center",
        fontsize=13, fontweight="bold", color=C_DI)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
fig.savefig(OUT, dpi=150, bbox_inches="tight")
print("wrote", os.path.relpath(OUT, REPO))
