# Resilience Forge (DRRA) — v1.0 (paper snapshot)

Reference implementation and finalized reproducibility artifacts for the WSG
paper: *A Closed-Loop Ransomware Resilience Framework combining VIGIL behavioral
detection, SHIELD automated containment, and immutable recovery with a formal
Defensibility Index.*

This release locks the exact code and data behind every quantity in the
manuscript so an independent reviewer can byte-compare.

## What's in this release

- **Reference implementation** — VIGIL detector (`vigil/`), SHIELD/GRAB backend
  (`backend/`), Rust file-system watcher (`watchers/`), experiment drivers
  (`scripts/`), and tests (`tests/`).
- **`paper_artifacts/`** — the finalized bundle:
  - `paper_metrics_final.json` — every reported quantity with seeds + provenance
  - `figures/figure2..5.png` — the four figures (colorblind-safe, single-axis)
  - `WSG_Experiment_Data_v1.0.xlsx` — the data workbook (Table 5, held-out FPR,
    §5.5 feedback, Table 7, embedded figures)
  - `REPRODUCIBILITY.md` — commands, seeds, the canonical DI definition, and the
    measured-vs-modeled provenance table
  - `MANIFEST.sha256` — SHA-256 of every artifact

## Reproduce

```bash
pip install -r requirements.txt
python scripts/generate_paper_artifacts.py
```

Deterministic (experiment seed 1234, held-out FPR seed 4242, 30 reps).

## Finalized headline

- One canonical Defensibility Index — the false-positive rate is folded into the
  detection term, so Table 5, §5.5, and Table 7 use a single definition.
- Base DI **0.70–0.71** (95% CI ± 0.02) at the detector's measured 32.5% held-out
  benign FPR, rising toward **~0.80** as the closed-loop feedback drives the FPR
  to zero. Unprotected baseline 0.00; single-pillar comparators 0.00–0.61.

## Honest scope

MTTD and APCR are measured on the simulation bench; MTTC and recovery fidelity
are modeled constants; the held-out FPR is a synthetic proxy, not representative
real-world FPR; Table 7 comparator rows are stated capability assumptions.
Production hardening (identity, audit, real containment/recovery providers,
scale testing) is tracked as Wave-2 work and is **not** claimed here.
See `docs/CLAIM_TRACEABILITY.md`.
