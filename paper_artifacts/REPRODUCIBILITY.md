# WSG Paper — Reproducibility Bundle (v1.0)

This directory locks the finalized quantities reported in the WSG manuscript to
a single, reproducible source. Every number is produced by running the
open-source reference implementation in this repository — none is hand-authored.

## Regenerate everything

```bash
git clone https://github.com/nddmars/DRRA && cd DRRA
git checkout v1.0-paper            # the tagged paper snapshot
pip install -r requirements.txt
python scripts/generate_paper_artifacts.py
```

This writes `paper_artifacts/paper_metrics_final.json`, the four figures, and
`MANIFEST.sha256`. Fixed seeds make it deterministic: experiment seed **1234**,
held-out FPR seed **4242**, 30 reps per scenario, 10 feedback cycles.

## The one Defensibility Index (canonical)

DI is a weighted harmonic mean of four component scores; the detection term is
**discounted by the measured false-positive rate**:

```
D = (1 − MTTD / T_drrt) · (1 − FPR)      (T_drrt = 300 s)
C = 1 − (MTTC / 90 s)
P = 1 − APCR
R = recovery fidelity
DI = (α+β+γ+δ) / (α/D + β/C + γ/P + δ/R),  α,β,γ,δ = 0.30,0.30,0.25,0.15
```

The false-positive rate is **intrinsic** to the index — the same definition is
used for Table 5, Section 5.5, and Table 7. Consequently the index rises as the
closed-loop feedback reduces false positives.

## Provenance of each reported quantity (honest scope)

| Quantity | Status | Note |
|---|---|---|
| MTTD | **Measured** | model detection point over templated, jittered kill-chain stage timings |
| APCR | **Measured** | stages completed before (detection + modeled MTTC) |
| MTTC | **Modeled** | simulation constant 8.0 s ± 3.0 jitter — NOT timed against live EDR/firewall |
| Recovery fidelity | **Modeled** | constant 1.0 (intact-WORM assumption); live Object Lock / IOC scan not exercised |
| Held-out benign FPR | **Measured** | synthetic held-out benign set with a Wilson 95% CI — a **synthetic proxy**, not representative real-world FPR |
| Defensibility Index | **Computed** | canonical FPR-inclusive DI from the four components above |
| Table 7 comparator rows | **Assumptions** | stated capability assumptions per architecture class — not measurements |

See `docs/CLAIM_TRACEABILITY.md` for the full implemented-vs-modeled map.

## Headline result (finalized)

- Base Defensibility Index (at the detector's out-of-the-box held-out FPR):
  **0.70–0.71** (Scenario A / B), 95% CI ± 0.02.
- Rises toward **~0.80** as the feedback loop drives the held-out FPR to zero.
- Unprotected baseline: **0.00**; single-pillar comparators: **0.00–0.61**.

The static headline is deliberately conservative and honest: the resilience gain
is expressed as a *trajectory* earned by the closed loop, not a single number.
