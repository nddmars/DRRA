# Capability → Evidence Traceability Matrix (DRRA-075)

Every capability DRRA claims maps to a tagged code path, a generator script, a
raw result, or is explicitly labeled **proposed/future work**. This keeps the
project's claims honest and gives any downstream artifact (documentation,
reports, or a research write-up) a single source of truth for what is actually
built and tested versus modeled or planned.

Legend: **Implemented** = executable + tested in-repo · **Partial** = mechanism
present, full acceptance pending · **Modeled** = simulation/assumption, labeled
as such wherever reported · **Future** = not yet built.

| Capability / claim | Status | Evidence (code / script / result) |
|---|---|---|
| VIGIL two-stage detector (IsolationForest + secondary classifier) | Implemented | `vigil/ml_model.py`; `tests/test_ml_model.py` |
| VIGIL scores real adversary telemetry | Partial | `vigil/ingest.py`, `scripts/run_real_data.py`; `tests/test_ingest.py`; data via `scripts/fetch_datasets.py` (DRRA-076) |
| Defensibility Index = weighted harmonic mean of MTTD/MTTC/APCR/recovery | Implemented | `backend/services/defensibility.py`; `tests/test_defensibility.py` |
| DI computed from recorded metrics (not literals) | Implemented | `backend/services/metrics_store.py`, `backend/routes/dashboard_router.py` |
| DI ranking is robust, monotone, and penalizes the weakest component | Implemented | `scripts/run_di_sensitivity.py`, `tests/test_di_sensitivity.py` (DRRA-082): 100% ordering preserved under uniform-simplex weight sampling, 0 monotonicity violations, weakest-component dominance verified |
| SHIELD concurrent containment, measured MTTC, 90 s SLA | Implemented | `backend/services/containment.py`; `tests/test_containment.py` |
| SHIELD real EDR containment (CrowdStrike) | Partial | `CrowdStrikeAdapter` in `backend/services/containment.py` (needs live creds) |
| GRAB immutable backups (MinIO Object Lock) | Partial | `backend/utils/minio_client.py` (Object Lock + retention); end-to-end clean-room recovery = Future (DRRA-083) |
| Table 5 measured results (30 reps, 95% CI) | Implemented (simulation) | `scripts/run_experiment.py --reps 30` → `results/paper_metrics.json` |
| §5.5 feedback-loop / compounding resilience | Implemented (simulation) | `scripts/run_feedback_experiment.py --cycles 10` → `results/feedback.json` |
| Figures 1–5 | Implemented | `scripts/generate_figures.py`, `scripts/generate_architecture_figure.py` |
| Detector-architecture comparison (measured) | Implemented | `scripts/run_comparator.py`, `tests/test_comparator.py` (DRRA-081): primary-only vs two-stage vs two-stage+feedback measured on one shared held-out set — FPR/recall/precision/F1, every value scored |
| External-tool comparator operational values (MTTD/MTTC/recovery) | **Modeled** | Illustrative capability assumptions only; not measurable on this bench, excluded from superiority claims and labelled as such in figures (DRRA-081) |
| Mordor "dataset replay" | **Modeled → Partial** | §5.2 describes ATT&CK-modeled scenarios; real ingestion added (DRRA-076); full raw-log reproduction = Future |
| False-positive rate (corrected: NOT 0%) | Implemented (measured) | `scripts/run_fpr_eval.py`, `tests/test_fpr_eval.py` (DRRA-079/080): measured on held-out benign workloads with a Wilson 95% CI; the prior "0% FPR" figure came from an adversarial-only replay with no benign denominator and is superseded. Figures now plot the measured value, not 0 |
| Defensibility Index is the "first / formal" resilience metric | Future | Requires independent literature review + construct validation before any priority claim (DRRA-045/049) |
| Near-linear enterprise-scale scalability | Future | Complexity analysis only; measured scale/soak = Future (DRRA-055) |
| 10-VM enterprise lab | Future | Docker Compose present; reproducible provisioning = Future (DRRA-077) |
| Rust watcher forwards real filesystem events | Implemented | `watchers/src/lib.rs`; `cargo test` |

## Rule
No performance number may be stated as measured unless its row above is
**Implemented**. Rows marked **Modeled** must be labeled illustrative wherever
reported and excluded from superiority claims (DRRA-081). Rows marked **Future**
must be phrased as proposed/planned.

## Status policy

> The requirements backlog describes the target research and production roadmap.
> Status values distinguish implemented capabilities from partial, proposed, and
> externally dependent work. No requirement is considered implemented without its
> stated acceptance criteria and supporting evidence.

This applies to the whole project. It is deliberately conservative so the
project's claims remain defensible to independent reviewers and evaluators.
