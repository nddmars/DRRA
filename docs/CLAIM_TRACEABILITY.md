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
| GRAB immutable backups (MinIO Object Lock) | Partial | `backend/utils/minio_client.py` (Object Lock + retention); live MinIO Object Lock needs a running server |
| GRAB clean-room recovery drill (bench simulation) | Implemented (simulation) | `backend/services/grab_recovery.py`, `scripts/run_recovery_drill.py`, `tests/test_grab_recovery.py` (DRRA-083): four-stage drill (integrity/completeness/isolation/immutability) restores from a path-safe WORM store into an isolated clean room; `recovery_fidelity` is measured on the bench and failure modes + traversal escapes are tested. The WORM guarantee is an in-process model (retention state is lost on restart); live MinIO Object Lock, IOC scanning, restore-point ranking, certification, and production cutover are out of scope for this drill (DRRA-083) |
| Production-grade GRAB recovery (Object Lock, IOC scan, restore-point ranking, cutover) | Partial | `backend/utils/minio_client.py` (Object Lock adapter); live-server validation, IOC scanning, ML restore-point selection, and cutover controls remain to be built (DRRA-083) |
| Table 5 measured results (30 reps, 95% CI) | Implemented (simulation) | `scripts/run_experiment.py --reps 30` → `results/paper_metrics.json` |
| §5.5 feedback-loop / compounding resilience (leakage-free) | Implemented (simulation) | `scripts/run_feedback_experiment.py` (default `run_leakfree`), `tests/test_fpr_eval.py` (DRRA-080): fixed held-out set never trained on; DI computed from the measured held-out FPR at a fixed reference operating point; Figure 2 generated from this path |
| Figures 1–5 (WSG values from measured output) | Implemented | `scripts/generate_figures.py`, `tests/test_figures.py`: the WSG operating point is loaded from measured `run_experiment` output (not constants), archived to `results/paper_metrics.json` with a SHA-256 provenance manifest (`results/figures/figure_manifest.json`); generation fails if the measurement is missing; comparator columns stay illustrative |
| Detector-architecture comparison (measured) | Implemented | `scripts/run_comparator.py`, `tests/test_comparator.py` (DRRA-081): primary-only vs two-stage vs two-stage+feedback measured on one shared held-out set — FPR/recall/precision/F1, every value scored |
| External-tool comparator operational values (MTTD/MTTC/recovery) | **Modeled** | Illustrative capability assumptions only; not measurable on this bench, excluded from superiority claims and labelled as such in figures (DRRA-081) |
| Mordor "dataset replay" | **Modeled → Partial** | §5.2 describes ATT&CK-modeled scenarios; real ingestion added (DRRA-076); full raw-log reproduction = Future |
| False-positive rate on synthetic held-out benign (corrected: NOT 0%) | Implemented (synthetic held-out) | `scripts/run_fpr_eval.py`, `tests/test_fpr_eval.py` (DRRA-079/080): measured on **synthetically-generated** held-out benign workloads (distinct seed, no host/time identity) with a Wilson 95% CI; the prior "0% FPR" from an adversarial-only replay is superseded. Figures plot the measured value, not 0 |
| Representative real-world FPR (real endpoint capture) | Future | Requires production/endpoint benign traffic with host/time identity; independent validation (DRRA-068). Synthetic held-out is a proxy, not representative real-world evidence |
| Defensibility Index is the "first / formal" resilience metric | Future | Requires independent literature review + construct validation before any priority claim (DRRA-045/049) |
| Near-linear enterprise-scale scalability | Future | Complexity analysis only; measured scale/soak = Future (DRRA-055) |
| 10-VM enterprise lab (reproducible definition) | Partial | `lab/lab_manifest.json`, `scripts/validate_lab.py`, `tests/test_lab_provisioning.py` (DRRA-077): pinned control-plane images + declarative endpoint tier whose scenarios map to fetchable OTRF captures, validated for reproducibility; standing up the live VMs and collecting fresh telemetry = Future (external evidence) |
| Rust watcher forwards real filesystem events | Implemented | `watchers/src/lib.rs`; `cargo test` |
| Deterministic, backend-independent model training | Implemented | `tests/test_determinism.py` (DRRA-085): seeded training reproducible across sklearn/TF; CI asserts non-root execution |
| Blocking Critical/High vuln policy for the **Python/Rust dependency manifests** | Implemented | `.github/workflows/ci-cd.yml` security-scan + `.trivyignore` (DRRA finding 9): `trivy fs` (excluding `dashboard/`) blocks the build on fixed Critical/High findings (ignore-unfixed), with a documented `.trivyignore` exception process; Python stack upgraded to clear known CVEs (tensorflow/numpy/cryptography/pyjwt/python-multipart/pillow; unused pandas removed). Scope is the Python/Rust manifests — does NOT assert the deployable image/OS/runtime is vulnerability-free |
| Full-stack vuln scanning (frontend npm, container image, OS, pinned actions) | Future | The frontend lockfile's transitive CVEs are reported (SARIF) but not yet blocking; stronger gate = `npm audit`, a scan of the built image, a resolved `pip-audit` lockfile, and pinning third-party Actions by commit SHA (DRRA finding 9 follow-up) |
| Detection-quality SLO enforced as a CI gate | Implemented | `.github/workflows/ci-cd.yml` detection-quality-gate + `scripts/run_fpr_eval.py` (DRRA-086): FPR budget + recall floor |
| Claim-integrity enforced (every Implemented row's evidence exists) | Implemented | `scripts/check_claim_integrity.py` (DRRA-087); runs as a CI gate |

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
