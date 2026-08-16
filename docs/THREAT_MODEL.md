# DRRA System Threat Model

**Version:** 0.1.0 · **Status:** Draft for review · **Last updated:** 2026-08-16

This is the versioned threat model that frames every hardening decision in the
DRRA backlog (DRRA-001). Each hardening requirement in the roadmap should trace
back to a threat named here; each threat should name the control that addresses
it and its current status. It is deliberately honest: where a control is not yet
built, the threat is marked **open** and points at the requirement that closes it.

Versioning: this document uses semantic versioning. A new threat or a materially
changed trust boundary is a minor bump; a re-scoping of the system is a major bump.

---

## 1. Scope and system model

DRRA (Detection, Response, Recovery, Assurance) is a ransomware-resilience
platform with four capability pillars and supporting components:

| Component | Role | Code |
|---|---|---|
| **VIGIL** | Two-stage behavioural detector (IsolationForest + secondary classifier) scoring Indicators of Behavior | `vigil/`, `backend/services/vigil_service.py` |
| **SHIELD** | Containment / isolation of affected resources | `backend/services/shield_service.py`, `containment.py` |
| **GRAB** | Immutable backup + clean-room recovery | `backend/services/grab_recovery.py`, `backend/utils/minio_client.py` |
| **FORGE** | Attack-simulation / cyber-range for evaluation | `backend/services/forge_service.py` |
| **Defensibility Index** | Weighted resilience score over MTTD / MTTC / APCR / recovery | `backend/services/defensibility.py` |
| **Endpoint watcher** | Rust filesystem agent forwarding file events | `watchers/src/lib.rs` |
| **Ingest** | OTRF/Sysmon telemetry ingestion for evaluation | `vigil/ingest.py` |
| **Control plane** | FastAPI backend, dashboard, message bus, object store | `backend/`, `dashboard/` |

### Trust boundaries

1. **Endpoint → control plane.** The watcher POSTs file events to
   `/api/v1/vigil/events` over the network. Today this call is unauthenticated
   and unsigned (see T-1, T-2).
2. **Analyst → control plane.** Humans drive detection review, containment, and
   recovery through the API / dashboard. No human authentication exists yet (T-4).
3. **Control plane → response providers.** Containment/recovery reach out to
   EDR, firewall/NAC, cloud IAM, and object storage. Adapters are largely stubs
   or single-vendor today (T-6).
4. **Build/supply chain → running system.** Dependencies, base images, and CI
   actions enter the trust base at build time (T-9).
5. **Tenant ↔ tenant.** Multi-tenant isolation is not yet implemented (T-10).

### Assets to protect

- Integrity and availability of production data (the thing ransomware attacks).
- Integrity of the immutable backup set and its retention guarantees.
- Integrity of detections, containment decisions, and the audit trail.
- Confidentiality of telemetry, models, and tenant data.
- Availability of the control plane during an active incident.

### Adversaries in scope

- **A1 — Ransomware operator** with a foothold on one or more endpoints.
- **A2 — Malicious or compromised insider / administrator** with elevated
  platform access.
- **A3 — Supply-chain attacker** targeting dependencies, images, or CI.
- **A4 — External network attacker** able to reach exposed control-plane
  interfaces.

Out of scope for v0.1.0: physical attacks, side-channel/hardware attacks, and
the security of the underlying cloud provider's control plane.

---

## 2. Threats (STRIDE) and controls

Status legend: **open** = no control yet · **partial** = mechanism exists,
acceptance pending · **planned** = scheduled, see requirement.

| ID | Threat | STRIDE | Adversary | Control / requirement | Status |
|---|---|---|---|---|---|
| **T-1** | Forged endpoint events: an attacker POSTs fabricated or replayed file events to the detection endpoint to hide activity or exhaust the analyst | Spoofing / Tampering | A1, A4 | Sensor attestation + event signing; backend rejects unsigned/forged events — **DRRA-012**; service identity + mTLS — **DRRA-003** | open |
| **T-2** | Eavesdropping / tampering on the endpoint→backend channel | Information disclosure / Tampering | A4 | Mutual TLS on all inter-service calls — **DRRA-003** | open |
| **T-3** | Shipped/default credentials or secrets in config extracted and reused | Elevation of privilege | A1–A4 | External secrets management, no embedded creds, rotation — **DRRA-006** | open |
| **T-4** | Unauthenticated human access to detection/containment/recovery actions | Spoofing / Elevation | A2, A4 | Human auth via OIDC + phishing-resistant MFA — **DRRA-004**; RBAC/ABAC least privilege — **DRRA-005** | open |
| **T-5** | A single compromised admin unilaterally triggers destructive containment or disables defenses | Elevation / Denial of service | A2 | Two-person approval / logged break-glass for high-impact actions — **DRRA-029** | open |
| **T-6** | Containment fails silently or is not honored by the provider, leaving the threat active past the MTTC SLO | Denial of service | A1 | Real containment providers — **DRRA-031**; idempotent/transactional actions — **DRRA-028**; containment SLO + provider error handling — **DRRA-035** | partial |
| **T-7** | Attacker disables EDR/logging/backups (defense evasion) before or during encryption | Tampering / DoS | A1, A2 | Detect defense-evasion attempts — **DRRA-026**; family-agnostic pre-encryption early warning — **DRRA-025** | open |
| **T-8** | Backups tampered with or deleted (e.g. shadow-copy deletion, admin-level backup wipe) so recovery is impossible | Tampering / DoS | A1, A2 | Recovery-inhibition detection (implemented signal in `vigil/ingest.py`); backups resist compromised admin — **DRRA-041**; immutable retention lifecycle + legal hold — **DRRA-089**; production Object Lock recovery — **DRRA-083** | partial |
| **T-9** | Malicious or vulnerable dependency, base image, or CI action enters the trust base | Tampering / Elevation | A3 | Blocking Critical/High vuln policy on Python/Rust manifests (implemented, `.github/workflows/ci-cd.yml` + `.trivyignore`); full-stack supply-chain hardening (npm/image/OS/SBOM/SHA-pinned actions) — **DRRA-090** | partial |
| **T-10** | Cross-tenant data/model/key access in a shared deployment | Information disclosure / Elevation | A2, A4 | Multi-tenant isolation with tested cross-tenant denial — **DRRA-009**; data minimization/retention/residency — **DRRA-010** | open |
| **T-11** | Poisoned analyst feedback degrades or backdoors the detector | Tampering | A2 | Governed feedback workflow (verified labels + provenance) — **DRRA-020**; poisoning defenses (quorum, anomaly checks, rollback) — **DRRA-021** | open |
| **T-12** | Model or telemetry drift silently erodes detection quality | Denial of service | A1 | Drift detection with retrain triggers — **DRRA-023**; detection-quality SLO CI gate (implemented, `run_fpr_eval.py`) | partial |
| **T-13** | Repudiation: an actor denies a detection/containment/recovery decision, or the record is altered after the fact | Repudiation | A2 | Tamper-evident, append-only signed audit trail — **DRRA-007**; forensic evidence + chain of custody — **DRRA-043**; trustworthy time — **DRRA-008** | open |
| **T-14** | Model artifacts swapped or rolled out without provenance/approval | Tampering / Elevation | A2, A3 | Model registry with signed artifacts, lineage, eval gates, safe rollback — **DRRA-022** | open |
| **T-15** | FORGE attack simulation escapes its environment or is misused against production | Elevation / DoS | A2 | FORGE runs only in strongly-isolated authorized environments — **DRRA-051**; safe declarative scenario language — **DRRA-050** | open |
| **T-16** | Control plane unavailable during an incident (node/zone failure or load) | Denial of service | A1, A4 | HA/DR for the control plane — **DRRA-058**; scale/soak/failure-injection testing — **DRRA-055** | open |

---

## 3. Residual risk and honest posture

As of v0.1.0 the **majority of these threats are open**: DRRA has a working
detection/recovery *core* and a supply-chain gate, but the identity, trust,
audit, and multi-tenant controls that a production deployment requires are
scheduled work (Wave 2), not built. This document exists so that status is
explicit rather than implied. No threat above should be described as "mitigated"
until its control's requirement is Implemented with supporting evidence in
`docs/CLAIM_TRACEABILITY.md`.

## 4. How to use and maintain this document

- Every new Wave-2 hardening PR should reference the threat ID(s) it closes and
  flip that row's status when acceptance criteria are met.
- New components or integrations must add their trust boundary (§1) and any new
  threats before merge.
- Review cadence: at minimum once per wave, and whenever a trust boundary changes.
