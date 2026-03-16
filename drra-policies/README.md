# DRRA Policies & Rules - Complete Reference

Vendor-agnostic policy definitions for Resilience Forge ransomware detection, containment, recovery, and hardening.

## Quick Navigation

### 📋 **Playbooks** - Orchestrated Incident Response
- [Active Ransomware Response](playbooks/README.md) – End-to-end incident playbook
- [Lateral Movement Response](playbooks/active_ransomware_response.yml) – Domain compromise handling
- [Post-Incident Hardening](playbooks/README.md#post-incident-hardening) – System hardening after recovery
- [Forensic Preservation](playbooks/README.md#forensic-preservation--handoff) – Evidence chain of custody

### 🛡️ **Hardening** - Post-Recovery System Hardening
- [Lateral Movement Prevention](hardening/lateral_movement_kerberos_hardening.rego) – Kerberos hardening
- [Credential & Access Reset](hardening/README.md#2-credential--access-reset) – Credential invalidation
- [Patch Management](hardening/README.md#3-patch-management) – Critical patches
- [File Integrity Monitoring](hardening/README.md#4-file-integrity-monitoring-rebaseline) – FIM rebaseline
- [Golden Image Validation](hardening/README.md#6-golden-image-validation) – System verification

### 🎯 **Sigma** - Detection Rules
- [Mass Modification Detection](sigma/ransomware_mass_modification.yml) – >15% files in 60s
- [Entropy Analysis](sigma/README.md) – Shannon entropy > 0.85
- [VSS Abuse Detection](sigma/README.md) – Shadow copy deletion
- [Lateral Movement](sigma/README.md) – Kerberos + credential reuse

### 🔐 **OPA** - Governance Policies
- [Isolation VLAN Rules](opa/isolation_vlan_rules.rego) – Safe network quarantine
- [Blast Radius Containment](opa/blast_radius_containment.rego) – Limit lateral movement spread
- [Recovery Validation](opa/README.md) – Snapshot integrity checks
- [Immutability Enforcement](opa/README.md#3-immutability-enforcement) – Object Lock + legal hold

### 🔍 **Semgrep** - Secure Coding
- [Logging Enforcement](semgrep/logging_no_unlogged_file_operations.yml) – Audit trail requirements
- [Golden Image Validation](semgrep/golden_image_validation.yml) – Binary integrity checks
- [Cryptography Security](semgrep/README.md) – Strong cipher enforcement
- [Input Validation](semgrep/README.md) – Injection attack prevention

### ✅ **Checklists** - Framework Compliance
- [NIST CSF Mapping](checklists/FRAMEWORKS.md#nist-csf-v11-mapping) – Identify/Protect/Detect/Respond/Recover
- [SOC2 Controls](checklists/FRAMEWORKS.md#soc2-type-ii-mapping) – Security/Availability/Integrity
- [CIS Controls v8](checklists/FRAMEWORKS.md#cis-controls-v8-mapping) – IG1/IG2/IG3
- [ISO 27001:2022](checklists/FRAMEWORKS.md#iso-270012022-mapping) – 69 control alignment

### 📚 **Principles** - Architectural Foundation
- [Immutability First](RESILIENCE_PRINCIPLES.md#1-immutability-first) – Evidence preservation
- [Defense-in-Depth](RESILIENCE_PRINCIPLES.md#2-defense-in-depth-layered-detection) – Multi-layer detection
- [Automated + Checkpoints](RESILIENCE_PRINCIPLES.md#3-automated-response-with-human-checkpoints) – Smart automation
- [Fail-Secure Design](RESILIENCE_PRINCIPLES.md#4-fail-secure-design) – Default to defensive
- [Graceful Degradation](RESILIENCE_PRINCIPLES.md#5-graceful-degradation) – Component failure tolerance
- [Zero-Trust Recovery](RESILIENCE_PRINCIPLES.md#6-zero-trust-recovery) – Verify post-recovery

### 🧪 **Tests** - Compliance Validation
- [Sigma Rule Testing](tests/compliance/README.md) – Detection accuracy
- [OPA Policy Testing](tests/compliance/README.md) – Decision correctness
- [Semgrep Rule Testing](tests/compliance/README.md) – Code quality
- [Integration Tests](tests/compliance/README.md#4-integration-testing) – End-to-end validation

---

## Incident Response Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   INCIDENT DETECTED                         │
│           (Sigma rules + Sentinel ML engine)                │
└────────────────────┬────────────────────────────────────────┘
                     │ [Detection Playbook]
                     ▼
    ┌────────────────────────────────────────┐
    │  Evidence Preservation                 │
    │  (Immutability First - Principle 1)    │
    │  → MinIO Object Lock activated         │
    │  → Forensic snapshot captured          │
    └────────────┬───────────────────────────┘
                 │ [OPA isolation policy validation]
                 ▼
    ┌────────────────────────────────────────┐
    │  Network Isolation                     │
    │  (Automated Response - Principle 3)    │
    │  → VLAN quarantine (< 3s)              │
    │  → Blast radius contained              │
    │  → Critical systems protected          │
    └────────────┬───────────────────────────┘
                 │ [OPA recovery validation]
                 ▼
    ┌────────────────────────────────────────┐
    │  Data Recovery                         │
    │  (Fail-Secure - Principle 4)           │
    │  → Snapshot restored (fastest option)  │
    │  → Parallel recovery (8 threads)       │
    │  → Integrity verified (MD5/SHA256)     │
    └────────────┬───────────────────────────┘
                 │ [Semgrep golden image validation]
                 ▼
    ┌────────────────────────────────────────┐
    │  Post-Recovery Hardening               │
    │  (Zero-Trust Recovery - Principle 6)   │
    │  → Binary validation (golden image)    │
    │  → Malware rescan                      │
    │  → Lateral movement prevented          │
    │  → FIM rebaselined                     │
    └────────────┬───────────────────────────┘
                 │ [OPA hardening policy enforcement]
                 ▼
    ┌────────────────────────────────────────┐
    │  System Hardening                      │
    │  (Defense-in-Depth - Principle 2)      │
    │  → Kerberos hardened                   │
    │  → Credentials reset (all users)       │
    │  → Critical patches applied            │
    │  → MFA enforced everywhere             │
    └────────────┬───────────────────────────┘
                 │
                 ▼
    ┌────────────────────────────────────────┐
    │  ✅ INCIDENT RESOLVED                  │
    │  Ready for production return            │
    └────────────────────────────────────────┘
```

---

## Key Metrics by Phase

| Phase | Component | Target | Principle |
|-------|-----------|--------|-----------|
| **Detect** | Sigma + Sentinel | < 1s | Defense-in-Depth |
| **Isolate** | Shield + OPA | < 3s | Automated Response |
| **Preserve** | MinIO | 100% immutable | Immutability First |
| **Recover** | Shield + Snapshot | < 60m | Graceful Degradation |
| **Validate** | Semgrep + Golden Image | 0 deviations | Zero-Trust Recovery |
| **Harden** | OPA + Hardening | < 2h | Fail-Secure Design |

---

## Integration Points

### With Sentinel (ML Detection Engine)
- Sigma rules operationalize ML detections
- Behavioral patterns → Detection triggers
- Entropy analysis → File modification classification

### With Shield (Recovery System)
- OPA policies govern isolation decisions
- Playbooks orchestrate recovery stages
- Hardening rules executed post-recovery

### With Dashboard
- Playbook metrics feed MTTC calculation
- Compliance checklists update DI score
- Forensic evidence available for investigation

### With CI/CD Pipeline
```bash
# Pre-commit: Semgrep validates code
semgrep --config=drra-policies/semgrep/ backend/ sentinel/ shield/

# Pre-deployment: OPA validates infrastructure
opa eval -d drra-policies/opa/ infrastructure.json

# Post-incident: Run compliance tests
pytest tests/compliance/ --cov=drra_policies
```

---

## Compliance Evidence

All policies support automated compliance reporting:

- ✅ **NIST CSF**: Detect → Respond → Recover alignment
- ✅ **SOC2 Type II**: Security controls + audit trail
- ✅ **CIS Controls v8**: Top 10 critical controls
- ✅ **ISO 27001**: 69 control mapping

Export compliance evidence:
```bash
python3 generate_compliance_report.py --framework nist_csf --output report.pdf
```

---

## Getting Started

### 1. Deploy Sigma Rules to SIEM
```bash
cp sigma/*.yml /path/to/siem/rules/
# Validate rules load successfully
```

### 2. Configure OPA Policies in Shield
```bash
# Validate policies
opa test drra-policies/opa/

# Deploy to Shield service
docker cp drra-policies/opa/ shield-container:/policies/
```

### 3. Integrate Semgrep with CI/CD
```yaml
# .github/workflows/security.yml
- uses: returntocorp/semgrep-action@v1
  with:
    config: drra-policies/semgrep/
```

### 4. Run Compliance Tests
```bash
pytest tests/compliance/ -v --cov=drra_policies
```

---

## Contributing

1. **New Detection Rule** → Add to `sigma/`
2. **New Governance Policy** → Add to `opa/`
3. **New Code Pattern** → Add to `semgrep/`
4. **New Playbook** → Add to `playbooks/`
5. **New Hardening Step** → Add to `hardening/`

All contributions must:
- ✅ Pass compliance tests
- ✅ Have clear documentation
- ✅ Map to a resilience principle
- ✅ Get SOC team review

---

**Questions?** See [RESILIENCE_PRINCIPLES.md](RESILIENCE_PRINCIPLES.md) for architectural overview.
