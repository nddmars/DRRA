# Compliance Checklists - Framework Mappings

Map DRRA security controls to industry standards (NIST CSF, SOC2, CIS Controls).

## Supported Frameworks

### 1. NIST Cybersecurity Framework (CSF)
Maps DRRA capabilities to NIST functions: Identify, Protect, Detect, Respond, Recover

**Files**:
- `nist_csf_mapping.md` – Cross-reference DRRA controls to NIST practices
- `nist_csf_checklist.xlsx` – Automated control scoring

**Key Alignment**:
- **Identify**: Honeypot generation reveals digital assets
- **Protect**: Sentinel ML + preventive controls (VSS monitoring, lateral movement blocking)
- **Detect**: Behavioral detection rules, entropy analysis, mass modification detection
- **Respond**: Shield isolation (VLAN quarantine, process kill, credential revocation)
- **Recover**: Snapshot restoration, incremental recovery, forensic preservation

### 2. SOC2 Type II Compliance
Controls for security, availability, processing integrity, confidentiality, privacy.

**Files**:
- `soc2_mapping.md` – DRRA control alignment with SOC2 trust service criteria
- `soc2_control_matrix.xlsx` – Test procedures and evidence requirements

**Key Alignment**:
- **CC6.1** (Logical access control): Identity squatting tests validate kerberos hardening
- **CC9.2** (System monitoring): Sentinel telemetry to MinIO provides immutable audit trail
- **CC9.3** (Investigation & response): Shield incident logging + forensic curation
- **A1.1** (Availability): MTTC < 60s ensures minimal service disruption

### 3. CIS Controls v8
Prioritized defenses for cybersecurity incidents (18 controls, 6 implementation groups).

**Files**:
- `cis_controls_mapping.md` – DRRA alignment with CIS v8 controls
- `cis_implementation_checklist.xlsx` – IG1/IG2/IG3 scoring

**Key Controls Addressed**:
- **Control 2** (Inventory asset management): Honeypots map sensitive file types
- **Control 5** (Account management): Identity squatting detection + auto-revocation
- **Control 10** (Malware defenses): Entropy spike detection + isolation
- **Control 13** (Data protection): Immutable logging + forensic preservation
- **Control 14** (Secure dev practices): Semgrep rules enforce logging/crypto patterns

### 4. ISO 27001:2022
Information security management system standard.

**Files**:
- `iso_27001_mapping.md` – DRRA controls to ISO clauses (69 controls across 14 sections)
- `iso_27001_statement_applicability.xlsx` – Control implementation status

## Using the Checklists

### Verify NIST CSF Coverage
```bash
# Review which NIST practices are addressed by DRRA
cat nist_csf_mapping.md | grep -A3 "DE.AE-1"  # Detect anomalies
```

### Generate SOC2 Control Matrix
```bash
python3 generate_soc2_matrix.py --output soc2_evidence.xlsx
```

### Self-Assess CIS Controls
```bash
python3 cis_self_assessment.py --implementation-group IG2
```

## Compliance Metrics

Dashboard exposes compliance score:
```
Defensibility Index (DI) =
  (NIST_CSF_coverage × 0.4) +
  (SOC2_controls_pass × 0.3) +
  (CIS_controls_pass × 0.3)
```

## Audit Trail

All compliance artifacts stored in Git:
- Policy versions tracked in commits
- Change log documents framework updates
- Evidence preserved for auditors

---

**Next**: Export compliance evidence to auditors
