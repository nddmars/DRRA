# Incident Response Playbooks

Orchestrated response runbooks for ransomware incidents. Automate the critical path: **Detect** → **Isolate** → **Preserve** → **Recover** → **Harden** → **Validate**.

## Playbook Categories

### 1. Active Ransomware Response
**Trigger**: Sentinel detection confidence > 85% + mass modification confirmed

**Execution Flow**:
```
T+0s:   Incident detected (Sentinel ML + Sigma rules)
T+0.5s: Alert to SOC team (real-time notification)
T+2.5s: Network isolation activated (Shield VLAN quarantine)
T+5s:   Evidence preservation begins (forensic snapshot to immutable MinIO)
T+30s:  Credential revocation initiated (compromised user accounts)
T+45s:  Recovery snapshot selected (pre-incident baseline)
T+2m:   Parallel recovery threads started (8 threads default)
T+30m:  Restoration complete, validation begins
T+45m:  System restored to clean state
T+1h:   Post-incident hardening policies applied
T+2h:   Full forensic analysis in Dashboard
```

**Playbook File**: `active_ransomware_response.yml`

**Key Decisions**:
- ✅ Auto-isolate or escalate to human? (Controlled by Shield policy)
- ✅ Restore from snapshot or rebuild? (OPA determines based on incident timeline)
- ✅ Revoke all credentials or selective reset? (Risk assessment)

### 2. Suspected Lateral Movement
**Trigger**: Multiple authentication failures + privilege escalation attempt

**Execution Flow**:
```
T+0s:   Lateral movement detected (identity squat correlation)
T+3s:   Blast radius analysis (determine affected systems)
T+5s:   Micro-segmentation enforcement (OPA blast radius policies)
T+10s:  Source account isolation (block credential usage)
T+20s:  Lateral movement paths blocked (network policy updates)
T+30s:  Investigation forensics gathered (authentication logs preserved)
```

**Playbook File**: `lateral_movement_response.yml`

**Key Actions**:
- Isolate source workstation
- Revoke compromised session tokens
- Block lateral movement paths (OPA VLAN rules)
- Forensic capture of auth logs (immutable MinIO storage)

### 3. Post-Incident Hardening
**Trigger**: After recovery completion, before system return to production

**Execution Flow**:
```
T+0s:   Hardening profile selected (default/high-security/aggressive)
T+5m:   Ransomware signatures updated (EDR + AV)
T+10m:  Lateral movement prevention enforced (Kerberos hardening)
T+15m:  File integrity monitoring re-baselined (FIM rules)
T+20m:  Credential reset validation (check no shared secrets remain)
T+25m:  Patch management enforced (critical patches applied)
T+30m:  System ready for user access (checkpoint reached)
```

**Playbook File**: `post_incident_hardening.yml`

**Integration**: Hardening rules defined in `drra-policies/hardening/`

### 4. Forensic Preservation & Handoff
**Trigger**: Incident contained, ready for investigation/legal review

**Execution Flow**:
```
T+0s:   Forensic data curated (chain of custody established)
T+2m:   Immutable evidence sealed (Object Lock legal hold activated)
T+5m:   Hashes generated (MD5/SHA256 for audit trail)
T+10m:  Evidence report generated (timeline, affected files, indicators)
T+15m:  SOC/Security team notified (investigation dashboards populated)
T+30m:  Export to SIEM (for compliance audit trail)
T+1h:   Legal hand-off (evidence ready for IR team/law enforcement)
```

**Playbook File**: `forensic_preservation.yml`

**Artifacts Preserved**:
- Complete file modification timeline
- Process execution logs
- Network connection logs
- Authentication events
- MinIO object integrity proofs

## Usage

### Trigger Active Response
```bash
# Manual trigger (if auto-isolation disabled)
POST /api/v1/shield/playbook/execute \
  -d '{
    "playbook": "active_ransomware_response",
    "incident_id": "INC-2026-02-19-001",
    "auto_isolate": true,
    "recovery_strategy": "snapshot_restore"
  }'
```

### Simulate Playbook Execution
```bash
# Test playbook without making changes
pytest tests/compliance/test_playbook_execution.py::test_active_ransomware_response
```

### Monitor Playbook Progress
```bash
# Dashboard shows real-time MTTC breakdown
GET /api/v1/dashboard/playbook-execution/{incident_id}

# Returns:
{
  "detection_time": 0.3,
  "isolation_time": 2.2,
  "preservation_time": 4.8,
  "recovery_time": 1800,
  "total_mttc": 45.0
}
```

## Playbook Components

Each playbook references policies and rules:

| Phase | Policy Type | Example |
|-------|------------|---------|
| **Detect** | Sigma | `ransomware_mass_modification.yml` |
| **Isolate** | OPA | `isolation_vlan_rules.rego` + `blast_radius_containment.rego` |
| **Preserve** | Semgrep | `logging_no_unlogged_file_operations.yml` |
| **Recover** | OPA | `recovery_snapshot_validation.rego` |
| **Harden** | Semgrep | `hardening_post_incident_validation.yml` |
| **Validate** | Testing | `test_golden_image.py` |

## Customization

### High-Security Profile
```yaml
# Longer isolation window, manual approval required
playbook_variant: high_security
auto_isolate: false
approval_required: true
isolation_timeout: 5m
recovery_strategy: rebuild  # Full rebuild, not snapshot
parallel_threads: 16
hardening_profile: aggressive
```

### Fast Recovery Profile
```yaml
# Minimize downtime, snapshot-based
playbook_variant: fast_recovery
auto_isolate: true
approval_required: false
isolation_timeout: 1s
recovery_strategy: snapshot_restore
parallel_threads: 8
hardening_profile: default
```

## Testing Playbooks

All playbooks must pass integration tests:

```bash
# Test complete playbook execution
pytest tests/compliance/test_playbooks.py -v

# Test individual phases
pytest tests/compliance/test_playbooks.py::test_detection_phase
pytest tests/compliance/test_playbooks.py::test_isolation_phase
pytest tests/compliance/test_playbooks.py::test_recovery_phase
pytest tests/compliance/test_playbooks.py::test_hardening_phase
```

**Pass Criteria**:
- ✅ Detection latency < 1s
- ✅ Isolation latency < 3s
- ✅ Recovery time < 60m
- ✅ Zero data loss
- ✅ All forensic evidence preserved
- ✅ System passes golden image validation

---

**Next**: Review individual playbook YAMLs and hardening profiles
