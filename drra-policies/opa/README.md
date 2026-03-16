# OPA/Rego Policies - Infrastructure Governance

Policy-as-code for Resilience Forge isolation, recovery, and immutability enforcement. Ensures safe automated responses to ransomware incidents.

## Policy Categories

### 1. Isolation Governance
Enforces safe network quarantine decisions.

**Policies**:
- `isolation_vlan_rules.rego` – Validates VLAN assignment, prevents blocking critical services
- `isolation_network_quarantine.rego` – Ensures isolated hosts can't reach sensitive assets
- `isolation_process_kill_safelist.rego` – Prevents killing system-critical processes

**Use Case**:
```
Shield receives isolation trigger
  ↓
OPA evaluates: Is process safe to kill? Is VLAN available?
  ↓
If policy passes → Execute isolation
If policy fails → Escalate to human review
```

### 2. Recovery Governance
Controls how systems are restored post-incident.

**Policies**:
- `recovery_snapshot_validation.rego` – Ensures restore point is clean (pre-incident)
- `recovery_parallel_threads.rego` – Enforces resource limits (max 16 threads)
- `recovery_credential_revocation.rego` – Validates users to revoke
- `recovery_data_integrity_checks.rego` – Requires hash validation post-restore

### 3. Immutability Enforcement
Guarantees logs and forensic data cannot be tampered with.

**Policies**:
- `immutability_object_lock_activation.rego` – Validates Object Lock is enabled
- `immutability_legal_hold.rego` – Requires legal hold on forensic buckets
- `immutability_audit_log_retention.rego` – Enforces 90-day minimum retention
- `immutability_deletion_prevention.rego` – Rejects any deletion requests

### 4. Compliance Governance
Enforces audit, monitoring, and security controls.

**Policies**:
- `compliance_logging_required.rego` – All actions must be logged
- `compliance_role_based_access.rego` – RBAC for isolation/recovery triggers
- `compliance_incident_approval.rego` – High-risk actions need approval

## Usage

### Validate Recovery Decision
```bash
opa eval -d recovery_snapshot_validation.rego \
  -i incident.json \
  'data.recovery.allow_snapshot_restore'
```

### Validate Isolation Decision
```bash
opa eval -d isolation_vlan_rules.rego \
  -i isolation_request.json \
  'data.isolation.allow_vlan_quarantine'
```

### Enforce in Shield Service
```python
# In shield_service.py
import json
from subprocess import run

incident = {
    "process_id": 1234,
    "affected_paths": ["/home/user/documents"],
    "target_vlan": "QUARANTINE_10",
}

result = run([
    'opa', 'eval',
    '-d', 'drra-policies/opa/isolation_vlan_rules.rego',
    '-i', json.dumps(incident),
    'data.isolation.allow_vlan_quarantine'
], capture_output=True)

if result.stdout == 'true':
    # Execute isolation
    shield.isolate(incident)
else:
    # Escalate to human review
    alert_soc_team(incident, "Policy violation in isolation")
```

## Testing Policies

```bash
pytest tests/compliance/test_opa_policies.py
```

Each policy must:
- ✅ Allow legitimate recovery scenarios
- ✅ Block dangerous operations (deleting logs, killing critical services)
- ✅ Provide clear denial reasons
- ✅ Support audit logging

## Contributing New Policies

1. Write Rego policy with clear allow/deny logic
2. Add test cases (both allow/deny scenarios)
3. Document policy rationale
4. Get SOC team approval
5. Deploy to Shield service

---

**Policy Structure** (see `isolation_vlan_rules.rego` for example)
