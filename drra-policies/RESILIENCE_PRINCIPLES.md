# Resilience Principles - DRRA Architectural Foundation

Six core principles guide Resilience Forge architecture and response decisions.

## 1. Immutability First

**Principle**: Evidence and recovery data cannot be altered or deleted.

**Implementation**:
- MinIO S3 Compliance Mode (Object Lock + Legal Hold)
- Write-once audit logs (append-only)
- Forensic evidence stored separately from operational data
- 365-day minimum retention for all incident artifacts

**Why**: Ransomware attackers prioritize deletion of backup chains and audit trails. Immutable storage ensures even successful encryption cannot erase evidence or prevent recovery.

**Example**:
```python
# MinIO object is immutable - attacker cannot delete
minio_client.set_object_lock(
    bucket="forensics",
    object_name="incident-2026-02-19.tar",
    mode="GOVERNANCE",
    retention_days=365
)
```

---

## 2. Defense-in-Depth (Layered Detection)

**Principle**: Multiple independent detection layers catch attacks missed by others.

**Implementation**:
- Layer 1 (Behavioral): ML entropy + mass modification patterns
- Layer 2 (Rules-Based): Sigma rules for known ransomware indicators
- Layer 3 (Heuristic): VSS abuse, lateral movement correlation
- Layer 4 (Forensic): Post-incident log analysis for root cause

**Why**: No single detection method is perfect. Layered approach ensures attacker must defeat multiple systems simultaneously.

**Example**:
```
File encrypted by ransomware:
  ✓ Layer 1: Entropy spike detected (>0.85)
  ✓ Layer 2: Sigma rule "suspicious extension" triggered
  ✓ Layer 3: Process correlation links to lateral movement
  ✓ Result: High-confidence incident classification
```

**DRRA Implementation**:
- Sigma rules (vendor-agnostic detection)
- OPA policies (governance verification)
- Semgrep patterns (secure code validation)
- Multi-stage incident verification

---

## 3. Automated Response with Human Checkpoints

**Principle**: Automate time-critical actions, require humans for risk-critical decisions.

**Implementation**:
- ✅ **Auto-Execute**: Detection → Isolation (< 3 seconds)
- ✅ **Auto-Execute**: Evidence preservation (immutable storage)
- ✅ **Auto-Execute**: Credential revocation (clear compromise)
- **Manual Review**: Recovery strategy selection (snapshot vs rebuild)
- **Manual Review**: High-risk hardening changes
- **Manual Review**: Public disclosure decisions

**Why**: Seconds matter in containment, but irreversible decisions need human judgment.

**Example**:
```yaml
# Auto-execute (no approval needed)
- detect_and_isolate:
    isolation_timeout: 2.5s
    auto_isolate: true

# Manual approval required
- recovery_strategy:
    requires_approval: true
    approval_timeout: 10m
```

---

## 4. Fail-Secure Design

**Principle**: When uncertain, always choose the defensive option (even if inconvenient).

**Implementation**:
- Network isolation defaults to **deny** (assume compromise)
- Credential revocation defaults to **all users** (assume domain-wide impact)
- Recovery defaults to **snapshot restore** (fastest, safest)
- Hardening defaults to **aggressive profile** (maximum protection)

**Why**: Type II errors (false positives) are recoverable; Type I errors (missed malware) are catastrophic.

**Example**:
```python
# Fail-secure: if confidence < 85%, escalate instead of ignoring
if detection_confidence < 0.85:
    escalate_to_soc_team()  # Don't auto-isolate, but alert human
else if detection_confidence >= 0.85:
    auto_isolate()  # High confidence = automatically respond
```

---

## 5. Graceful Degradation

**Principle**: System loses features, never security.

**Implementation**:
- If isolation fails → escalate to manual intervention
- If recovery fails → preserve forensics, attempt alternative strategy
- If ForensicIO unavailable → buffer events locally, sync later
- If Dashboard unavailable → Shield still executes, just no visibility

**Why**: Ransomware aims to disable defenses. Graceful degradation ensures core resilience survives component failures.

**Example**:
```python
try:
    isolate_vlan()  # Preferred method
except VLANUnavailableError:
    kill_process()  # Fallback
except ProcessKillFailedError:
    revoke_credentials()  # Last resort
    alert_soc_team()  # Manual escalation
```

---

## 6. Zero-Trust Recovery

**Principle**: Verify everything post-recovery; assume restoration may be compromised.

**Implementation**:
- Golden image validation (hash all system binaries)
- Malware rescan with fresh definitions
- Lateral movement tests (verify isolation holds)
- Configuration consistency checks
- Network connectivity validation

**Why**: Ransomware may evade snapshot (e.g., fileless malware in memory, registry persistence). Post-recovery validation catches survival attempts.

**Example**:
```python
post_recovery_checks = [
    golden_image_validation(check_binary_integrity=True),
    malware_rescan(definitions_age_max=1h),
    network_connectivity_test(),
    lateral_movement_test(),
    fim_rebaseline()
]

for check in post_recovery_checks:
    if check.failed():
        alert_soc_team("Recovery may be compromised")
        return QUARANTINE_SYSTEM
```

---

## Principles in Action: Ransomware Incident Response

```
Incident: WannaCry outbreak detected on finance-shares-01

T+0.1s  [Principle 2: Defense-in-Depth]
        Entropy spike detected + mass modification confirmed + VSS abuse observed
        → High confidence classification

T+0.5s  [Principle 1: Immutability First]
        Forensic snapshot captured immediately, locked to immutable storage
        → Evidence cannot be deleted

T+2.5s  [Principle 3: Automated Response with Checkpoints]
        Auto-isolate triggered (confidence > 85%)
        → VLAN quarantine activated, no human delay

T+5s    [Principle 4: Fail-Secure Design]
        Assume full domain compromise (fail-secure)
        → Revoke all user credentials (not just affected share)

T+30s   [Principle 5: Graceful Degradation]
        Primary isolation method succeeds
        → Continue to recovery phase

T+45m   [Principle 6: Zero-Trust Recovery]
        Snapshot fully restored
        → Validate against golden image (100% binary hashes checked)
        → Rescan with fresh malware definitions
        → Lateral movement tests confirm isolation

Result:  ✅ Incident contained in <3s
         ✅ Zero forensic data loss
         ✅ Recovery completed in 45 minutes
         ✅ System verified clean before user access
```

---

## Architectural Implications

| Principle | Policy Type | Example Implementation |
|-----------|------------|--------|
| **Immutability First** | OPA + Semgrep | `immutability_object_lock_activation.rego` |
| **Defense-in-Depth** | Sigma + OPA + Semgrep | Multi-layer detection + validation |
| **Automated + Checkpoints** | Playbooks + OPA | `active_ransomware_response.yml` |
| **Fail-Secure** | OPA policies | `isolation_vlan_rules.rego` (default deny) |
| **Graceful Degradation** | Semgrep + Shield | Error handling + fallback strategies |
| **Zero-Trust Recovery** | Semgrep + Golden image | `golden_image_validation.yml` |

---

**Next**: Review how each component implements these principles
