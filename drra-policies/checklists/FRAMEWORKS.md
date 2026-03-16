# DRRA Control Cross-Reference

## NIST CSF v1.1 Mapping

### Function: IDENTIFY (ID)

| NIST Control | Description | DRRA Implementation |
|---|---|---|
| **ID.AM-1** | Physical devices and systems | Honeypot deployment maps real assets |
| **ID.BE-1** | Business objectives | MTTC/DI metrics driven by incident impact |
| **ID.RA-1** | Risk assessment | Sentinel entropy + behavioral analysis |
| **ID.RA-2** | Risk ranking | Dashboard severity classification |

### Function: PROTECT (PR)

| NIST Control | Description | DRRA Implementation |
|---|---|---|
| **PR.AC-1** | Logical access controls | Identity squatting tests validate kerberos hardening |
| **PR.AC-4** | Multi-factor authentication | OPA policies enforce MFA for recovery triggers |
| **PR.DS-1** | Data handling | Immutability enforced at MinIO layer |
| **PR.DS-2** | Data in transit | Encrypted Kafka streams for telemetry |

### Function: DETECT (DE)

| NIST Control | Description | DRRA Implementation |
|---|---|---|
| **DE.AE-1** | Detect anomalies | Mass modification >15%, entropy >0.85 |
| **DE.CH-1** | Insider threats | Lateral movement correlation rules |
| **DE.CM-1** | Network monitoring | File watcher telemetry to Sentinel |
| **DE.CM-7** | Monitoring processes | VSS abuse detection |

### Function: RESPOND (RS)

| NIST Control | Description | DRRA Implementation |
|---|---|---|
| **RS.MI-1** | Mitigation | Shield VLAN isolation <2.5 seconds |
| **RS.MI-2** | Incident containment | Process kill + credential revocation |
| **RS.IM-1** | Incident response processes | OPA governance policies guide automation |

### Function: RECOVER (RC)

| NIST Control | Description | DRRA Implementation |
|---|---|---|
| **RC.RP-1** | Recovery planning | Snapshot-based point-in-time restore |
| **RC.IM-1** | Incident recovery | 99.9% recovery success target |
| **RC.IM-2** | Recovery info restoration | Forensic curation preserves evidence |

---

## SOC2 Type II Mapping

### Trust Service Category: Security (CC)

| Control | Requirement | DRRA Evidence |
|---|---|---|
| **CC6.1** | Logical access protection | OPA policies validate identity squat tests |
| **CC6.2** | Authentication | Kerberos hardening validation in Forge |
| **CC7.2** | System monitoring | Sentinel/Vector telemetry to immutable MinIO |
| **CC7.3** | Alerts | Dashboard real-time incident notifications |
| **CC9.2** | Log monitoring | Immutable audit logs with Object Lock |
| **CC9.3** | Investigation tools | Forensic curation + chain of custody |

### Trust Service Category: Availability (A1)

| Control | Requirement | DRRA Evidence |
|---|---|---|
| **A1.1** | System availability | MTTC <60s prevents prolonged downtime |
| **A1.2** | Incident response | Shield recovery <45 minutes target |

### Trust Service Category: Processing Integrity (PI)

| Control | Requirement | DRRA Evidence |
|---|---|---|
| **PI1.1** | Data completeness | >99.9% file recovery validation |
| **PI1.3** | Data accuracy | MD5/SHA256 integrity verification |

---

## CIS Controls v8 Mapping

### Group 1: Foundational (IG1)

| Control | Description | DRRA Implementation |
|---|---|---|
| **01** | Inventory & control of assets | Honeypots catalog sensitive data types |
| **02** | Inventory & control of hardware devices | File watcher asset discovery |
| **04** | Controlled use of administrative privileges | OPA policies restrict isolation triggers |
| **05** | Account management | Identity squatting tests enforce hardened auth |

### Group 2: Foundational & Intermediate (IG2)

| Control | Description | DRRA Implementation |
|---|---|---|
| **10** | Malware defenses | Entropy analysis detects encrypted payloads |
| **13** | Data protection | Immutable MinIO storage + Object Lock |
| **14** | Secure development | Semgrep rules enforce logging + crypto patterns |

### Group 3: Intermediate & Advanced (IG3)

| Control | Description | DRRA Implementation |
|---|---|---|
| **23** | Incident response | Shield automation + forensics preservation |

---

## ISO 27001:2022 Mapping

### Annex A: Control Objectives & Controls

| Clause | Domain | DRRA Controls |
|---|---|---|
| **A.5** | Organizational controls | OPA governance policies + compliance checklists |
| **A.6** | People controls | RBAC for incident response approvals |
| **A.7** | Physical controls | Honeypot protection within secure infrastructure |
| **A.8** | Technical controls | Sentinel detection + Shield isolation |

**Key Controls**:
- **A.8.1.1**: Information processing facilities → Sentinel telemetry monitoring
- **A.8.2.1**: User endpoint devices → File watcher + entropy analysis
- **A.8.3.1**: Access control → Identity squatting validation
- **A.8.4.1**: Cryptography → Semgrep crypto validation rules
- **A.9.1.1**: Event logging → MinIO immutable audit trail
- **A.9.4.2**: Secure development → Semgrep SAST integration

---

**Evidence Generation**:
All compliance artifacts automatically exported to `compliance-reports/` for auditor review.
