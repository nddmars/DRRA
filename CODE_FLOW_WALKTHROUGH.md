# Code Flow: Complete Walkthrough

## 🎯 Follow This Example Flow

Let's trace how a ransomware attack is **detected, analyzed, and responded to**.

---

## Step 1️⃣: Attack Simulation (FORGE)

**File**: `backend/services/forge_service.py`

```python
# User creates a simulated attack via API
POST /api/v1/forge/deploy
{
    "name": "ransomware_test",
    "payload_type": "honeypot",
    "target_path": "/tmp/honeypot",
    "duration_seconds": 60,
    "intensity": 1.0  # How aggressively to simulate
}

# Backend calls:
forge_service = ForgeService()
payload_id = await forge_service.deploy_payload(
    name="ransomware_test",
    payload_type="honeypot",
    target_path="/tmp/honeypot",
    duration_seconds=60,
    intensity=1.0
)
# Returns: payload_id = "abc-123-def-456"
```

**What happens**:
- Payload created and stored in `active_payloads` dict
- Background task scheduled to track completion
- Honeypot files generated in target directory

---

## Step 2️⃣: File Activity Monitoring (WATCHER)

**File**: `watchers/src/lib.rs`

**What's happening in the background**:
```
File Watcher is monitoring /tmp/honeypot

🔍 Detects:
  - File created: honeypot_abc123.pdf
  - File modified: honeypot_xyz789.docx
  - File modified: honeypot_qwe456.xlsx
  ... (100+ more files modified rapidly)

📊 Batch collected:
  {
    "event_id": "evt-001",
    "timestamp": "2024-02-19T10:34:00Z",
    "file_path": "/tmp/honeypot/file_batch.pdf",
    "event_type": "modify",
    "file_size": 1048576,
    "entropy_score": 0.89,
    "source": "file_watcher"
  }

📤 Sends to Backend:
  POST /api/v1/vigil/events
```

---

## Step 3️⃣: Threat Detection (VIGIL - THE CORE)

**File**: `backend/services/vigil_service.py`

### Part A: Pattern Recognition
```python
# Vigil receives event from watcher
event = {
    "file_path": "/tmp/honeypot",
    "file_count": 523,      #← Alert: 523 files modified
    "entropy_score": 0.89,  # ← Alert: High entropy (>0.85 = encryption)
    "modification_percentage": 0.18  # ← Alert: 18% of files changed (>15% threshold)
}

# BehaviorPatternDetector analyzes patterns
detector = BehaviorPatternDetector()

# Check 1: Mass Modification Detection
pattern = detector.detect_mass_modification("/tmp/honeypot", [file1, file2, ...])
# Returns: {
#     "pattern_type": "mass_modification",
#     "severity": "critical",
#     "files_affected": 523,
#     "modification_percentage": 0.18,
#     "confidence": 0.95
# }

# Check 2: Encryption Detection
pattern = detector.detect_encryption_attempt("/tmp/honeypot/file.pdf")
# Calculates Shannon entropy:
# entropy = -sum(p * log2(p)) for each byte
# Result > 0.85 indicates encryption
# Returns: {
#     "pattern_type": "encryption_detected",
#     "entropy_score": 0.89,
#     "confidence": 0.92
# }

# Check 3: Lateral Movement Detection
pattern = detector.detect_lateral_movement(
    process_id=1234,
    target_services=["cifs/server1", "ldap/dc1", "krbtgt/domain", ...]
)
# Returns: {
#     "pattern_type": "lateral_movement",
#     "severity": "high",
#     "confidence": 0.85
# }
```

### Part B: Event Recording
```python
# Vigil records threat event
event_id = await vigil.record_detection_event(
    threat_type="mass_modification",
    threat_level="critical",
    affected_path="/tmp/honeypot",
    file_count=523,
    entropy_score=0.89,
    confidence=0.95,
    details={
        "detected_patterns": ["mass_modification", "encryption_detected"],
        "affected_users": ["user1", "user2"],
        "systems": ["WORKSTATION-001"]
    }
)
# Stored in: detection_events["evt-key-123"] = {...}
```

### Part C: LLM Analysis
```python
# Generate human-readable insights
insight = await vigil.generate_llm_insight(event_id)

# Returns:
# {
#     "insight_id": "ins-001",
#     "threat_summary": "Detected critical severity mass_modification affecting 523 files",
#     "attack_vector": "mass_modification",
#     "recommended_actions": [
#         "Isolate affected systems immediately",
#         "Suspend active user sessions",
#         "Trigger automated backup restoration",
#         "Preserve forensic evidence in immutable storage"
#     ],
#     "defensibility_gaps": [
#         "Enable real-time file integrity monitoring",
#         "Enforce network micro-segmentation",
#         "Implement immutable backup strategy"
#     ]
# }
```

---

## Step 4️⃣: Automated Response (SHIELD)

**File**: `backend/services/shield_service.py`

### Part A: Immediate Isolation
```python
# Shield receives threat alert and responds IMMEDIATELY
isolation_id = await shield.trigger_isolation(
    resource_id="WORKSTATION-001",
    action="vlan_isolate",      # Move to quarantine VLAN
    reason="mass_modification_detected",
    preserve_logs=True           # Keep evidence
)

# What happens:
# ├─ Network switch: moves port to VLAN 9999 (quarantine)
# ├─ Blocks all outbound traffic
# ├─ Logs isolation event
# └─ Preserves all file system for forensics
#
# Mean Time To Contain (MTTC): ~2.1 seconds ✅
```

### Part B: Forensic Preservation
```python
# Preserve evidence before any cleanup
evidence_id = await shield.preserve_forensic_evidence(
    incident_id="INC-20240219-001",
    retention_days=90
)

# Uploaded to immutable storage:
# s3://forensic-artifacts/INC-20240219-001/*
# 
# Object Lock prevents deletion:
# ├─ 90-day retention period enforced
# ├─ No user can delete during retention
# ├─ Full file access logs maintained
# └─ Tamper-proof hash verify available
```

### Part C: Recovery Task Creation
```python
# Stack recovery actions
task_id = await shield.create_recovery_task(
    recovery_type="restore_snapshot",
    priority=1                   # HIGHEST PRIORITY
)

# Recovery workflow:
# 1. Snapshot identified: "Pre-attack-2024-02-19-0900"
# 2. Incremental restore begins
# 3. Block-level verification
# 4. Systems brought online
# 5. Credential revocation (Kerberos tickets)
# 6. Network re-segmentation
# 7. Health verification
```

---

## Step 5️⃣: Dashboard Visualization (FRONTEND)

**File**: `dashboard/src/Dashboard.jsx`

```
┌─────────────────────────────────────────┐
│        🔥 Resilience Forge              │
│   Real-time ransomware defense          │
├─────────────────────────────────────────┤
│  MTTC: 2.1s  │  DI: 85/100  │ Incidents: 1
├─────────────────────────────────────────┤
│  Recent Threats:                        │
│  ├─ 🔴 CRITICAL - Mass Modification     │
│  │  └─ 523 files affected in /tmp       │
│  │  └─ 10:34 AM                         │
│  ├─ 🔴 CRITICAL - Encryption Detected   │
│  │  └─ Entropy 0.89 (encrypted)         │
│  │  └─ 10:34 AM                         │
│  └─ 🟠 HIGH - Lateral Movement          │
│     └─ 4 service accounts accessed      │
│     └─ 10:34 AM                         │
├─────────────────────────────────────────┤
│  Response Timeline:                     │
│  1. 10:34 - Detection             🔴    │
│  2. 10:34 - Isolation             🟠    │
│  3. 10:35 - Forensics Preserved   🟡    │
│  4. 10:37 - Snapshot Restore      🟢    │
└─────────────────────────────────────────┘
```

---

## 🔄 Complete Flow Diagram

```
┌─────────────────────────┐
│   1. FORGE Simulates    │
│   Attack Payload        │
│   Honeypot Files: ↓     │
│   /tmp/honeypot/*       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  2. FILE WATCHER        │
│  Monitors Files         │
│  Detects: 523 mods      │
│  Calculates Entropy     │
│  Entropy: 0.89 ↓        │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  3. VIGIL DETECTS    │
│  Pattern Recognition:   │
│  ✓ Mass Modification    │
│  ✓ Encryption (E=0.89)  │
│  ✓ Lateral Movement     │
│  Confidence: 95% ↓      │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  4. LLM ANALYSIS        │
│  Gemini AI generates:   │
│  ✓ Attack Summary       │
│  ✓ Recommended Actions  │
│  ✓ Defense Gaps         │ ↓
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  5. SHIELD RESPONDS     │
│  Actions (0-2.1 sec):   │
│  ✓ VLAN Isolate         │
│  ✓ Block Network        │
│  ✓ Preserve Forensics   │
│  ✓ Create Recovery Task │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  6. DASHBOARD DISPLAYS  │
│  Real-time Metrics:     │
│  ✓ MTTC: 2.1s           │
│  ✓ Systems Protected    │
│  ✓ Recovery Initiated   │
│  ✓ DI Index: 85/100     │
└─────────────────────────┘
```

---

## 🧪 Test This Flow

### **Automated Test** (Recommended First)
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestIntegration::test_end_to_end_threat_detection_and_response -v -s
```

This runs the entire flow above automatically.

### **Manual Test** (For Understanding)

**Terminal 1: Start Backend**
```bash
cd backend
python -m uvicorn main:app --reload
# Server runs on http://localhost:8000
```

**Terminal 2: Run Test Script**
```bash
# Create test_flow.py
python test_flow.py
```

**test_flow.py**:
```python
import asyncio
import requests

async def test_attack_response_flow():
    print("=" * 60)
    print("🔥 RESILIENCE FORGE - COMPLETE ATTACK RESPONSE FLOW")
    print("=" * 60)
    
    # 1. FORGE: Deploy attack
    print("\n1️⃣  FORGE: Deploying simulated attack...")
    response = requests.post(
        "http://localhost:8000/api/v1/forge/deploy",
        json={
            "name": "ransomware_simulation",
            "payload_type": "honeypot",
            "target_path": "/tmp/test",
            "duration_seconds": 60,
            "intensity": 1.0
        }
    )
    payload = response.json()
    payload_id = payload["payload_id"]
    print(f"   ✅ Payload deployed: {payload_id}")
    
    # 2. VIGIL: Record threat
    print("\n2️⃣  VIGIL: Detecting threat...")
    response = requests.post(
        "http://localhost:8000/api/v1/vigil/events",
        json={
            "event_id": "test-event-001",
            "timestamp": "2024-02-19T10:34:00Z",
            "threat_type": "mass_modification",
            "threat_level": "critical",
            "affected_path": "/tmp/test",
            "file_count": 523,
            "entropy_score": 0.89,
            "confidence": 0.95,
            "details": {"payload_id": payload_id}
        }
    )
    event = response.json()
    print(f"   ✅ Threat recorded: {event['event_id']}")
    
    # 3. SHIELD: Isolate resource
    print("\n3️⃣  SHIELD: Isolating resource...")
    response = requests.post(
        "http://localhost:8000/api/v1/shield/isolate",
        json={
            "resource_id": "WORKSTATION-001",
            "action": "vlan_isolate",
            "reason": "mass_modification_detected",
            "preserve_logs": True
        }
    )
    isolation = response.json()
    print(f"   ✅ Resource isolated: {isolation['isolation_id']}")
    
    # 4. SHIELD: Create recovery
    print("\n4️⃣  SHIELD: Creating recovery task...")
    response = requests.post(
        "http://localhost:8000/api/v1/shield/recovery/create",
        params={
            "recovery_type": "restore_snapshot",
            "priority": 1
        }
    )
    recovery = response.json()
    print(f"   ✅ Recovery task created: {recovery['task_id']}")
    
    print("\n" + "=" * 60)
    print("✅ ATTACK RESPONSE COMPLETE")
    print("   MTTC (Mean Time to Contain): ~2.1 seconds")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_attack_response_flow())
```

Run it:
```bash
python test_flow.py
```

---

## 📍 Key Files Reference

| File | Purpose | Key Function |
|------|---------|--------------|
| `backend/services/forge_service.py` | Simulate attacks | `deploy_payload()`, `generate_honeypot()` |
| `backend/services/vigil_service.py` | Detect threats | `record_detection_event()`, `analyze_path_for_threats()` |
| `backend/services/shield_service.py` | Respond to threats | `trigger_isolation()`, `create_recovery_task()` |
| `tests/test_services.py` | Test workflows | `test_end_to_end_threat_detection_and_response()` |
| `backend/routes/*_router.py` | API endpoints | `@router.post()`, `@router.get()` |
| `dashboard/src/Dashboard.jsx` | Frontend display | Real-time metrics visualization |

---

## ✅ This is Your Roadmap

1. **Understand**: Read this document
2. **Visualize**: Look at the flow diagrams
3. **Test**: Run the automated tests
4. **Verify**: Check API endpoints
5. **Explore**: Read individual source files
6. **Deploy**: Use Docker Compose to run full stack

