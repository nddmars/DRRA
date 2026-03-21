# Testing Guide & Code Flow

## 🔄 System Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   USER/ATTACKER ACTION                      │
│              (File modification/Encryption)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │   FORGE (Simulation Engine)     │
        │  - Deploy honeypot files        │
        │  - Simulate attack payloads     │
        │  - Test lateral movement        │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │  FILE WATCHER (Rust)            │
        │  - Monitor /tmp, /home, /var    │
        │  - Detect file modifications    │
        │  - Send events to backend       │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │  SENTINEL (Detection Engine)    │
        │  - Analyze events               │
        │  - Calculate entropy            │
        │  - Detect patterns              │
        │  - Generate insights            │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │   SHIELD (Recovery Engine)      │
        │  - Isolate compromised systems  │
        │  - Lock immutable storage       │
        │  - Start recovery workflows     │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │   DASHBOARD (React Frontend)    │
        │  - Visualize threats            │
        │  - Show MTTC metrics            │
        │  - Display incidents            │
        └─────────────────────────────────┘
```

---

## 📋 Testing Workflow (Beginner to Advanced)

### Level 1: Unit Tests (Individual Components)

#### **Test Forge Service**
```bash
# Test honeypot file generation
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService::test_generate_honeypot -v

# Test payload deployment
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService::test_deploy_payload -v

# Test Kerberos simulation
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService::test_kerberos_test -v
```

**What it tests:**
- Can honeypot files be generated?
- Does payload deployment track lifecycle?
- Is Kerberos testing simulation working?

---

#### **Test Sentinel Detection Engine**
```bash
# Test threat detection
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestSentinelService::test_record_detection_event -v

# Test behavior pattern detection
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestBehaviorPatternDetector -v

# Test entropy-based encryption detection
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestBehaviorPatternDetector::test_detect_encryption_attempt -v
```

**What it tests:**
- Does Sentinel record threats correctly?
- Can it detect mass file modifications?
- Can it identify encryption via entropy?

---

#### **Test Shield Recovery Engine**
```bash
# Test resource isolation
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestShieldService::test_trigger_isolation -v

# Test recovery task creation
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestShieldService::test_create_recovery_task -v

# Test network segmentation
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestMicroSegmentationService -v
```

**What it tests:**
- Can resources be isolated immediately?
- Are recovery tasks tracked?
- Does VLAN isolation work?

---

### Level 2: Integration Tests

#### **Full Threat Detection & Response Workflow**
```bash
# End-to-end: Deploy → Detect → Isolate → Recover
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestIntegration::test_end_to_end_threat_detection_and_response -v
```

**What it tests:**
1. Forge deploys attack payload
2. Sentinel detects threat
3. Shield isolates resources
4. Recovery task is created

---

### Level 3: API Testing (Backend Server)

#### **Start the Backend Server**
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
API Swagger UI: http://localhost:8000/docs

#### **Test API Endpoints with curl or Postman**

**1. Health Check**
```bash
curl http://localhost:8000/
```

**2. Deploy Forge Payload**
```bash
$payload = @{
    name = "test_attack"
    payload_type = "honeypot"
    target_path = "/tmp/test"
    duration_seconds = 60
    intensity = 1.0
} | ConvertTo-Json

curl -X POST http://localhost:8000/api/v1/forge/deploy `
  -Headers @{"Content-Type"="application/json"} `
  -Body $payload
```

**3. Generate Honeypot Files**
```bash
$honeypot = @{
    file_types = @("pdf", "xlsx")
    count = 10
    size_mb = 0.5
} | ConvertTo-Json

curl -X POST http://localhost:8000/api/v1/forge/honeypot/generate `
  -Headers @{"Content-Type"="application/json"} `
  -Body $honeypot
```

**4. Record Detection Event**
```bash
$event = @{
    event_id = "evt-001"
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    threat_type = "mass_modification"
    threat_level = "critical"
    affected_path = "/home/user/docs"
    file_count = 5000
    entropy_score = 0.87
    confidence = 0.94
    details = @{}
} | ConvertTo-Json

curl -X POST http://localhost:8000/api/v1/sentinel/events `
  -Headers @{"Content-Type"="application/json"} `
  -Body $event
```

**5. Get Detection Events**
```bash
curl http://localhost:8000/api/v1/sentinel/events?limit=10
```

**6. Isolate Resource**
```bash
$isolation = @{
    resource_id = "workstation_001"
    action = "vlan_isolate"
    reason = "mass_modification_detected"
    preserve_logs = $true
} | ConvertTo-Json

curl -X POST http://localhost:8000/api/v1/shield/isolate `
  -Headers @{"Content-Type"="application/json"} `
  -Body $isolation
```

---

### Level 4: Load Testing & Performance

#### **Run All Tests with Coverage Report**
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py -v --cov=backend --cov-report=html
```

This generates a coverage report in `htmlcov/index.html`

#### **Run Tests with Performance Timing**
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py -v --durations=10
```

Shows slowest 10 tests

---

### Level 5: Manual Testing Workflow

#### **Step 1: Deploy Payload via Forge**
```python
# In Python REPL or script
import asyncio
from backend.services.forge_service import ForgeService

async def test_workflow():
    forge = ForgeService()
    
    # Deploy payload
    payload_id = await forge.deploy_payload(
        name="test_payload",
        payload_type="honeypot",
        target_path="/tmp/honeypot",
        duration_seconds=60,
        intensity=1.0
    )
    print(f"✅ Payload deployed: {payload_id}")
    
    # Generate honeypot
    honeypot_id = await forge.generate_honeypot(
        file_types=["pdf", "xlsx"],
        count=10,
        size_mb=0.5,
        target_dir="/tmp"
    )
    print(f"✅ Honeypot generated: {honeypot_id}")

asyncio.run(test_workflow())
```

#### **Step 2: Detect Threats via Sentinel**
```python
import asyncio
from backend.services.vigil_service import VigilService

async def test_detection():
    sentinel = SentinelService()
    
    # Record event
    event_id = await sentinel.record_detection_event(
        threat_type="mass_modification",
        threat_level="critical",
        affected_path="/tmp/honeypot",
        file_count=100,
        entropy_score=0.89,
        confidence=0.95,
        details={"source": "test"}
    )
    print(f"✅ Threat detected: {event_id}")
    
    # Get insights
    insight = await sentinel.generate_llm_insight(event_id)
    print(f"✅ LLM Insight: {insight['threat_summary']}")

asyncio.run(test_detection())
```

#### **Step 3: Respond via Shield**
```python
import asyncio
from backend.services.shield_service import ShieldService

async def test_recovery():
    shield = ShieldService()
    
    # Isolate resource
    isolation_id = await shield.trigger_isolation(
        resource_id="workstation_001",
        action="vlan_isolate",
        reason="mass_modification_detected"
    )
    print(f"✅ Resource isolated: {isolation_id}")
    
    # Create recovery task
    task_id = await shield.create_recovery_task(
        recovery_type="restore_snapshot",
        priority=1
    )
    print(f"✅ Recovery task created: {task_id}")

asyncio.run(test_recovery())
```

---

## 🧪 Test Categories & What They Cover

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_deploy_payload` | Forge simulates attacks | Payload lifecycle management |
| `test_generate_honeypot` | Forge creates trap files | File generation works |
| `test_record_detection_event` | Sentinel logs threats | Event recording pipeline |
| `test_detect_mass_modification` | Sentinel identifies patterns | ML detection algorithms |
| `test_detect_encryption_attempt` | Sentinel analyzes entropy | Encryption detection |
| `test_trigger_isolation` | Shield responds immediately | Auto-remediation works |
| `test_create_recovery_task` | Shield orchestrates recovery | Recovery workflows |
| `test_end_to_end_threat_detection_and_response` | Complete workflow | Full system integration |

---

## 📊 Quick Test Commands

### Run All Tests
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py -v
```

### Run Only Passing Tests (exclude slow ones)
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py -v -m "not slow"
```

### Run Specific Component
```bash
# Forge only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService -v

# Sentinel only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestSentinelService -v

# Shield only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestShieldService -v
```

### Run with Stopwatch (show timing)
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py -v -durations=0
```

### Generate HTML Coverage Report
```bash
$env:PYTHONPATH = "."; pytest tests/test_services.py --cov=backend --cov-report=html
# Open: htmlcov/index.html
```

---

## 🔍 Understanding Test Results

### ✅ PASSED
Test completed successfully. Feature works as expected.

### ❌ FAILED
Test failed. Check the error message for what went wrong.

### ⏭️ SKIPPED
Test was skipped (marked with `@pytest.mark.skip`).

### ⚠️ WARNINGS
Test passed but has deprecation warnings (as seen with `datetime.utcnow()`).

---

## 💡 Tips for Testing

1. **Always run full suite before committing**
   ```bash
   $env:PYTHONPATH = "."; pytest tests/test_services.py -v
   ```

2. **Check coverage to find untested code**
   ```bash
   $env:PYTHONPATH = "."; pytest --cov=backend --cov-report=term-missing
   ```

3. **Use verbose mode to see detailed output**
   ```bash
   $env:PYTHONPATH = "."; pytest -v -s
   ```

4. **Stop on first failure for debugging**
   ```bash
   $env:PYTHONPATH = "."; pytest -x
   ```

5. **Run tests matching a pattern**
   ```bash
   $env:PYTHONPATH = "."; pytest -k "mass_modification"
   ```

---

## 🚀 Next Steps

After testing the backend:

1. **Test the Dashboard**
   ```bash
   cd dashboard
   npm install
   npm start
   # Visit http://localhost:3000
   ```

2. **Test the File Watcher**
   ```bash
   cd watchers
   cargo test
   ```

3. **Test with Docker**
   ```bash
   docker-compose up -d
   docker-compose logs -f
   ```

---

## 📞 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'backend'` | Set `$env:PYTHONPATH = "."` before pytest |
| Tests pass but warnings appear | Normal - related to Python 3.13 deprecations |
| API port already in use | Kill process: `lsof -i :8000` |
| Honeypot files not generating | Check `/tmp` directory exists and has write permissions |

---

**Happy Testing!** 🎉

