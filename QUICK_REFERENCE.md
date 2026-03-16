# 🚀 Quick Reference Cheat Sheet

## Testing Commands (Copy & Paste)

### Run All Tests
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py -v
```

### Run by Component
```powershell
# FORGE (Simulation)
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService -v

# SENTINEL (Detection)
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestSentinelService -v

# SHIELD (Recovery)
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestShieldService -v

# END-TO-END (Complete Flow)
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestIntegration -v
```

### Run with Coverage
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py --cov=backend --cov-report=html
# Open: htmlcov/index.html
```

### Run Specific Test
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestSentinelService::test_detect_mass_modification -v
```

---

## Starting Services

### Backend API Server
```powershell
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

### Dashboard (React)
```powershell
cd dashboard
npm install
npm start
# Dashboard: http://localhost:3000
```

### File Watcher (Rust)
```powershell
cd watchers
cargo build --release
./target/release/watcher
```

### Full Stack (Docker)
```powershell
docker-compose up -d
docker-compose logs -f
```

---

## API Testing (PowerShell)

### 1. Check Backend Health
```powershell
curl http://localhost:8000/
```

### 2. Deploy Forge Payload
```powershell
$payload = @{
    name = "test"
    payload_type = "honeypot"
    target_path = "/tmp/test"
    duration_seconds = 60
    intensity = 1.0
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/forge/deploy" `
  -Method POST `
  -ContentType "application/json" `
  -Body $payload
```

### 3. Generate Honeypot
```powershell
$honeypot = @{
    file_types = @("pdf", "xlsx")
    count = 10
    size_mb = 0.5
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/forge/honeypot/generate" `
  -Method POST `
  -ContentType "application/json" `
  -Body $honeypot
```

### 4. Record Detection Event
```powershell
$event = @{
    event_id = "evt-001"
    timestamp = (Get-Date -AsUTC).ToString("o")
    threat_type = "mass_modification"
    threat_level = "critical"
    affected_path = "/home/user"
    file_count = 5000
    entropy_score = 0.87
    confidence = 0.94
    details = @{}
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/sentinel/events" `
  -Method POST `
  -ContentType "application/json" `
  -Body $event
```

### 5. Get Detection Events
```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/sentinel/events?limit=10" | Select-Object -ExpandProperty Content
```

### 6. Isolate Resource
```powershell
$isolation = @{
    resource_id = "workstation_001"
    action = "vlan_isolate"
    reason = "mass_modification_detected"
    preserve_logs = $true
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/shield/isolate" `
  -Method POST `
  -ContentType "application/json" `
  -Body $isolation
```

---

## File Structure Quick Map

```
ransomwaredefense/
├── backend/                    # FastAPI server
│   ├── main.py                # Entry point
│   ├── routes/
│   │   ├── forge_router.py
│   │   ├── sentinel_router.py
│   │   └── shield_router.py
│   ├── services/
│   │   ├── forge_service.py       ⭐ Attack simulation
│   │   ├── sentinel_service.py    ⭐ Threat detection
│   │   └── shield_service.py      ⭐ Recovery actions
│   ├── models/
│   │   └── schemas.py             ⭐ Data models
│   └── db/                    # Database setup
├── dashboard/                 # React frontend
│   ├── src/
│   │   ├── Dashboard.jsx      ⭐ Main component
│   │   └── components/
│   ├── package.json
│   └── public/
├── watchers/                  # Rust file monitoring
│   ├── src/
│   │   ├── main.rs            ⭐ Entry point
│   │   └── lib.rs             ⭐ Core logic
│   └── Cargo.toml
├── tests/
│   └── test_services.py       ⭐ 26 test cases
├── docs/
│   ├── ARCHITECTURE.md
│   └── CONTRIBUTING.md
├── TESTING_GUIDE.md           ⭐ You are here
├── CODE_FLOW_WALKTHROUGH.md   ⭐ Detailed flow
├── DEVELOPMENT_GUIDE.md       ⭐ Setup guide
└── docker-compose.yml
```

---

## Key Classes & Methods

### ForgeService (Attack Simulation)
```python
# Deploy attack
payload_id = await forge.deploy_payload(name, payload_type, target_path, duration_seconds, intensity)

# Generate honeypot files
honeypot_id = await forge.generate_honeypot(file_types, count, size_mb, target_dir)

# Simulate Kerberos
test_id = await forge.kerberos_test(target_domain)
```

### SentinelService (Threat Detection)
```python
# Record threat
event_id = await sentinel.record_detection_event(threat_type, threat_level, affected_path, file_count, entropy_score, confidence, details)

# Analyze for threats
analysis = await sentinel.analyze_path_for_threats(path, duration_seconds)

# Get LLM insights
insight = await sentinel.generate_llm_insight(event_id)
```

### ShieldService (Recovery)
```python
# Isolate resource
isolation_id = await shield.trigger_isolation(resource_id, action, reason, preserve_logs)

# Create recovery task
task_id = await shield.create_recovery_task(recovery_type, priority, preserve_forensics)

# Preserve evidence
evidence_id = await shield.preserve_forensic_evidence(incident_id, retention_days)
```

---

## Understanding Test Output

### ✅ All Passed
```
===== 26 passed in 0.57s =====
```
Everything works! ✅

### ❌ Failed Test
```
FAILED tests/test_services.py::TestForgeService::test_deploy_payload
```
Check error message for what went wrong

### ⚠️ Warnings
```
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```
Normal in Python 3.13 - doesn't affect functionality

---

## Common Issues & Fixes

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'backend'` | Set `$env:PYTHONPATH = "."` |
| Port 8000 already in use | `lsof -i :8000` then kill process |
| Tests timeout | Increase timeout: `pytest --timeout=300` |
| Honeypot files not created | Check `/tmp` exists and has write perms |
| Dashboard won't connect to API | Check backend is running on :8000 |

---

## What Each Component Does

| Component | Role | Tests It |
|-----------|------|----------|
| **FORGE** | Simulates attacks safely | Honeypot generation, Payload lifecycle |
| **SENTINEL** | Detects threats via ML | Pattern recognition, Entropy analysis |
| **SHIELD** | Responds automatically | Resource isolation, Recovery tasks |
| **DASHBOARD** | Visualizes threats | Real-time metrics, Incident timeline |
| **WATCHER** | Monitors file system | Event detection, Batching |

---

## Testing Pyramid

```
        Integration Tests (1 test)
       /                          \
      /   End-to-End Workflows     \
     /___________________________\
    
        Service Tests (15 tests)
       /                         \
      /   Individual Components    \
     /____________________________\
    
        Unit Tests (10 tests)
       /                        \
      /   Isolated Functions      \
     /___________________________\
```

Run from bottom up for faster feedback:
1. Unit tests (0.1s)
2. Service tests (0.3s)
3. Integration tests (0.2s)

---

## Environment Setup

```powershell
# 1. Create virtual environment (if needed)
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# 4. Set Python path
$env:PYTHONPATH = "."

# 5. Run tests
pytest tests/test_services.py -v
```

---

## Performance Benchmarks (Expected)

| Operation | Time | Status |
|-----------|------|--------|
| Unit tests (26 tests) | 0.57 sec | ✅ Fast |
| API endpoint response | 50-100 ms | ✅ Fast |
| Honeypot generation (10 files) | 100-200 ms | ✅ Fast |
| Pattern detection | 10-50 ms | ✅ Fast |
| LLM insight generation | 200-500 ms | ⏳ Slower (API call) |

---

## Tips & Tricks

### 1. Watch Test Changes Automatically
```powershell
# Using pytest-watch (install: pip install pytest-watch)
ptw tests/test_services.py
```

### 2. Run Tests in Parallel
```powershell
# Install: pip install pytest-xdist
pytest tests/test_services.py -n auto
```

### 3. Stop on First Failure
```powershell
pytest tests/test_services.py -x
```

### 4. Show Print Statements
```powershell
pytest tests/test_services.py -v -s
```

### 5. Run Only Failing Tests
```powershell
pytest tests/test_services.py --lf
```

---

## Next Steps After Testing

✅ Tests pass → Code is working!

Next:
1. **Code Review** - Read the source files
2. **Manual Testing** - Test API endpoints
3. **Load Testing** - Test with more data
4. **Deployment** - Use Docker Compose
5. **Production** - Follow hardening guide

---

## Resources

- 📖 [CODE_FLOW_WALKTHROUGH.md](./CODE_FLOW_WALKTHROUGH.md) - Detailed flow
- 🛠️ [DEVELOPMENT_GUIDE.md](./DEVELOPMENT_GUIDE.md) - Setup steps
- 🏗️ [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) - System design
- 📊 [IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md) - Feature list

---

**Ready to test?** Start with:
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py -v
```

Good luck! 🚀
