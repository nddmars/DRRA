# Testing Flow Decision Tree

## 🎯 Where to Start?

```
                    ┌─ Ready to Code?
                    │
         ┌──────────▼──────────┐
         │  DECISION: Start    │
         │  Where?             │
         └──────────┬──────────┘
                    │
         ┌──────────┴──────────┬──────────┬──────────┐
         │                     │          │          │
         ▼                     ▼          ▼          ▼
    I want to       I want to        I want to    I want to
    RUN TESTS       UNDERSTAND       TEST API     DEPLOY
                    THE CODE         ENDPOINTS    (Docker)
         │                 │             │          │
         │                 │             │          │
         ▼                 ▼             ▼          ▼
    ┌────────┐      ┌──────────┐   ┌──────────┐  ┌──────┐
    │SECTION │      │SECTION 2 │   │SECTION 3 │  │  4   │
    │   1    │      │   CODE   │   │   API    │  │ 4.1  │
    │ TESTS  │      │  FLOW    │   │ TESTING  │  │      │
    └────────┘      └──────────┘   └──────────┘  └──────┘
```

---

## ✅ SECTION 1: RUNNING TESTS

```
START
  │
  ▼
┌─────────────────────────────┐
│ Want quick test result?     │
└─────────────┬───────────────┘
              │
   ┌──────────┴──────────┐
   │                     │
   ▼                     ▼
  YES                   NO
   │                     │
   │                     ▼
   │          ┌──────────────────────────┐
   │          │ Want detailed output?    │
   │          └──────┬───────────────────┘
   │                 │
   ▼                 ▼
RUN THIS:        RUN THIS:
                 
$env:PYTHONPATH  $env:PYTHONPATH = ".";
= ".";           pytest tests/test_services.py
pytest tests/    -v -s --tb=long
test_services.py
                 (Shows every detail)
│                │
▼                ▼
(Quick!)     (Detailed!)
   │                └─┬────────┐
   │                  │        │
   └──────┬───────────┘        │
          │                    │
          ▼                    ▼
    ┌──────────────┐   ┌──────────────────┐
    │All PASS? ✅  │   │All PASS? ✅      │
    │              │   │                  │
    │Done!         │   │Coverage Report?  │
    │              │   │(HTML)            │
    └──────────────┘   └────────┬─────────┘
                                │
                        ┌───────┘
                        │
                        ▼
                   RUN THIS:
            $env:PYTHONPATH = ".";
            pytest tests/test_services.py 
            --cov=backend --cov-report=html
            
            Open: htmlcov/index.html
                        │
                        ▼
                   ✅ SEE COVERAGE
```

### **Test Commands By Scenario**

#### Scenario A: I just want to see if tests pass
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py -q
```

#### Scenario B: I want to see what each test does
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py -v
```

#### Scenario C: I want to see everything (debugging)
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py -v -s --tb=long
```

#### Scenario D: I want a coverage report
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py --cov=backend --cov-report=html
```

#### Scenario E: I want to test only one component
```powershell
# Test Forge only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestForgeService -v

# Test Sentinel only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestSentinelService -v

# Test Shield only
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestShieldService -v
```

#### Scenario F: I want the full end-to-end test
```powershell
$env:PYTHONPATH = "."; pytest tests/test_services.py::TestIntegration -v -s
```

---

## 📚 SECTION 2: UNDERSTANDING THE CODE FLOW

```
START
  │
  ▼
┌──────────────────────────────────┐
│ What do you want to understand?  │
└────────┬───────────────────┬────┬┘
         │                   │    │
         ▼                   ▼    ▼
    How does          What is          How do I
    attack            each               trace
    detection         component          through
    work?             responsible        the code?
        │             for?                  │
        │                 │                 │
        ▼                 ▼                 ▼
   READ:            READ:             READ:
   CODE_FLOW_       ARCHITECTURE.md   DEVELOPMENT
   WALKTHROUGH.md   + Services        _GUIDE.md
                                      
        │                 │                 │
        ▼                 ▼                 ▼
   📖 Detailed      📊 System design   🔧 Setup &
   step-by-step    overview            structure
   walkthrough      
        │                 │                 │
        └─────────┬───────┴────────────────┘
                  │
                  ▼
         ┌────────────────────┐
         │ Code Topics Map:   │
         ├────────────────────┤
         │ Forge       (Att)  │
         │ Sentinel    (Det)  │
         │ Shield      (Rec)  │
         │ Dashboard   (Viz)  │
         │ Watcher     (Mon)  │
         └────────────────────┘
                  │
                  ▼
         Ready to explore!
```

### **Map of Each Component**

| Component | File | What It Does | Key Method |
|-----------|------|---|---|
| **FORGE** | `backend/services/forge_service.py` | Simulates attacks | `deploy_payload()` |
| **SENTINEL** | `backend/services/sentinel_service.py` | Detects threats | `record_detection_event()` |
| **SHIELD** | `backend/services/shield_service.py` | Responds/Recovers | `trigger_isolation()` |
| **DASHBOARD** | `dashboard/src/Dashboard.jsx` | Shows real-time UI | Fetches `/api/v1/dashboard/metrics` |
| **WATCHER** | `watchers/src/lib.rs` | Monitors files | Sends events to `/api/v1/sentinel/events` |

---

## 🌐 SECTION 3: TESTING API ENDPOINTS

```
START
  │
  ▼
┌────────────────────────────────────┐
│ Is backend server running?         │
│ (http://localhost:8000)            │
└────────┬────────────────┬──────────┘
         │                │
        YES              NO
         │                │
         │                ▼
         │          Terminal 1:
         │          cd backend
         │          uvicorn main:app --reload
         │                │
         │                ▼
         │          Server starts...
         │          Wait for message:
         │          "Uvicorn running on..."
         │                │
         └────────┬───────┘
                  │
                  ▼
         ┌────────────────────────┐
         │ What do you want to    │
         │ test?                  │
         └────┬──────┬────┬───────┘
              │      │    │
              ▼      ▼    ▼
           Forge  Sentinel Shield
              │      │    │
              ▼      ▼    ▼
         ┌───────────────────────────┐
         │ TERMINAL 2 (PowerShell):  │
         │ Invoke-WebRequest ...     │
         └───────────────────────────┘
              │      │    │
              ▼      ▼    ▼
           Payload Events Isolate
           Honeypot Threads Shield
```

### **API Testing Sequence** (Copy & Paste)

#### Step 1: Check Backend Health
```powershell
curl http://localhost:8000/
```

#### Step 2: Deploy Attack (Forge)
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

#### Step 3: Generate Honeypot Files  
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

#### Step 4: Record Threat Detection (Sentinel)
```powershell
$event = @{
    event_id = "evt-001"
    timestamp = (Get-Date -AsUTC).ToString("o")
    threat_type = "mass_modification"
    threat_level = "critical"
    affected_path = "/tmp/test"
    file_count = 523
    entropy_score = 0.89
    confidence = 0.95
    details = @{}
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/sentinel/events" `
  -Method POST `
  -ContentType "application/json" `
  -Body $event
```

#### Step 5: Isolate Resource (Shield)
```powershell
$isolation = @{
    resource_id = "WORKSTATION-001"
    action = "vlan_isolate"
    reason = "mass_modification_detected"
    preserve_logs = $true
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/v1/shield/isolate" `
  -Method POST `
  -ContentType "application/json" `
  -Body $isolation
```

#### Step 6: View Results
```powershell
# Get all events
curl http://localhost:8000/api/v1/sentinel/events?limit=10

# View API docs
# Browser: http://localhost:8000/docs
```

---

## 🐳 SECTION 4: DEPLOYMENT (DOCKER)

### 4.1: Full Stack with Docker

```
START
  │
  ▼
┌──────────────────────────────┐
│ Install Docker & Docker      │
│ Compose (if not already)     │
└─────────┬────────────────────┘
          │
          ▼
     (Have Docker?)
          │
   ┌──────┴──────┐
   │             │
  YES           NO
   │             │
   │             ▼
   │          Download:
   │          docker.com
   │             │
   │             ▼
   │          Install
   │             │
   │             ▼
   │          Restart
   │          Terminal
   │             │
   └──────┬──────┘
          │
          ▼
     ┌───────────────────────┐
     │ Run this in terminal: │
     ├───────────────────────┤
     │ docker-compose up -d  │
     └───────────┬───────────┘
                 │
                 ▼
          Services start:
          ├─ Backend (8000)
          ├─ Dashboard (3000)
          ├─ MinIO (9000)
          ├─ PostgreSQL (5432)
          └─ Kafka (9092)
                 │
                 ▼
          ┌────────────────────┐
          │ Verify running:    │
          │ docker ps          │
          └────────┬───────────┘
                   │
                   ▼
          All containers up?
                   │
         ┌─────────┴─────────┐
         │                   │
        YES                 NO
         │                   │
         │                   ▼
         │              docker logs <name>
         │              (Check errors)
         │                   │
         ▼                   ▼
    ┌──────────────┐   ┌──────────────┐
    │ Ready to use!│   │ Fix issues   │
    │              │   │              │
    │ Backend:     │   │ Then:        │
    │ :8000        │   │ restart      │
    │              │   │ services     │
    │ Dashboard:   │   │              │
    │ :3000        │   └──────┬───────┘
    │              │           │
    └──────────────┘           └───────┐
                                       │
                                       ▼
                                 Ready to use!
```

### **4.2: Docker Quick Commands**

```powershell
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart backend

# View running containers
docker ps

# Test backend in container
docker exec <container-id> pytest tests/
```

---

## 🎓 TESTING MINDSET

```
Question: "Is my code working?"
    │
    ▼
Choose test level:
    │
    ├─ Unit Test?        (Fast, isolated)
    ├─ Service Test?      (Medium, integrated)
    ├─ API Test?          (Slow, full stack)
    └─ E2E Test?          (Slowest, complete flow)
    │
    ▼
Select what to test:
    │
    ├─ Function result?   → Unit test
    ├─ Service logic?     → Service test
    ├─ API endpoint?      → API test
    └─ Full workflow?     → E2E test
    │
    ▼
Run test:
    │
    $ pytest <test>
    │
    ▼
    ┌─────────────┐
    │ PASS or     │
    │ FAIL?       │
    └──┬────┬─────┘
       │    │
      PASS FAIL
       │    │
       ▼    ▼
      ✅   ❌
       │   Fix code
       │   Re-run
       │    │
       └────┴─→ ✅ PASS
                │
                ▼
           Code is good!
```

---

## 🚦 TESTING CHECKLIST

Before committing code:

- [ ] Run unit tests: `pytest tests/test_services.py::Test<Component>`
- [ ] Run integration test: `pytest tests/test_services.py::TestIntegration`
- [ ] Check coverage: `pytest --cov=backend`
- [ ] Start backend: `uvicorn main:app --reload`
- [ ] Test API endpoints (manual or Postman)
- [ ] Check for linting errors: `flake8 backend/`
- [ ] All ✅ PASS?

If all pass → Ready to commit! 🚀

---

## 📍 QUICK NAVIGATION

📚 Documentation:
- [TEST_GUIDE.md](./TESTING_GUIDE.md) - Detailed testing strategies
- [CODE_FLOW_WALKTHROUGH.md](./CODE_FLOW_WALKTHROUGH.md) - Complete flow example
- [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) - Copy-paste commands
- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) - System design

🎯 Key Files:
- Tests: `tests/test_services.py`
- Services: `backend/services/*_service.py`
- Routes: `backend/routes/*_router.py`
- Dashboard: `dashboard/src/Dashboard.jsx`

---

## ✅ You're Ready!

Pick a section above and start testing! 🎉

**First time?** → Start with **SECTION 1: RUNNING TESTS**

Questions? Check the guides above or read the full TESTING_GUIDE.md!

