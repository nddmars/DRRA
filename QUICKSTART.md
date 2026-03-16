# Resilience Forge (DRRA) - Quick Start Guide

## 🎯 5-Minute Get Started

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Git
- 4GB RAM minimum

### Step 1: Clone & Setup
```bash
git clone https://github.com/resilience-forge/drra.git
cd resilience-forge
cp .env.example .env
```

### Step 2: Start Services
```bash
docker-compose up -d
```

Wait for services to be healthy (30-60 seconds):
```bash
docker-compose ps
```

All services should show "healthy" or "running".

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Start Backend API
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 5: Access Dashboard & APIs

| Service | URL |
|---------|-----|
| **API Docs** | http://localhost:8000/docs |
| **Dashboard** | http://localhost:3000 |
| **MinIO Console** | http://localhost:9001 |
| **Prometheus** | http://localhost:9090 |
| **Grafana** | http://localhost:3000 |
| **Kafka** | localhost:9092 |

**Default Credentials:**
- MinIO: `minioadmin` / `minioadmin`
- Grafana: `admin` / `admin`
- Postgres: `drra_admin` / `drra_secure_password`

---

## 🔬 Run Your First Simulation

### 1. Deploy a Honeypot
```bash
curl -X POST "http://localhost:8000/api/v1/forge/deploy" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "First Test Honeypot",
    "payload_type": "honeypot",
    "target_path": "C:\\test",
    "duration_seconds": 60
  }'
```

### 2. Generate Honeypot Files
```bash
curl -X POST "http://localhost:8000/api/v1/forge/honeypot/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "file_types": ["pdf", "docx", "xlsx"],
    "count": 50,
    "size_mb": 1.0
  }'
```

### 3. Simulate Detection
```bash
curl -X POST "http://localhost:8000/api/v1/sentinel/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "test_evt_001",
    "timestamp": "2024-02-19T10:00:00Z",
    "threat_type": "mass_modification",
    "threat_level": "high",
    "affected_path": "C:\\test",
    "file_count": 5000,
    "entropy_score": 0.87,
    "confidence": 0.94,
    "details": {}
  }'
```

### 4. Trigger Isolation
```bash
curl -X POST "http://localhost:8000/api/v1/shield/isolate" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "workstation_001",
    "action": "vlan_isolate",
    "reason": "test_simulation",
    "preserve_logs": true
  }'
```

### 5. Check Dashboard Summary
```bash
curl http://localhost:8000/api/v1/dashboard/summary | python -m json.tool
```

---

## 🧪 Run The Test Suite (The Gauntlet)

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/test_gauntlet.py -v

# Run specific test
pytest tests/test_gauntlet.py::TestForge::test_payload_deployment -v

# Run with coverage report
pytest tests/ --cov=.
```

**Critical Build Requirements** (must pass):
- ✅ Data loss < 0.1%
- ✅ MTTC < 60 seconds
- ✅ All logs immutable
- ✅ Detection confidence > 90%

---

## 📊 Understanding Your Dashboard

### Key Metrics

**Defensibility Index (0-100)**
- Your Score: **87** (A grade)
- Percentile: **76th** (top 25%)
- Components:
  - Detection: 92/100
  - Isolation: 85/100
  - Recovery: 88/100
  - Immutability: 79/100

**Incident Metrics**
- Active Incidents: **2**
- Total Files Affected: **125,000**
- Files Recovered: **124,750** (99.8%)
- Data Loss: **0.2%** ✓ (below 0.1% target)

**MTTC (Mean Time to Contain)**
- Current: **45.3 seconds** ✓ (beats 60s target)
- Last 24h: -2.5s improvement
- Containment Rate: **97.9%**

---

## 🛠️ Configuration Tuning

### View Current Config
```bash
curl http://localhost:8000/api/v1/dashboard/config
```

### Update Detection Sensitivity
```bash
curl -X PUT "http://localhost:8000/api/v1/dashboard/config/thresholds" \
  -H "Content-Type: application/json" \
  -d '{
    "mass_modification_threshold": 0.10,
    "entropy_threshold": 0.85,
    "sensitivity_level": "strict"
  }'
```

### Presets Available
- **strict**: Catch 5% file changes (high false positives)
- **balanced**: Catch 15% file changes (default)
- **permissive**: Catch 25% file changes (miss some attacks)

---

## 🔐 Immutable Log Verification

### Check Immutable Storage Status
```bash
docker exec -it $(docker ps -q -f "ancestor=minio/minio") \
  aws s3api get-object-lock-configuration \
  --bucket immutable-logs \
  --endpoint-url http://localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin
```

### List Archived Logs
```bash
docker exec -it $(docker ps -q -f "ancestor=minio/minio") \
  aws s3 ls s3://immutable-logs/ \
  --endpoint-url http://localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin
```

---

## 📚 Next Steps

1. **Read Architecture Guide**: [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
2. **Deploy to Kubernetes**: Follow [infra/kubernetes/](../infra/kubernetes/)
3. **Integrate with SOAR**: See [infra/shuffle/](../infra/shuffle/)
4. **Custom ML Models**: Add to [sentinel/models/](../sentinel/models/)
5. **Contribute**: See [docs/CONTRIBUTING.md](../docs/CONTRIBUTING.md)

---

## ❓ Troubleshooting

### Services not starting
```bash
# Check logs
docker-compose logs
docker-compose logs postgres  # Check specific service

# Restart services
docker-compose restart
```

### API connection refused
```bash
# Verify API is running
curl http://localhost:8000/health

# Check if port is in use
netstat -an | grep 8000  # macOS/Linux
netstat -ano | findstr 8000  # Windows
```

### Insufficient disk space
```bash
# Clean up volumes
docker-compose down -v
docker system prune -a

# Increase Docker disk allocation
# (Docker Desktop Settings → Resources → Disk Image Size)
```

### Dashboard not loading
```bash
# Check frontend service
docker-compose logs dashboard

# Rebuild containers
docker-compose up --build
```

---

## 📞 Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: security@resilience-forge.com
- **Chat**: Discord community

---

## 🚀 You're Ready!

Your Resilience Forge instance is now operational. Start building ransomware-proof architecture!

**Quick Commands:**
```bash
# View all incidents
curl http://localhost:8000/api/v1/dashboard/incidents

# Get latest detection events
curl http://localhost:8000/api/v1/sentinel/events

# View immutable telemetry
curl http://localhost:8000/api/v1/sentinel/telemetry

# Check system health
curl http://localhost:8000/health
```

For more options, see API docs at http://localhost:8000/docs

**Happy Hardening!** 🔥🛡️
