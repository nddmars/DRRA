# Resilience Forge Development Guide

## Framework Overview: WALL-SQUAT-GRAB

Resilience Forge (DRRA) is built on three pillars of ransomware defense:

- **WALL 🔵 (PREVENT)**: Vigil detection engine - Identify threats before encryption spreads
- **SQUAT 🟡 (SURVIVE)**: Shield containment - Rapid automated isolation and network quarantine
- **GRAB 🔴 (CONTROL)**: Shield recovery - Verified backup restoration with data integrity
- **FORGE**: Testing framework - Safe simulation of all threat scenarios

**Key Metric**: **Defensibility Index** (0-100, higher is better) combines all three pillars

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Rust 1.70+ (for watchers)
- Node.js 18+ (for dashboard)
- Git

### 1. Backend Setup

```bash
# Clone the repository
git clone <repo-url>
cd ransomwaredefense

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio pytest-cov flake8

# Run tests
pytest tests/ -v

# Start backend server
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at: `http://localhost:8000`
Swagger UI: `http://localhost:8000/docs`

### 2. Dashboard Setup

```bash
cd dashboard
npm install
npm start
```

Dashboard will be available at: `http://localhost:3000`

### 3. File Watcher Setup (Rust)

```bash
cd watchers

# Check code formatting
cargo fmt

# Run linter
cargo clippy

# Build
cargo build --release

# Run
./target/release/watcher
```

### 4. Docker Composition

```bash
# Start all services with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Project Structure

```
ransomwaredefense/
├── backend/                    # FastAPI server
│   ├── main.py                # App entry point
│   ├── routes/                # API endpoints
│   ├── services/              # Business logic (Forge, Vigil, Shield)
│   ├── models/                # Database & Pydantic models
│   └── db/                    # Database configuration
├── vigil/                     # ML detection module (behavioral analysis)
├── forge/                     # Simulation engine (stub)
├── shield/                    # Recovery engine (stub)
├── dashboard/                 # React frontend
├── watchers/                  # Rust file monitoring
├── tests/                     # Test suite
├── infra/                     # Infrastructure configs
└── drra-policies/             # Security policies (OPA, Semgrep, etc.)
```

## API Endpoints

### Health Check
```bash
GET /
GET /health
```

### Forge (Simulation)
```bash
# Deploy payload
POST /api/v1/forge/deploy
{
  "name": "test_payload",
  "payload_type": "honeypot",
  "target_path": "/tmp/test",
  "duration_seconds": 60,
  "intensity": 1.0
}

# Get payload status
GET /api/v1/forge/payloads/{payload_id}

# Generate honeypot
POST /api/v1/forge/honeypot/generate
{
  "file_types": ["pdf", "xlsx"],
  "count": 50,
  "size_mb": 1.0
}

# Start Kerberos test
POST /api/v1/forge/identity-squat/kerberos-test
```

### Vigil (Detection - WALL/PREVENT)
```bash
# Get detection events
GET /api/v1/vigil/events?limit=100&threat_level=high

# Record event
POST /api/v1/vigil/events
{
  "event_id": "evt-123",
  "threat_type": "mass_modification",
  "threat_level": "critical",
  "affected_path": "/home/user",
  "file_count": 5000,
  "entropy_score": 0.87,
  "confidence": 0.94,
  "details": {}
}

# Analyze behavior
POST /api/v1/vigil/behaviors/analyze
?path=/tmp&process_id=1234&duration_seconds=60

# Get LLM insights
POST /api/v1/vigil/insights/generate
?event_id={event_id}
```

### Shield (Recovery)
```bash
# Isolate resource
POST /api/v1/shield/isolate
{
  "resource_id": "workstation_001",
  "action": "vlan_isolate",
  "reason": "suspicious_activity",
  "preserve_logs": true
}

# Activate object lock
POST /api/v1/shield/object-lock/activate
{
  "bucket_name": "backup-bucket",
  "retention_days": 365,
  "legal_hold": true
}

# Create recovery task
POST /api/v1/shield/recovery/create
?recovery_type=restore_snapshot&priority=1
```

### Dashboard
```bash
# Get metrics
GET /api/v1/dashboard/metrics

# Get defensibility index
GET /api/v1/dashboard/defensibility-index

# Get incident metrics
GET /api/v1/dashboard/incident-metrics
```

## Testing

### Run All Tests
```bash
# Python backend
pytest tests/ -v --cov=backend

# Rust watcher
cd watchers && cargo test

# React dashboard (if configured)
cd dashboard && npm test
```

### Run Specific Tests
```bash
# Test only Vigil
pytest tests/test_services.py::TestVigilService -v

# Test with coverage
pytest tests/ --cov=backend --cov-report=html
```

## Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes and test**
   ```bash
   pytest tests/ -v
   cd watchers && cargo test
   ```

3. **Format and lint code**
   ```bash
   # Python
   black backend/
   flake8 backend/
   
   # Rust
   cd watchers && cargo fmt && cargo clippy
   ```

4. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: description of your changes"
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request**
   - GitHub Actions will run CI/CD checks
   - Address any review comments
   - Merge when approved

## Common Tasks

### Add a New API Endpoint

1. **Define the schema** in `backend/models/schemas.py`
2. **Create the route** in `backend/routes/<component>_router.py`
3. **Implement logic** in `backend/services/<component>_service.py`
4. **Add tests** in `tests/test_services.py`
5. **Update documentation** in this guide

### Add a New Test

```python
@pytest.mark.asyncio
async def test_my_feature():
    """Test description."""
    service = MyService()
    result = await service.my_method()
    assert result is not None
```

### Debug Backend

```bash
# Start with verbose logging
python -m uvicorn main:app --log-level debug --reload

# View logs in Docker
docker-compose logs -f backend
```

### Profile Performance

```bash
# Python profiling
python -m cProfile -s cumulative backend/main.py

# Rust benchmarking
cd watchers && cargo bench
```

## Security Considerations

- ✅ Never commit `.env` files with secrets
- ✅ Use environment variables for configuration
- ✅ Keep dependencies updated: `pip install --upgrade -r requirements.txt`
- ✅ Run security scans: The CI/CD pipeline runs Trivy
- ✅ Review OPA policies in `drra-policies/opa/`
- ✅ Validate all inputs before processing

## Troubleshooting

### Backend won't start
```bash
# Check port availability
lsof -i :8000

# Ensure dependencies installed
pip install -r requirements.txt

# Check for syntax errors
python -m py_compile backend/main.py
```

### Watcher not detecting files
```bash
# Verify watch paths exist
ls -la /tmp/honeypot /home /var/lib

# Check watcher logs
journalctl -u resilience-watcher -f
```

### Dashboard connection error
Check backend is running:
```bash
curl http://localhost:8000/
```

## Contributing

1. Follow PEP 8 for Python code
2. Follow Rust conventions (cargo fmt, cargo clippy)
3. Write tests for new features
4. Update documentation
5. Keep commits atomic and well-described

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Tokio Async Rust](https://tokio.rs/)
- [React Docs](https://react.dev/)
- [OPA Documentation](https://www.openpolicyagent.org/)
- [Resilience Forge Architecture](./docs/ARCHITECTURE.md)

## Support

For issues or questions:
1. Check existing GitHub issues
2. Review architecture docs
3. Create a new issue with detailed description

---

**Last updated:** 2024-02-19
**Maintainers:** Security Engineering Team
