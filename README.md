# Resilience Forge (DRRA)
## Damn Resilient Ransomware App

**The industry standard for architecting, testing, and validating ransomware-proof ecosystems through automation and AI.**

## Documentation

Full documentation, architecture diagrams, API reference, and DevSecOps pipeline details are in [`docs/index.html`](docs/index.html). Open it in a browser — no server required.

## Three Pillars of Ransomware Defense

Built on the **WALL-SQUAT-GRAB** framework:

1. **WALL — PREVENT** (Vigil)
   - AI-driven behavioral detection identifies threats before encryption
   - Entropy analysis detects encryption attempts
   - Mass modification patterns flagged in real-time
   - Lateral movement tracking blocks privilege escalation

2. **SQUAT — SURVIVE** (Shield)
   - SOAR automation + rapid response limits blast radius
   - Micro-segmentation isolates compromised systems
   - Automated containment triggers within seconds
   - Network isolation prevents lateral spread

3. **GRAB — CONTROL** (Recovery)
   - Immutable backups ensure recovery capability
   - Verified backup restoration validates data integrity
   - Automated failover to known-good state
   - Forensic preservation maintains compliance

## Quick Start

```bash
git clone https://github.com/yourusername/resilience-forge.git
cd resilience-forge
docker-compose up -d
```

Then open `docs/index.html` for full setup instructions.

## Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| Backend API | http://localhost:8000 | FastAPI — all component routes |
| Swagger UI | http://localhost:8000/docs | Interactive API documentation |
| Dashboard | http://localhost:7700 | React frontend — Defensibility Index & MTTC |
| Grafana | http://localhost:7600 | Live metrics & alerting (admin/admin) |
| Prometheus | http://localhost:7500 | Metrics collection & time-series storage |
| MinIO Console | http://localhost:7001 | Immutable object storage (minioadmin/minioadmin) |
| Kafka | localhost:7300 | Event streaming for telemetry pipeline |
| PostgreSQL | localhost:7100 | Audit logs (drra_admin/drra_secure_password) |
| Redis | localhost:7200 | Session caching & rate limiting |

## Project Structure

```
drra/
├── backend/          # FastAPI application
├── dashboard/        # React frontend
├── watchers/         # Rust file system monitor
├── vigil/            # ML detection engine
├── drra-policies/    # Policy-as-Code (Sigma, OPA, Semgrep, Playbooks)
├── infra/            # Docker, Prometheus, Grafana, Kubernetes
├── tests/            # Python test suites + Postman collection
├── scripts/          # Demo and utility scripts
├── docs/             # HTML documentation site + architecture
├── docker-compose.yml
└── README.md
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python (FastAPI) |
| Monitoring | Rust-based file watchers |
| Automation | Ansible / Shuffle (SOAR) |
| Storage & Logs | MinIO (S3-compatible) with Object Lock |
| Detection ML | scikit-learn, TensorFlow |
| LLM Integration | Google Gemini 2.5 Flash |
| Message Queue | Apache Kafka |
| Frontend | React / TypeScript |

## License

MIT License — See LICENSE file for details.

## Contact & Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: [docs/index.html](docs/index.html)
