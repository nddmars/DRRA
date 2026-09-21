# DRRA — Distributed Ransomware Response Architecture

> Ransomware resilience you can prove: detect, contain and recover — with evidence.

DRRA is an open-source reference implementation of WSG (WALL–SQUAT–GRAB), a closed-loop
ransomware resilience framework in which detection, containment and recovery feed each other.

## Background

The WSG framework was presented at RSA Conference 2026 (session IMT-T09, "Beyond Prevention:
Architecting Cyber-Resilient Defense Against Ransomware"). DRRA implements its three pillars —
WALL (behavioural detection), SQUAT (automated containment) and GRAB (immutable, validated
recovery) — and its Defensibility Index. A research paper describing the framework is in preparation.

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
git clone https://github.com/nddmars/DRRA.git
cd DRRA
docker-compose up -d
```

Then open `docs/index.html` for full setup instructions.

## Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| Backend API | http://localhost:8000 | FastAPI — all component routes |
| Swagger UI | http://localhost:8000/docs | Interactive API documentation |
| Dashboard | http://localhost:7700 | **Business/SOC view** — Defensibility Index, MTTC, incident cards (CISOs & analysts) |
| Grafana | http://localhost:7600 | **Engineering/Ops view** — Raw metrics, Kafka throughput, container health (admin/admin) |
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

## Defensibility Index & Reproducible Metrics

The **Defensibility Index (DI)** is implemented once, canonically, in
[`backend/services/defensibility.py`](backend/services/defensibility.py) as the
weighted harmonic mean of four measured components — detection efficiency
(MTTD), containment efficiency (MTTC), prevention (`1 − APCR`), and recovery
fidelity. The dashboard endpoints compute the DI, MTTC, FPR and APCR from
**recorded incident measurements** (`services/metrics_store.py`), not from
hard-coded values. With no incidents recorded the API returns honest zeros.

**Real behavioural detection (two-stage ensemble).** VIGIL uses a
scikit-learn `IsolationForest` anomaly gate (`vigil/ml_model.py`,
`contamination=0.02`, `n_estimators=200`) followed by a **supervised secondary
classifier** that confirms ransomware behaviour (paper Algorithm 1, step 5). A
CRITICAL alert fires only when **both stages agree**, suppressing false
positives on legitimate high-volume file operations. The secondary uses
TensorFlow/Keras when available and falls back to a scikit-learn MLP, then a
logistic heuristic. Exposed at `POST /api/v1/vigil/score`, which returns the
stage-1 anomaly score, the stage-2 confirmation, and MITRE ATT&CK mappings.

**Reproduce the simulation results** end-to-end:

```bash
python scripts/run_experiment.py --reps 10 --out results/experiment.json
```

Runs the multi-stage adversarial scenarios used to evaluate the Defensibility Index
and writes the results to results/experiment.json.

## Testing

```bash
pip install -r requirements.txt
pytest tests/                 # Python: DI engine, ML model, services, API gauntlet
cd watchers && cargo test     # Rust file-system watcher
```

Tests that need the live stack (PostgreSQL/Kafka/MinIO) skip automatically when
those services are not reachable; the core logic is fully covered offline.

## License

MIT License — See LICENSE file for details.

## Author

Suryaprakash Nalluri — design and implementation.

## Disclaimer

DRRA is a personal research and education project. It is not affiliated with, sponsored by or
endorsed by the author's current or former employers, and it contains no employer code, data or
confidential information. It is provided for research and evaluation; review and harden it before
any production use. Third-party tools named in this repository (for example Kafka, MinIO, Shuffle,
Ansible and Google Gemini) are examples of interchangeable components, not endorsements.

## Contact & Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: [docs/index.html](docs/index.html)
