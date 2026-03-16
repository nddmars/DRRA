# Resilience Forge (DRRA)
## Damn Resilient Ransomware App

**The industry standard for architecting, testing, and validating ransomware-proof ecosystems through automation and AI.**

## Vision

Resilience Forge is an open-source "Assume Breach" laboratory providing a controlled playground where engineers build:
- **Defensible perimeters** - Automated isolation and micro-segmentation
- **Resilient cores** - AI-driven detection and immutable logging
- **Recovery mechanisms** - Automated healing and forensic capabilities

## Core Components

### 1. **The Forge** (Simulation Engine)
- Honeypot Architect: Generates realistic file structures to act as detection tripwires
- Resilience Payloads: Safe, non-propagating scripts mimicking encryption entropy
- Identity Squatting Tests: Validates lateral movement defenses

### 2. **The Sentinel** (Detection & Auditing)
- Behavioral Intelligence: ML-based mass modification pattern detection
- Immutable Telemetry: Write-once logging pipeline (Vector → MinIO)
- LLM Insights: Gemini 2.5 Flash integration for attack summarization

### 3. **The Shield** (Recovery & Isolation)
- Dynamic Micro-Segmentation: Automated VLAN isolation via API
- Immutable Object Locking: Storage-layer compliance mode activation
- Forensic Curation: Preserve and analyze attack artifacts

### 4. **The Dashboard** (Monitoring & Control)
- MTTC Tracker: Real-time Mean Time to Contain metrics
- Defensibility Index: Score-based hardening benchmarking
- Configuration Studio: Granular threshold management

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

## Project Structure

```
ransomwaredefense/
├── backend/              # FastAPI core services
├── sentinel/             # ML detection & telemetry
├── forge/               # Simulation & payload testing
├── shield/              # Recovery & isolation
├── dashboard/           # Frontend & monitoring UI
├── watchers/            # Rust file monitoring
├── infra/               # Ansible & deployment configs
├── tests/               # CI/CD test suite (The Gauntlet)
├── docs/                # Architecture & design docs
└── docker-compose.yml   # Container orchestration
```

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Rust 1.70+ (for watchers)
- Node.js 18+ (for dashboard)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/resilience-forge.git
cd resilience-forge
```

2. **Start the infrastructure**
```bash
docker-compose up -d
```

3. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the backend**
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

5. **Access the dashboard**
```
http://localhost:3000
```

## The Defensibility Index (DI)

Rather than focusing on vulnerabilities, Resilience Forge introduces a **Defensibility Index** that measures:
- Number of defensive layers successfully blocking attacks
- Response time effectiveness (MTTC)
- Data integrity preservation during incidents
- Community benchmark comparisons

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for development guidelines.

## License

MIT License - See LICENSE file for details.

## Contact & Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: [docs/](docs/)
