# Resilience Forge (DRRA)
## Damn Resilient Ransomware App

**The industry standard for architecting, testing, and validating ransomware-proof ecosystems through automation and AI.**

## 🛡️ Three Pillars of Ransomware Defense

**Built on the WALL-SQUAT-GRAB framework:**

1. **WALL — PREVENT** 🔵 (Vigil)
   - AI-driven behavioral detection identifies threats before encryption
   - Entropy analysis detects encryption attempts
   - Mass modification patterns flagged in real-time
   - Lateral movement tracking blocks privilege escalation

2. **SQUAT — SURVIVE** 🟡 (Shield)
   - SOAR automation + rapid response limits blast radius
   - Micro-segmentation isolates compromised systems
   - Automated containment triggers within seconds
   - Network isolation prevents lateral spread

3. **GRAB — CONTROL** 🔴 (Recovery)
   - Immutable backups ensure recovery capability
   - Verified backup restoration validates data integrity
   - Automated failover to known-good state
   - Forensic preservation maintains compliance

## Vision

Resilience Forge is an open-source "Assume Breach" laboratory providing a controlled playground where engineers build:
- **Defensible perimeters** (SQUAT) - Automated isolation and micro-segmentation
- **Resilient cores** (WALL) - AI-driven detection and immutable logging
- **Recovery mechanisms** (GRAB) - Automated healing and forensic capabilities

## Core Components

### 1. **The Forge** (Simulation Engine - Testing Framework)
- **Purpose**: Safe, controlled testing of all three pillars without real threats
- **Honeypot Architect**: Generates realistic file structures to act as detection tripwires
- **Resilience Payloads**: Safe, non-propagating scripts mimicking encryption entropy
- **Identity Squatting Tests**: Validates lateral movement defenses
- **Use**: `POST /api/v1/forge/deploy` to simulate ransomware attacks

### 2. **Vigil** (Detection & Auditing - WALL/PREVENT)
- **Purpose**: Detect threats BEFORE they cause damage
- **Behavioral Intelligence**: ML-based mass modification pattern detection
- **Entropy Analysis**: Identifies encryption attempts (Shannon entropy >0.85)
- **Immutable Telemetry**: Write-once logging pipeline (Vector → MinIO)
- **LLM Insights**: Gemini 2.5 Flash integration for attack summarization
- **Use**: `GET /api/v1/vigil/events` to retrieve detections

### 3. **The Shield** (Response & Recovery - SQUAT/GRAB)
- **Purpose**: Contain threats rapidly and restore operations
- **Dynamic Micro-Segmentation**: Automated VLAN isolation via API (SQUAT)
- **Immutable Object Locking**: Storage-layer compliance mode activation (GRAB)
- **Automated Recovery**: Verified backup restoration to known-good state
- **Forensic Curation**: Preserve and analyze attack artifacts
- **Use**: `POST /api/v1/shield/isolate` for immediate containment

### 4. **The Dashboard** (Monitoring & Control)
- **MTTC Tracker**: Real-time Mean Time to Contain metrics
- **Defensibility Index**: Measures effectiveness of all three pillars (0-100)
- **Incident Timeline**: Visualizes attack progression and response
- **Configuration Studio**: Granular threshold management for each pillar

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
├── vigil/                # WALL (PREVENT) - ML detection & telemetry
├── forge/                # Simulation & payload testing framework
├── shield/               # SQUAT/GRAB (SURVIVE/CONTROL) - Response & recovery
├── dashboard/            # Frontend & monitoring UI (Defensibility Index)
├── watchers/             # Rust file monitoring (real-time event stream)
├── infra/                # Ansible & deployment configs
├── tests/                # CI/CD test suite (The Gauntlet)
├── docs/                 # Architecture & design docs
└── docker-compose.yml    # Container orchestration
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
