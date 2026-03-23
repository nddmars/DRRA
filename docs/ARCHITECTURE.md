# Resilience Forge Architecture Guide

## 🛡️ Three Pillars of Defense Framework

Resilience Forge (DRRA) implements the **WALL-SQUAT-GRAB** framework:

- **WALL** 🔵 (PREVENT) - Vigil detects threats before encryption spreads
- **SQUAT** 🟡 (SURVIVE) - Shield contains and responds within seconds
- **GRAB** 🔴 (CONTROL) - Recovery restores from verified immutable backups

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    DASHBOARD (Control Center)           │
│  - Defensibility Index (0-100 higher is better)        │
│  - Real-time MTTC (Mean Time to Contain)               │
│  - Incident Timeline & Response Tracking               │
│  - Configuration Studio (Threshold management)          │
└────────────┬────────────────┬────────────────┬──────────┘
             │                │                │
    ┌────────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │   THE FORGE   │  │    VIGIL    │  │  THE SHIELD │
    │(Testing/Sim) │  │ (PREVENT)  │  │(SURVIVE/CTL)│
    ├───────────────┤  ├─────────────┤  ├─────────────┤
    │ • Honeypots  │  │ • ML Engine │  │ • Isolation │
    │ • Payloads   │  │ • Entropy   │  │ • Locking   │
    │ • Identity   │  │ • Behavior  │  │ • Recovery  │
    │   Squatting  │  │ • Telemetry │  │ • Forensics │
    └───────────────┘  └─────────────┘  └─────────────┘
             │                │                │
    ┌────────────────────────────────────────────────────┐
    │    WATCHER (Real-time File System Monitoring)      │
    │  - Rust-based file event detection                 │
    │  - Sub-millisecond latency                         │
    │  - Entropy spike detection                         │
    │  - Mass modification tracking                      │
    └────────────────────────────────────────────────────┘
             │                │                │
└────────────┴────────────────┴──────────────────────────┐
│         IMMUTABLE FOUNDATION (MinIO + PostgreSQL)      │
│  - WALL: Write-Once Object Storage (Compliance Mode)  │
│  - SQUAT: Micro-segmentation rules & isolation state  │
│  - GRAB: Verified backup catalogs & recovery plans    │
│  - Tamper-Proof Audit Logs (365-day retention)        │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### 1. The Forge (Testing Framework) - `forge/`

**Purpose**: Safe, controlled testing of all three pillars (WALL, SQUAT, GRAB) without real threats.
**Role**: Tests the Vigil detection, Shield containment, and Recovery capabilities

**Components**:
- **Honeypot Architect**: Generates realistic file structures
  - PDF documents, Excel spreadsheets, SQL dumps
  - File size: configurable (1-100 MB per file)
  - Modified timestamps to blend with real data
  
- **Resilience Payloads**: Safe encryption simulation
  - Entropy spike mimicking ransomware encryption
  - File modification patterns matching real threats
  - Non-destructive (reads files, doesn't encrypt)
  
- **Identity Squatting Tests**: Kerberos lateral movement simulation
  - Unauthorized ticket requests
  - Credential reuse patterns
  - Domain enumeration attempts

**API Endpoints**:
- `POST /api/v1/forge/deploy` - Deploy payload
- `POST /api/v1/forge/honeypot/generate` - Create honeypot files
- `POST /api/v1/forge/identity-squat/kerberos-test` - Test lateral movement

### 2. Vigil (Detection Engine - WALL/PREVENT) - `vigil/`

**Purpose**: Detect threats BEFORE they cause damage through AI-driven behavioral analysis.
**Pillar**: WALL (PREVENT) - Identifies threats before encryption spreads

**Components**:
- **Behavioral ML Engine** (`detector.py`)
  - Mass modification detection (>15% files in 60s) = CRITICAL
  - Entropy analysis (>0.85 indicates encryption) = CRITICAL  
  - Lateral movement tracking (process spawning chains) = HIGH
  - VSS (Volume Shadow Copy) abuse detection = CRITICAL
  
- **Immutable Telemetry Pipeline** (Write-once logging)
  - Vector/Fluentd → Kafka → MinIO
  - All events logged to write-once object storage (S3 compliance mode)
  - Object Lock prevents deletion during 365-day retention period
  - Tamper-proof for compliance (HIPAA, PCI-DSS, SOC2)
  
- **LLM Integration** (Google Gemini 2.5 Flash)
  - Plain-English attack summarization
  - Recommended hardening actions
  - Defensibility gap identification

**Detection Signatures**:
| Pattern | Threshold | Severity |
|---------|-----------|----------|
| Entropy Score | >0.85 | CRITICAL |
| Mass Modification | >15% in 60s | CRITICAL |
| Lateral Movement | 2+ suspicious processes | HIGH |
| VSS Abuse | vssadmin delete detected | CRITICAL |

**API Endpoints**:
- `GET /api/v1/vigil/events` - Retrieve detection events
- `POST /api/v1/vigil/behaviors/analyze` - Trigger analysis
- `GET /api/v1/vigil/telemetry` - Immutable log access
- `POST /api/v1/vigil/insights/generate` - LLM analysis

### 3. The Shield (Response & Recovery - SQUAT/GRAB) - `shield/`

**Purpose**: Rapidly contain threats AND restore operations from verified backups.
**Pillars**: 
  - SQUAT (SURVIVE) - Automated containment limits blast radius
  - GRAB (CONTROL) - Verified recovery restores known-good state

**Components**:
- **Dynamic Micro-Segmentation** (SQUAT)
  - Automated VLAN isolation via API (network quarantine)
  - Blocks lateral movement within 30 seconds
  - Rollback capability for false positives
  
- **Immutable Object Locking** (GRAB)
  - MinIO Compliance Mode activation
  - Legal hold on critical forensic buckets
  - Prevents even admin deletion (tamper-proof backups)
  
- **Recovery Orchestration** (GRAB)
  - Snapshot restoration from verified backups
  - Credential revocation automation
  - Block-level incremental restores (minimize downtime)
  - Parallel recovery threads (default: 8)
  
- **Forensic Curation** (GRAB)
  - Automatic evidence preservation (chain of custody)
  - Attack artifacts captured for post-incident analysis
  - 90-day default retention (configurable)

**Critical Metrics for SQUAT**:
- **MTTC (Mean Time to Contain)**: Target < 60 seconds
- **Isolation Effectiveness**: 100% (no lateral spread)
- **False Positive Rollback**: < 5 seconds

**Critical Metrics for GRAB**:
- **MTTR (Mean Time to Restore)**: Target < 15 minutes
- **Data Loss**: Target < 0.1%
- **Backup Verification**: 100% integrity checks
- **Recovery Completeness**: 99.99%+

**API Endpoints**:
- `POST /api/v1/shield/isolate` - Trigger isolation (SQUAT)
- `POST /api/v1/shield/object-lock/activate` - Enable backup locking (GRAB)
- `POST /api/v1/shield/recovery/create` - Start recovery (GRAB)
- `POST /api/v1/shield/forensics/preserve` - Archive evidence (GRAB)

### 4. The Dashboard (Control Center) - `dashboard/`

**Purpose**: Real-time monitoring, analysis, and configuration.

**Metrics**:
- **MTTC Tracker**: Detection → Isolation → Recovery timeline
- **Defensibility Index (DI)**: 0-100 score based on:
  - Detection effectiveness (30% weight)
  - Isolation success (30% weight)
  - Recovery completeness (20% weight)
  - Immutability confidence (20% weight)
  
- **Incident Severity**: Low/Medium/High/Critical
- **Data Integrity**: % files recovered, % data loss
- **System Health**: Component status dashboard

**Configuration Studio**:
- Mass modification threshold (default: 15%)
- Entropy threshold (default: 0.85)
- Auto-isolation trigger (true/false)
- Credential revocation (manual/auto)
- Recovery strategy selection

**API Endpoints**:
- `GET /api/v1/dashboard/summary` - Complete overview
- `GET /api/v1/dashboard/metrics/mttc` - MTTC details
- `GET /api/v1/dashboard/defensibility-index` - DI breakdown
- `PUT /api/v1/dashboard/config/thresholds` - Update settings

## Data Flow

### Threat Detection Flow
```
File System Events
    ↓
File Watcher (Rust) → [Entropy, Path, Process ID]
    ↓
Vigil ML Engine
    ├─→ Mass Modification Check
    ├─→ Entropy Analysis
    ├─→ Lateral Movement Detection
    └─→ VSS Abuse Detection
    ↓
Detection Event → MinIO (Immutable) + PostgreSQL
    ↓
Confidence > Threshold?
    └─→ YES: Trigger Shield
         ├─→ Isolate → VLAN quarantine
         ├─→ Lock → Object Lock activation
         └─→ Recover → Snapshot restore
    ↓
LLM Analysis → Plain-English summary
    ↓
Dashboard Update (Real-time via WebSocket)
```

### Recovery Flow
```
Incident Detected
    ↓
Isolation Active (< 2.5s)
    ↓
Evidence Preserved (Immutable)
    ↓
Recovery Task Created
    ├─→ Type: restore_snapshot / rebuild / incremental
    ├─→ Priority: 1-5 (queue management)
    └─→ Parallel execution (8 threads)
    ↓
Data Validation
    ├─→ Integrity check (MD5/SHA256)
    ├─→ Completeness verification
    └─→ Malware re-infection scan
    ↓
Restoration Complete
    ↓
Metrics Update
    ├─→ MTTC tracking
    ├─→ Data loss calculation
    └─→ Defensibility Index update
```

## Technology Stack Details

### Backend (`backend/`)
- **FastAPI**: Async web framework
- **SQLAlchemy**: ORM for PostgreSQL
- **Pydantic**: Data validation
- **Kafka**: Event streaming
- **MinIO**: S3-compatible storage
- **Redis**: Caching & sessions

### Vigil (`vigil/`)
- **scikit-learn**: ML classification
- **NumPy/Pandas**: Data processing
- **TensorFlow**: Deep learning (optional)
- **Vector/Fluentd**: Log aggregation
- **Google Generative AI**: Gemini integration

### File Watchers (`watchers/`)
- **Rust**: Performance-critical file monitoring
- **tokio**: Async runtime
- **watchdog**: File system events
- **rayon**: Parallel processing

### Infrastructure (`infra/`)
- **Docker Compose**: Local orchestration
- **Kubernetes**: Production deployment
- **Ansible**: Configuration management
- **Prometheus**: Metrics collection
- **Grafana**: Visualization

## Security Architecture

### Defense-in-Depth Layers

1. **Detection Layer**
   - ML-based behavioral analysis
   - Entropy monitoring
   - Process correlation
   - Network activity analysis

2. **Prevention Layer**
   - File integrity monitoring (FIM)
   - Application whitelisting
   - Privilege escalation prevention
   - Lateral movement blocking

3. **Isolation Layer**
   - VLAN micro-segmentation
   - Network quarantine
   - Process killing
   - File access revocation

4. **Recovery Layer**
   - Immutable snapshot restoration
   - Incremental block recovery
   - Credential management
   - System rebuild capability

5. **Immutability Layer**
   - Write-once object storage
   - Object Lock on critical data
   - Legal hold capability
   - Tamper-proof audit logs

### Immutability Guarantees

```
Ransomware Attack Timeline:
│
├─ T+0: Malware execution detected
├─ T+2.1s: Isolation activated (network/VLAN quarantine)
├─ T+42.3s: Containment achieved (MTTC)
│
├─ Attacker attempts: Delete logs? ✗ (Object Lock)
├─ Attacker attempts: Corrupt recovery? ✗ (Immutable)
├─ Attacker attempts: Tamper with audit trail? ✗ (Write-once)
│
└─ T+45m: Full recovery completed, zero data loss
```

## Testing Strategy (The Gauntlet)

### Stage 1: Detonate
```bash
pytest tests/test_gauntlet.py::TestGauntletScenarios::test_complete_ransomware_scenario
```
- Deploy simulated payload
- Verify detection triggered
- Measure detection latency

### Stage 2: Validate
```bash
pytest tests/test_gauntlet.py -v
```
- **Data Loss Requirement**: < 0.1%
- **MTTC Requirement**: < 60 seconds
- **Immutability**: 100% (logs untouched)
- **Recovery Success**: > 99.9%

CI/CD Build Failure Triggers:
```
IF data_loss > 0.1% THEN FAIL
IF mttc > 60s THEN FAIL
IF logs_tampered THEN FAIL
```

## Configuration Examples

### High-Security Profile
```yaml
detection:
  mass_modification_threshold: 0.05  # 5% (more sensitive)
  entropy_threshold: 0.80
  
isolation:
  auto_isolate: true
  isolation_timeout: 1s
  
recovery:
  auto_start: false  # Manual approval required
  parallel_threads: 16
  
logs:
  retention_days: 365
  legal_hold: true
```

### Balanced Profile (Default)
```yaml
detection:
  mass_modification_threshold: 0.15  # 15%
  entropy_threshold: 0.85
  
isolation:
  auto_isolate: true
  isolation_timeout: 2.5s
  
recovery:
  auto_start: false
  parallel_threads: 8
  
logs:
  retention_days: 90
  legal_hold: false
```

### Performance Profile
```yaml
detection:
  mass_modification_threshold: 0.25  # 25% (less sensitive)
  entropy_threshold: 0.90
  
isolation:
  auto_isolate: false  # Manual trigger
  
recovery:
  auto_start: false
  parallel_threads: 4
```

## Community & Support

- **Documentation**: https://docs.resilience-forge.com
- **GitHub**: https://github.com/resilience-forge/drra
- **Discord**: https://discord.gg/resilience-forge
- **Security Issues**: security@resilience-forge.com
- **Architecture Board**: https://github.com/resilience-forge/drra/discussions

---

**Resilience Forge: Building infrastructure that survives the unthinkable.** 🔥🛡️
