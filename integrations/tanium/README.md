# DRRA Tanium Integration

Fleet-wide endpoint visibility, ransomware hunting, and automated quarantine via Tanium.

## Components

| File | Description |
|------|-------------|
| `drra_tanium_connector.py` | Python API connector using Tanium REST API |
| `tanium_sensors.json` | 6 custom PowerShell sensors for ransomware detection |

## Setup

### 1. Generate API Token

```
Tanium Console → Administration → API Tokens → New Token
  Name: DRRA Integration
  Expiration: 365 days
  Permissions: Read (Questions, Packages, Endpoints), Write (Actions)
```

```bash
export TANIUM_URL=https://tanium.yourorg.com
export TANIUM_API_TOKEN=your-token-here
pip install requests
```

### 2. Import Custom Sensors

```
Tanium Console → Content → Import Content
Upload: tanium_sensors.json
```

Or via Tanium API:
```bash
python -c "
import json, requests, os
sensors = json.load(open('tanium_sensors.json'))
for s in sensors['sensors']:
    r = requests.post(
        os.environ['TANIUM_URL'] + '/api/v2/sensors',
        json=s,
        headers={'session': os.environ['TANIUM_API_TOKEN']}
    )
    print(s['name'], r.status_code)
"
```

### 3. Import DRRA Packages (for remediation actions)

```
Tanium Console → Content → Import Package
```
Required packages (create in Tanium Content):
- `DRRA - Kill Ransomware Processes`
- `DRRA - Re-enable VSS`
- `DRRA - Deploy VIGIL Agent`
- `Tanium Quarantine` (built-in, enable in Tanium Threat Response)

## Usage

### Fleet Ransomware Hunt

```python
from drra_tanium_connector import DRRATaniumConnector

tanium = DRRATaniumConnector()

# Run full hunt across all endpoints
results = tanium.run_ransomware_hunt()
print(f"Affected hosts: {results['total_affected']}")
print(results['affected_hosts'])

# Targeted hunt (faster)
results = tanium.run_ransomware_hunt(hunt_types=["entropy", "extensions", "notes"])
```

### Quarantine a Host

```python
# Isolate via Tanium Quarantine (blocks all traffic except Tanium server)
result = tanium.quarantine_host("workstation-42.corp.com", reason="DRRA SHIELD")

# DRRA SHIELD calls this automatically when isolating via the webhook
```

### Push IOCs Fleet-Wide

```python
import requests

# Pull confirmed IOCs from DRRA
iocs = requests.get("http://localhost:8000/api/v1/vigil/confirmed-iocs").json()

# Push to Tanium Threat Response for fleet scanning
tanium.push_iocs_to_threat_response(iocs)
# Tanium will now scan all endpoints for these IOCs
```

### Endpoint Risk Dashboard

```python
# Get risk-ranked endpoint list for DRRA Dashboard integration
risk_summary = tanium.get_endpoint_risk_summary()
for endpoint in risk_summary[:10]:  # Top 10 riskiest
    print(f"{endpoint['hostname']}: shadow_count={endpoint.get('shadow_count',0)}, "
          f"encrypted_files={endpoint.get('encrypted_file_count',0)}")
```

## Custom Sensors Overview

| Sensor | Question | Alert Threshold |
|--------|----------|-----------------|
| File Write Entropy | Files written in last 60s with entropy > 0.85 | Any result |
| Ransomware Extension Count | Files with .locked/.ryk/.hive etc. | Count > 0 |
| Shadow Copy Count | VSS shadow copies available | Count = 0 (CRITICAL) |
| Ransom Note Presence | HOW_TO_DECRYPT / README.TXT etc. | Any result |
| Suspicious Outbound Connections | TCP to non-standard external ports | Any result |
| Backup Service Status | VSS / wbengine / SDRSVC status | Status ≠ Running |

## Tanium Module Requirements

| Capability | Required Module |
|-----------|----------------|
| Live Questions | Tanium Core Platform |
| Host Quarantine | Tanium Threat Response |
| Package Deployment | Tanium Deploy |
| IOC Distribution | Tanium Threat Response |
| Compliance Audit | Tanium Comply |

## Integration Architecture

```
DRRA VIGIL detects entropy spike
    ↓
DRRA SHIELD triggers isolation
    ↓
Tanium Quarantine (network block) ← parallel with VLAN quarantine
    ↓
Tanium Threat Response pushes DRRA IOCs fleet-wide
    ↓
Tanium Hunt scans all endpoints for spread
    ↓
Findings forwarded to DRRA VIGIL for correlation
```
