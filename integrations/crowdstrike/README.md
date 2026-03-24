# DRRA CrowdStrike Falcon Integration

Bidirectional integration between DRRA and CrowdStrike Falcon.

## Components

| File | Description |
|------|-------------|
| `drra_crowdstrike_connector.py` | Python SDK connector (FalconPy-based) |
| `custom_ioa_rules.json` | Custom IOA rule groups for ransomware behaviors |

## Setup

### 1. Create Falcon API Client

In the Falcon Console → Support → API Clients and Keys → Add new API client:

| Permission | Access |
|------------|--------|
| Detections | Read |
| Hosts | Read + Write |
| Real Time Response | Read + Write |
| Real Time Response Admin | Read + Write |
| IOC Management | Read + Write |
| Event Streams | Read |

```bash
export FALCON_CLIENT_ID=your_client_id
export FALCON_CLIENT_SECRET=your_client_secret
pip install crowdstrike-falconpy
```

### 2. Import Custom IOA Rules

```bash
# Via CrowdStrike Falcon Console:
# Endpoint Security → Prevention Policies → Custom IOA → Import
# Upload: custom_ioa_rules.json
```

### 3. Configure DRRA SHIELD Webhook

Add to your `.env`:
```
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
CROWDSTRIKE_WEBHOOK_ENABLED=true
```

This triggers CrowdStrike Network Containment in parallel with DRRA VLAN isolation.

## Key Capabilities

### Dual Isolation Path
When DRRA SHIELD isolates a host:
1. **DRRA**: VLAN quarantine via network switch API (<3s)
2. **CrowdStrike**: Network Containment via Falcon agent (parallel, <5s)

This ensures the host is blocked at both network infrastructure AND agent levels.

### Real-Time Stream → VIGIL
```python
from drra_crowdstrike_connector import DRRACrowdStrikeConnector

connector = DRRACrowdStrikeConnector()
# Runs continuously, forwards Falcon detections to DRRA VIGIL
connector.stream_detections_to_drra()
```

### IOC Sync
```python
# Pull confirmed IOCs from DRRA incidents and push to Falcon
iocs = requests.get("http://localhost:8000/api/v1/vigil/confirmed-iocs").json()
connector.push_iocs_from_drra(iocs)
```

### RTR Forensics
```python
# Run forensic commands on isolated host via RTR
device_id = connector.get_device_id_by_ip("192.168.1.100")
results   = connector.run_forensic_commands(device_id)
```

## Custom IOA Coverage

| Rule Group | Rules | MITRE Techniques |
|------------|-------|-----------------|
| Ransomware Pre-Staging | vssadmin, wmic shadowcopy, bcdedit, wbadmin | T1490 |
| Credential Theft | LSASS access, Mimikatz patterns | T1003, T1003.001 |
| Lateral Movement | PsExec, remote service install | T1021.002 |
