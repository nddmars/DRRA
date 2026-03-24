# DRRA TheHive Integration

Automated SOC case management — creates alerts and cases in TheHive for every DRRA detection.

## Setup

```bash
pip install thehive4py requests
export THEHIVE_URL=https://thehive.yourorg.com
export THEHIVE_API_KEY=your-api-key   # TheHive → Settings → API Key
```

## Key Operations

### Create alert from detection
```python
from thehive_connector import DRRATheHiveConnector

hive      = DRRATheHiveConnector()
detection = requests.get("http://localhost:8000/api/v1/vigil/events/abc123").json()
alert     = hive.create_alert_from_detection(detection)
```

### Create full case from confirmed incident (with 8 task templates)
```python
incident = requests.get("http://localhost:8000/api/v1/dashboard/incidents/xyz").json()
case     = hive.create_case_from_incident(incident)
```

## Case Task Templates

Automatically generated when a case is created:
1. Confirm Isolation
2. Collect Forensic Evidence (Velociraptor artifact reference)
3. Identify Ransomware Family
4. Determine Blast Radius
5. Notify Stakeholders (with regulatory timelines: GDPR 72h, HIPAA 60d, SEC 4d)
6. Execute Recovery
7. Post-Recovery Hardening
8. Lessons Learned & MISP Sharing
