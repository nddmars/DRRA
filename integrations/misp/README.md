# DRRA MISP Integration

Bidirectional threat intelligence sharing with MISP (Malware Information Sharing Platform).

## Setup

```bash
pip install pymisp requests
export MISP_URL=https://misp.yourorg.com
export MISP_KEY=your-automation-key   # MISP → Event Actions → Automation
```

## Key Operations

### Enrich a detection event with MISP context
```python
from misp_connector import DRRAMISPConnector

misp = DRRAMISPConnector()
detection = requests.get("http://localhost:8000/api/v1/vigil/events/abc123").json()
enriched  = misp.enrich_detection_event(detection)
print(enriched["misp_enrichment"]["threat_actors"])
print(enriched["misp_enrichment"]["risk_score"])
```

### Publish a confirmed incident to MISP
```python
incident = requests.get("http://localhost:8000/api/v1/dashboard/incidents/xyz").json()
misp.publish_incident(incident, publish=False)  # publish=True to share with community
```

### Sync MISP IOC feed to DRRA blocklist (run as cron)
```bash
# Every 30 minutes
*/30 * * * * python /opt/drra/integrations/misp/misp_connector.py
```
