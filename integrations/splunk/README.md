# DRRA Splunk Integration

Full Splunk integration including a deployable Add-on, saved searches, and correlation rules.

## Components

| Path | Description |
|------|-------------|
| `drra_searches.spl` | 8 production-ready saved searches (copy/paste into Splunk) |
| `drra_addon/` | Deployable Splunk Add-on (TA-drra) |
| `drra_addon/default/inputs.conf` | Data collection: REST API poll + file monitor + Kafka |
| `drra_addon/default/transforms.conf` | Field extractions and lookups |
| `drra_addon/bin/drra_vigil_events.py` | Scripted input: polls DRRA VIGIL every 30s |

## Quick Start

### 1. Deploy the Add-on

```bash
# Copy to Splunk apps directory
cp -r drra_addon $SPLUNK_HOME/etc/apps/TA-drra

# Set DRRA connection (via Splunk Web: Apps → Manage → Set up TA-drra)
# Or set environment variables before Splunk starts:
export DRRA_API_URL=http://your-drra-host:8000
export DRRA_API_KEY=your-api-key

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### 2. Create the Index

```
Settings → Indexes → New Index
  Name: drra_events
  Max Size: 50 GB
```

### 3. Import Saved Searches

```
Settings → Searches, Reports and Alerts → New Report
```
Paste each search from `drra_searches.spl` and configure:

| Search | Schedule | Action |
|--------|----------|--------|
| Active Ransomware Encryption | Every 1m | Email + TheHive alert |
| Mass File Modification | Every 2m | Email + TheHive alert |
| VSS Deletion Events | Real-time | Immediate page + isolation |
| Lateral Movement | Every 5m | Email |
| Defensibility Index | Every 15m | Dashboard feed |
| MTTC SLA Compliance | Every 1h | Dashboard feed |
| Suricata Correlation | Every 10m | Email |

### 4. Configure Alert Actions

For isolation alerts (VSS Deletion, Active Encryption), configure a webhook action
pointing to DRRA SHIELD:

```
Alert Action: Webhook
URL: http://drra-backend:8000/api/v1/shield/isolate
Custom Headers: X-API-Key: your-api-key
Payload: {"target_ip": "$result.source_ip$", "reason": "Splunk alert: $name$", "source": "splunk"}
```

## Splunk Enterprise Security (ES)

If using Splunk ES, import the DRRA notable event mapping:

```conf
# $SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/default/correlationsearches.conf

[DRRA - Active Ransomware Encryption]
action.notable         = 1
action.notable._name   = DRRA - Active Ransomware Encryption
action.notable.param.drilldown_search = index=drra_events hostname=$hostname$ earliest=-15m
action.notable.param.security_domain  = endpoint
action.notable.param.severity         = critical
action.notable.param.rule_name        = DRRA - Active Ransomware Encryption
```

## Data Model

DRRA events follow this schema (sourcetype: `drra:vigil`):

```json
{
  "id":           "uuid",
  "event_type":   "entropy_spike | mass_modification | vss_deletion | lateral_movement",
  "timestamp":    "ISO8601",
  "hostname":     "host.domain.com",
  "source_ip":    "192.168.1.100",
  "severity":     "low | medium | high | critical",
  "confidence":   0.95,
  "incident_id":  "uuid",
  "metadata": {
    "entropy_score":    0.93,
    "files_modified":   847,
    "sha256":           "abc123...",
    "c2_domain":        "evil.example.com"
  },
  "llm_summary":  "Gemini-generated attack narrative",
  "mitre_techniques": ["T1486", "T1490"]
}
```
