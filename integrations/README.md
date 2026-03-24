# DRRA Industry Tool Integrations

Production-ready integrations connecting DRRA to the most widely deployed security tools in enterprise environments.

## Available Integrations

| Tool | Category | Key Capability |
|------|----------|----------------|
| [Splunk](splunk/) | SIEM | 8 saved searches, Add-on with checkpoint-based event ingestion |
| [CrowdStrike Falcon](crowdstrike/) | EDR/XDR | Network Containment, Custom IOA rules, Streaming API → VIGIL |
| [Tanium](tanium/) | Endpoint Management | Fleet-wide hunting, Quarantine, 6 custom PowerShell sensors |
| [Wazuh](wazuh/) | Open-source XDR | 15 detection rules, active response script → SHIELD |
| [MISP](misp/) | Threat Intelligence | IOC enrichment, incident publishing, community IOC feed |
| [TheHive](thehive/) | Case Management | Auto alert/case creation, 8-task IR template |
| [Velociraptor](velociraptor/) | DFIR | Forensic collection artifact, real-time hunting artifact |

## Detection Rule Sets

| Tool | Location | Coverage |
|------|----------|----------|
| [YARA](../drra-policies/yara/) | `drra-policies/yara/` | 12 rules: generic behaviors + 6 ransomware families |
| [Suricata](../drra-policies/suricata/) | `drra-policies/suricata/` | 20 rules: C2 communication + lateral movement |
| [Sigma](../drra-policies/sigma/) | `drra-policies/sigma/` | 8 rules: SIEM-agnostic (Splunk, ELK, ArcSight, QRadar) |

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DRRA PLATFORM                                │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │  FORGE   │    │  VIGIL   │    │  SHIELD  │    │  DASHBOARD   │  │
│  │ (Sim)    │    │(Detect)  │    │(Respond) │    │   (Metrics)  │  │
│  └──────────┘    └────┬─────┘    └────┬─────┘    └──────────────┘  │
└───────────────────────┼──────────────┼──────────────────────────────┘
                        │              │
          ┌─────────────┼──────────────┼──────────────────┐
          │             │              │                  │
    ┌─────▼──────┐ ┌────▼──────┐ ┌────▼──────┐  ┌────────▼───────┐
    │   Splunk   │ │   MISP    │ │CrowdStrike│  │   TheHive      │
    │  (SIEM)    │ │(Threat    │ │(EDR/XDR)  │  │(Case Mgmt)     │
    │  8 searches│ │  Intel)   │ │Containment│  │Auto IR cases   │
    └────────────┘ └───────────┘ └───────────┘  └────────────────┘
          │
    ┌─────▼──────┐ ┌───────────┐ ┌───────────┐
    │   Wazuh    │ │  Tanium   │ │Velociraptor│
    │(Open XDR)  │ │ (Fleet    │ │  (DFIR)   │
    │15 AR rules │ │  Mgmt)    │ │Forensics  │
    └────────────┘ └───────────┘ └───────────┘
```

## Shared IOC Bus

All integrations participate in the DRRA IOC bus:

```
DRRA VIGIL confirms IOC
  → pushes to MISP (community sharing)
  → pushes to CrowdStrike Falcon (fleet block)
  → pushes to Tanium Threat Response (fleet scan)
  → Splunk search detects matching events retroactively
```

## Environment Variables Summary

```bash
# DRRA
DRRA_API_URL=http://localhost:8000
DRRA_API_KEY=

# Splunk
SPLUNK_HOME=/opt/splunk
DRRA_API_URL=http://localhost:8000

# CrowdStrike
FALCON_CLIENT_ID=
FALCON_CLIENT_SECRET=
FALCON_BASE_URL=https://api.crowdstrike.com

# Tanium
TANIUM_URL=https://tanium.yourorg.com
TANIUM_API_TOKEN=

# Wazuh
# Set in /var/ossec/etc/ossec.conf or environment

# MISP
MISP_URL=https://misp.yourorg.com
MISP_KEY=
MISP_VERIFYCERT=true

# TheHive
THEHIVE_URL=https://thehive.yourorg.com
THEHIVE_API_KEY=
```

## Python Dependencies

```bash
pip install \
  crowdstrike-falconpy \   # CrowdStrike
  pymisp \                 # MISP
  thehive4py \             # TheHive
  requests                 # All connectors
```
