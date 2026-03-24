# DRRA YARA Rules

Industry-standard YARA rules for ransomware detection, compatible with any YARA-enabled tool.

## Files

| File | Description |
|------|-------------|
| `ransomware_generic.yar` | Behavioral indicators: crypto APIs, VSS deletion, bulk rename, credential harvesting, anti-forensics |
| `ransomware_families.yar` | Family-specific signatures: Ryuk, LockBit 3.0, Conti, BlackCat/ALPHV, Hive, Royal |

## Compatible Tools

| Tool | Usage |
|------|-------|
| **Velociraptor** | Use with `Windows.Detection.Yara.Drive` or embed in custom artifacts |
| **ClamAV** | `clamscan --yara=ransomware_generic.yar /path/to/scan` |
| **CrowdStrike** | Import via Custom IOA / Custom YARA (Falcon Horizon) |
| **Carbon Black** | Upload rules via CB Response YARA connector |
| **Wazuh** | Reference in `ossec.conf` with `<yara_rules>` module |
| **VirusTotal** | Retrohunt and livehunt via VT Intelligence API |
| **CAPE Sandbox** | Drop into `/opt/CAPEv2/data/yara/` |
| **Any.run** | Upload as custom YARA signature set |

## Quick Test

```bash
# Install YARA
sudo apt install yara

# Test against a directory
yara -r ransomware_generic.yar /suspicious/files/

# Test with verbose output
yara -r -s ransomware_families.yar /sample.exe

# Combine all rules
yara -r *.yar /mnt/infected_share/
```

## Integration with DRRA VIGIL

DRRA's VIGIL engine triggers YARA scans automatically when entropy spikes above the
configured threshold (`ENTROPY_THRESHOLD=0.85`). Results are ingested as detection events
and stored in PostgreSQL with immutable telemetry in MinIO.

To manually trigger a YARA scan via the DRRA API:

```bash
curl -X POST http://localhost:8000/api/v1/vigil/behaviors/analyze \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "yara", "target_path": "/mnt/share", "ruleset": "all"}'
```

## MITRE ATT&CK Coverage

| Rule | Technique |
|------|-----------|
| `DRRA_VSS_Deletion` | T1490 – Inhibit System Recovery |
| `DRRA_CryptoAPI_Ransomware` | T1486 – Data Encrypted for Impact |
| `DRRA_CredentialHarvest` | T1003 – OS Credential Dumping |
| `DRRA_NetworkEnum_Ransomware` | T1018 – Remote System Discovery |
| `DRRA_AntiForensics` | T1070 – Indicator Removal |
| `DRRA_BulkRename_Behavior` | T1486 – Data Encrypted for Impact |

## Updating Rules

Rules should be reviewed monthly against:
- [MalwareBazaar](https://bazaar.abuse.ch/) new submissions
- [VirusTotal](https://www.virustotal.com/) retrohunt results
- DRRA threat intelligence feed (MISP integration in `integrations/misp/`)
