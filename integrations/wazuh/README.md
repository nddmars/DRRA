# DRRA Wazuh Integration

Open-source XDR/SIEM integration with automatic active response.

## Components

| File | Description |
|------|-------------|
| `custom_ransomware_rules.xml` | 15 Wazuh detection rules (IDs 200000–200091) |
| `active_response.sh` | Shell script: auto-calls DRRA SHIELD when rules fire |
| `ossec_conf_snippet.xml` | Config snippets for syslog, FIM, active response, log analysis |

## Quick Setup

```bash
# 1. Copy rules
sudo cp custom_ransomware_rules.xml /var/ossec/etc/rules/drra_ransomware_rules.xml

# 2. Copy active response script
sudo cp active_response.sh /var/ossec/active-response/bin/drra_isolate.sh
sudo chmod 750 /var/ossec/active-response/bin/drra_isolate.sh
sudo chown root:wazuh /var/ossec/active-response/bin/drra_isolate.sh

# 3. Add relevant sections from ossec_conf_snippet.xml to /var/ossec/etc/ossec.conf

# 4. Set environment variables
echo "DRRA_API_URL=http://localhost:8000" >> /var/ossec/etc/ossec.conf
echo "DRRA_API_KEY=your-key" >> /var/ossec/etc/ossec.conf

# 5. Restart Wazuh
sudo systemctl restart wazuh-manager
```

## Rule Coverage

| Rule ID | Level | Trigger |
|---------|-------|---------|
| 200001 | 12 | Entropy spike from DRRA VIGIL |
| 200002 | 14 | Mass file modification |
| 200003 | 15 | VSS deletion (critical) |
| 200004 | 13 | Lateral movement |
| 200020 | 14 | vssadmin/wmic delete command (Windows 4688) |
| 200021 | 12 | Ransom note file created (FIM) |
| 200022 | 12 | Known ransomware extension (FIM) |
| 200030 | 13 | LSASS memory access (Sysmon 10) |
| 200031 | 11 | PowerShell encoded command |
| 200090 | 15 | **Correlation**: entropy + ransom note = active encryption |
| 200091 | 15 | **Correlation**: lateral movement + mass modification = propagation |

## Active Response Behavior

| Rule Level | Action |
|------------|--------|
| ≥ 15 (critical) | DRRA SHIELD isolation (VLAN quarantine) |
| 12–14 (high) | DRRA SHIELD isolation |
| 11 (medium) | DRRA VIGIL enrichment event only |

If DRRA API is unreachable: falls back to local `iptables DROP` rules.
