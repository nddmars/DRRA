# DRRA Suricata Rules

Network intrusion detection rules for ransomware C2 communication and lateral movement.
Compatible with Suricata 6.0+ and Snort 3.

## Files

| File | Description |
|------|-------------|
| `ransomware_c2.rules` | C2 beaconing, Tor, Cobalt Strike, data exfiltration |
| `ransomware_lateral_movement.rules` | SMB exploitation, RDP brute force, Kerberoasting, WMI, NTLM relay |

## Deployment

### Suricata (recommended)

1. Copy rules to your Suricata rules directory:
   ```bash
   sudo cp *.rules /etc/suricata/rules/drra/
   ```

2. Add to `suricata.yaml`:
   ```yaml
   rule-files:
     - drra/*.rules
   ```

3. Reload rules without restart:
   ```bash
   sudo suricatasc -c reload-rules
   ```

### Snort 3

```bash
# Convert SID ranges (adjust sid: values if conflicting with local rules)
snort -c /etc/snort/snort.lua --rule-path /etc/snort/rules/drra/ --lua 'include "ransomware_c2.rules"'
```

### Integration with Kafka (DRRA event pipeline)

Configure Suricata `eve.json` output to publish to the DRRA Kafka topic:

```yaml
# suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: redis
      redis:
        server: localhost
        port: 6379
        mode: list
        key: suricata-events
```

Then use the DRRA Kafka consumer bridge:
```bash
python integrations/wazuh/suricata_kafka_bridge.py
```

### Integration with MISP

Alert SIDs in the 9001xxx-9002xxx range are linked to MISP event taxonomy.
The DRRA MISP connector (`integrations/misp/misp_connector.py`) automatically
enriches Suricata alerts with threat intelligence context.

## Tuning

| Variable | Description |
|----------|-------------|
| `$HOME_NET` | Define your internal network ranges |
| `$EXTERNAL_NET` | Everything outside HOME_NET |
| `detection_filter count` | Adjust thresholds to reduce false positives |

### Recommended HOME_NET

```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
```

## SID Allocation

| Range | Category |
|-------|----------|
| 9001000–9001099 | C2 communication |
| 9002000–9002099 | Lateral movement |
| 9003000–9003099 | (Reserved) Encryption activity |
| 9004000–9004099 | (Reserved) Exfiltration |

## MITRE ATT&CK Coverage

| Rule File | Techniques |
|-----------|-----------|
| `ransomware_c2.rules` | T1071, T1041, T1090, T1132, T1048 |
| `ransomware_lateral_movement.rules` | T1021, T1550, T1558, T1210, T1557, T1110 |
