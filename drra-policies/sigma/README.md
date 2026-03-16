# Sigma Rules - Ransomware Detection

Vendor-agnostic behavioral detection rules for ransomware attacks. These rules detect the patterns that Sentinel ML engine identifies, but in a format portable to any SIEM (Splunk, ELK, Chronicle, etc.).

## Rule Categories

### 1. Mass File Modification Detection
- Threshold: >15% of files in 60 seconds (configurable)
- Detects: Encryption, bulk renaming, mass deletion
- Source: File watcher events, process behavior correlation

**Files**:
- `ransomware_mass_modification.yml` – Core detection rule

### 2. Entropy Analysis
- Threshold: Shannon entropy > 0.85 (configurable)
- Detects: Encrypted file extensions, random byte patterns
- Source: File magic headers, binary content analysis

**Files**:
- `ransomware_entropy_spike.yml` – Entropy detection rule
- `ransomware_suspicious_extensions.yml` – Known ransomware extensions

### 3. Lateral Movement Detection
- Detects: Kerberos abuse, credential reuse, domain enumeration
- Source: Authentication logs, process creation events
- Correlation: Multiple failed auth + privilege escalation

**Files**:
- `lateral_movement_kerberos_abuse.yml` – Domain auth anomalies
- `lateral_movement_privilege_escalation.yml` – UAC bypass, token theft

### 4. Volume Shadow Copy (VSS) Abuse
- Detects: `vssadmin delete`, `wmic shadowcopy`, PowerShell backup deletion
- Detects: Admin shares access, registry tampering
- Source: Process logs, command-line audit

**Files**:
- `ransomware_vss_abuse.yml` – Shadow copy deletion attempts
- `ransomware_admin_share_access.yml` – Lateral movement via shares

## Usage

### Deploy to Splunk
```bash
cp ransomware_*.yml /opt/splunk/etc/apps/search/local/
splunk restart
```

### Deploy to ELK
```bash
# Use sigma CLI to convert to Elasticsearch queries
sigma convert -t es-query ransomware_mass_modification.yml > queries/
kibana import queries/...
```

### Deploy to Chronicle
```bash
# Use Chronicle Sigma integration
gsutil cp ransomware_*.yml gs://your-chronicle-bucket/sigma/
```

## Testing Rules

```bash
pytest tests/compliance/test_sigma_rules.py
```

Each rule must:
- ✅ Trigger on simulated ransomware payloads (forge/)
- ✅ Correlate with Sentinel ML detections
- ✅ Not over-trigger on normal file operations
- ✅ Meet <60 second detection latency

## Contributing New Rules

1. Create rule YAML with metadata
2. Test against Forge payloads
3. Validate detection timing
4. Document false positive rates
5. Submit for review

---

**Example Rule Structure** (see `ransomware_mass_modification.yml` for full template)
