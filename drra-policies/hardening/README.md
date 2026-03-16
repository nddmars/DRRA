# Post-Incident Hardening

Automated remediation rules executed after incident recovery. Prevents re-infection, blocks attack vectors, and hardens the system against similar attacks.

## Hardening Categories

### 1. Lateral Movement Prevention
Disable techniques used for domain compromise.

**Rules**:
- `lateral_movement_kerberos_hardening.rego` – Enforce strict Kerberos authentication
- `lateral_movement_network_segmentation.rego` – OPA policies enforce VLAN boundaries
- `lateral_movement_credential_filtering.rego` – Block admin credential caching

**Actions**:
```bash
# Enforce Kerberos hardening
gpupdate /force /target:computer  # Apply GPO: Kerberos strict mode

# Block unconstrained delegation
Get-ADUser -Filter * | foreach { 
  Set-ADAccountControl -Identity $_ -TrustedForDelegation $false 
}

# Enable Event Log forwarding
winrm quickconfig -q
# Forward logs to SIEM
```

### 2. Credential & Access Reset
Invalidate compromised credentials and reset access controls.

**Rules**:
- `credential_reset_validation.yml` – Semgrep: ensure no hardcoded credentials remain
- `credential_mfa_enforcement.rego` – OPA: require MFA for all admin access
- `session_token_revocation.yml` – Semgrep: validate all sessions revoked

**Execution**:
```powershell
# Reset all user credentials
$users = Get-ADUser -Filter {Enabled -eq $true}
foreach ($user in $users) {
    Set-ADAccountPassword -Identity $user -Reset -NewPassword `
        (ConvertTo-SecureString -AsPlainText "TemporaryPassword123!" -Force)
    Set-ADUser -Identity $user -ChangePasswordAtLogon $true
}

# Force MFA re-enrollment
# For Office 365/Azure AD
Update-MsolUser -ObjectId (Get-MsolUser -All) -StrongAuthenticationMethods Reset
```

### 3. Patch Management
Apply critical security patches to prevent exploitation.

**Rules**:
- `patch_critical_validation.yml` – Semgrep: verify patches installed
- `patch_missing_detection.yml` – Sigma: detect missing patches on domain

**Execution**:
```powershell
# Install critical patches
$updates = Get-WindowsUpdate -Category Security -Severity Critical
Install-WindowsUpdate -Accept -AutoReboot

# Update malware definitions
Update-MpSignature

# Validate patch status
Get-Hotfix | Select-Object HotFixID, InstalledOn | Sort InstalledOn -Descending
```

### 4. File Integrity Monitoring Rebaseline
Establish new FIM baseline after system restore.

**Rules**:
- `fim_rebaseline_validation.yml` – Semgrep: ensure critical files hashed
- `fim_suspicious_changes.yml` – Sigma: detect unauthorized modifications post-hardening

**Execution**:
```python
# Rebaseline FIM (in Shield service)
import hashlib
import json

critical_paths = [
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\ProgramData"
]

fim_baseline = {}
for path in critical_paths:
    for file in get_files_recursive(path):
        hash_value = hashlib.sha256(open(file, 'rb').read()).hexdigest()
        fim_baseline[file] = hash_value

# Store in immutable MinIO
minio_client.put_object(
    "fim-baselines",
    f"post_recovery_{incident_id}.json",
    json.dumps(fim_baseline)
)
```

### 5. Ransomware-Specific Hardening
Block known ransomware attack vectors.

**Rules**:
- `ransomware_vss_protection.rego` – OPA: prevent shadow copy deletion
- `ransomware_backup_hardening.yml` – Semgrep: ensure immutable backups configured
- `ransomware_recovery_key_hardening.yml` – Semgrep: verify BitLocker/FileVault recovery keys secured

**Execution**:
```powershell
# BitLocker protection
foreach ($drive in Get-BitLockerVolume) {
    if ($drive.ProtectionStatus -eq "Off") {
        Enable-BitLocker -MountPoint $drive.MountPoint -EncryptionMethod Aes256
    }
}

# Disable VSS deletion
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Immutable backup configuration (Windows Server 2022+)
Set-NtfsAcl -Path "E:\Backups" -ObjectLock Enabled -LegalHold
```

### 6. Golden Image Validation
Verify restored system matches known-good baseline.

**Rules**:
- `golden_image_binary_validation.yml` – Semgrep: check system binaries haven't been modified
- `golden_image_configuration_validation.yml` – Semgrep: validate config files against baseline
- `golden_image_registry_validation.yml` – Semgrep: ensure registry not tampered with

**Execution**:
```python
# Validate against golden image hash manifest
import subprocess
import json

golden_manifest = minio_client.get_object("golden-images", "manifest.json")
manifest = json.loads(golden_manifest.read())

issues = []
for filepath, expected_hash in manifest.items():
    actual_hash = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
    if actual_hash != expected_hash:
        issues.append({
            "file": filepath,
            "expected": expected_hash,
            "actual": actual_hash
        })

if issues:
    alert_security_team(f"Golden image validation FAILED: {issues}")
else:
    print("✅ System matches golden image - safe to return to production")
```

## Hardening Profiles

### Profile: Default (Balanced)
```yaml
duration_minutes: 90
actions:
  - lateral_movement_prevention: enabled
  - credential_reset: full  # Reset all users
  - patch_management: critical_only
  - fim_rebaseline: enabled
  - ransomware_hardening: enabled
  - golden_image_validation: enabled
  - mfa_enforcement: admin_only
```

### Profile: High-Security (Aggressive)
```yaml
duration_minutes: 180
actions:
  - lateral_movement_prevention: aggressive  # Strict segmentation
  - credential_reset: full_with_mfa
  - patch_management: all  # Critical + optional
  - fim_rebaseline: aggressive  # Monitor more paths
  - ransomware_hardening: aggressive  # Block all VSS, encryption tools
  - golden_image_validation: strict  # Zero tolerance for deviations
  - mfa_enforcement: everywhere
  - network_rescan: enabled  # Scan all hosts for lateral movement
```

### Profile: Fast-Recovery (Minimal)
```yaml
duration_minutes: 30
actions:
  - lateral_movement_prevention: basic
  - credential_reset: compromised_only
  - patch_management: critical_only
  - fim_rebaseline: critical_paths_only
  - ransomware_hardening: enabled
  - golden_image_validation: spot_check  # Sample files only
  - mfa_enforcement: admin_only
```

## Testing Hardening Rules

```bash
pytest tests/compliance/test_hardening_rules.py -v
```

**Pass Criteria**:
- ✅ Lateral movement vectors blocked
- ✅ All weak credentials reset
- ✅ Critical patches applied
- ✅ Golden image validation passes
- ✅ No suspicious modifications detected post-hardening
- ✅ Immutable backups confirmed accessible

---

**Integration**: Executed by playbook `post_incident_hardening` stage
