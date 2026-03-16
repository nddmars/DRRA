package hardening

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Lateral Movement Prevention Hardening Policy
# Enforces post-incident Kerberos hardening after ransomware recovery

allow_kerberos_hardening if {
    system_is_recovered
    no_active_detections
    immutable_logs_preserved
}

# Verify system is fully recovered before hardening
system_is_recovered if {
    input.recovery_status == "complete"
    input.golden_image_validation == true
    input.malware_rescan_result == "clean"
}

# Ensure no detections are active
no_active_detections if {
    input.active_alerts == 0
    input.suspicious_processes == false
    input.lateral_movement_blocked == true
}

# Verify forensics are preserved before changes
immutable_logs_preserved if {
    input.object_lock_enabled == true
    input.forensic_snapshot_immutable == true
    input.legal_hold_enabled == true
}

# Hardening actions to enforce
hardening_rules := {
    "kerberos_strict_mode": {
        "enabled": true,
        "unconstrained_delegation": false,
        "constrained_delegation_audit": true
    },
    "credential_management": {
        "disable_empty_passwords": true,
        "enforce_strong_passwords": true,
        "reset_all_credentials": true,
        "mfa_required": true
    },
    "network_segmentation": {
        "enforce_vlan_boundaries": true,
        "block_admin_share_access": true,
        "disable_null_sessions": true
    },
    "logging": {
        "enable_auth_log_forwarding": true,
        "enable_process_creation_log": true,
        "immutable_log_destination": "minios3"
    }
}

# Provide hardening plan
hardening_plan := {
    "allowed": allow_kerberos_hardening,
    "profile": input.hardening_profile,
    "rules": hardening_rules,
    "estimated_duration_minutes": get_duration_minutes,
    "rollback_snapshot": input.pre_hardening_snapshot,
    "validation": {
        "golden_image_check": true,
        "lateral_movement_test": true,
        "credential_reset_validation": true
    }
}

# Get estimated duration based on profile
get_duration_minutes := minutes if {
    input.hardening_profile == "default"
    minutes := 90
} else if {
    input.hardening_profile == "aggressive"
    minutes := 180
} else if {
    input.hardening_profile == "fast"
    minutes := 30
}

# Denial if conditions not met
deny_reason[reason] if {
    not system_is_recovered
    reason := "System recovery not complete - postpone hardening"
}

deny_reason[reason] if {
    active_alerts := count(input.active_alerts)
    active_alerts > 0
    reason := sprintf(
        "Active alerts still pending (%d) - resolve before hardening",
        [active_alerts]
    )
}

deny_reason[reason] if {
    not immutable_logs_preserved
    reason := "Forensic evidence not immutable - cannot proceed with hardening"
}
