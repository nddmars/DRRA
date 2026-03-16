package isolation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# VLAN Isolation Policy
# Enforces safe network quarantine by validating target VLAN and preventing critical service disconnection

# Allow VLAN quarantine if:
# 1. Target VLAN exists and is designated for quarantine
# 2. Process is not critical system process
# 3. Affected host is not a domain controller or critical infrastructure
# 4. At least 60 seconds of immutable logging exists

allow_vlan_quarantine if {
    input.target_vlan in quarantine_vlans
    not is_critical_process
    not is_critical_infrastructure
    has_immutable_logs
}

# Define approved quarantine VLANs
quarantine_vlans := {
    "QUARANTINE_10",
    "QUARANTINE_20",
    "ISOLATED_TIER_0",
    "THREAT_CONTAINMENT_1"
}

# Processes that cannot be killed (would break system)
critical_processes := {
    "svchost.exe",
    "System",
    "csrss.exe",
    "wininit.exe",
    "ntlm.exe",
    "lsass.exe",
    "winlogon.exe"
}

# Infrastructure that cannot be isolated (would break network)
critical_infrastructure := {
    "DC-PRIMARY",
    "DC-SECONDARY",
    "DNS-01",
    "DNS-02",
    "NTP-SERVER",
    "SYSLOG-COLLECTOR"
}

is_critical_process if {
    input.process_name in critical_processes
}

is_critical_infrastructure if {
    input.hostname in critical_infrastructure
}

has_immutable_logs if {
    input.log_retention_minutes > 60
    input.object_lock_enabled == true
}

# Denial reasons for audit trail
deny_reason[reason] if {
    not input.target_vlan in quarantine_vlans
    reason := sprintf(
        "VLAN %s not in approved quarantine list: %v",
        [input.target_vlan, quarantine_vlans]
    )
}

deny_reason[reason] if {
    is_critical_process
    reason := sprintf(
        "Process %s is critical system process and cannot be isolated",
        [input.process_name]
    )
}

deny_reason[reason] if {
    is_critical_infrastructure
    reason := sprintf(
        "Host %s is critical infrastructure and cannot be isolated",
        [input.hostname]
    )
}

deny_reason[reason] if {
    not has_immutable_logs
    reason := "Insufficient immutable logging configured before isolation"
}

# Provide detailed response
isolation_decision := {
    "allowed": allow_vlan_quarantine,
    "vlan": input.target_vlan,
    "process": input.process_name,
    "host": input.hostname,
    "reasons": deny_reason,
    "timestamp": input.timestamp,
    "requires_approval": is_high_risk
}

# High-risk isolation (requires manual approval)
is_high_risk if {
    input.affected_service_count > 5
}

is_high_risk if {
    input.isolation_method in ["kill_process", "revoke_credentials"]
}
