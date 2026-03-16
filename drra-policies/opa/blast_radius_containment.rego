package isolation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Blast Radius Containment Policy
# Limits lateral movement impact by micro-segmenting network based on affected systems

# Determine safe isolation scope
allow_blast_radius_containment if {
    has_clear_infection_scope
    sufficient_segmentation_available
    can_isolate_without_critical_impact
}

# Analyze affected systems to contain spread
has_clear_infection_scope if {
    count(input.affected_hosts) > 0
    count(input.infection_timeline) > 0
    input.entry_point_identified != null
}

# Check network has available segmentation
sufficient_segmentation_available if {
    count(available_vlans) > 0
    count(input.network_segments) > 3  # At least 4 segments
}

# Available quarantine VLANs for blast radius containment
available_vlans := {
    "QUARANTINE_10",
    "QUARANTINE_20",
    "ISOLATED_TIER_0",
    "THREAT_CONTAINMENT_1",
    "THREAT_CONTAINMENT_2"
}

# Determine hosts that can be safely isolated
can_isolate_without_critical_impact if {
    not includes_critical_infrastructure
    not affects_all_user_devices
    not blocks_backup_systems
}

# Critical systems that cannot be isolated
critical_services := {
    "AD-Primary",
    "AD-Secondary",
    "DNS-Primary",
    "DNS-Secondary",
    "Exchange-Primary",
    "Backup-Storage",
    "Syslog-Collector"
}

includes_critical_infrastructure if {
    some host in input.affected_hosts
    host in critical_services
}

# User device isolation scope
affects_all_user_devices if {
    input.user_device_count > 0
    input.infected_device_percentage > 0.5  # If >50% affected, risky
}

# Backup system isolation check
blocks_backup_systems if {
    "Backup-Storage" in input.affected_hosts
}

# Build containment strategy
blast_radius_containment := {
    "allowed": allow_blast_radius_containment,
    "affected_hosts": input.affected_hosts,
    "infection_timeline_minutes": input.timeline_minutes,
    "estimated_lateral_movement_hops": count_hops,
    "containment_zones": determine_zones,
    "network_policies": create_policies,
    "critical_systems_protected": get_protected_systems
}

# Estimate how many hops attacker made (infection timeline / average hop duration)
count_hops := hops if {
    hops := input.timeline_minutes / 5  # Assume 5 min per lateral movement hop
    hops > 0
} else {
    hops := 1
}

# Determine which systems to isolate in which zones
determine_zones[zone] if {
    zone := {
        "zone_id": input.entry_point,
        "vlans": pick_vlan,
        "hosts": get_hosts_to_isolate,
        "isolation_method": "vlan_quarantine",
        "monitor_for_spread": true,
        "estimated_containment_time": "5 minutes"
    }
}

# Pick appropriate VLAN based on threat level
pick_vlan := vlan_selection if {
    input.threat_level == "critical"
    vlan_selection := "ISOLATED_TIER_0"
} else if {
    input.threat_level == "high"
    vlan_selection := "QUARANTINE_10"
} else {
    vlan_selection := "QUARANTINE_20"
}

# Get hosts to isolate (don't isolate critical services)
get_hosts_to_isolate[host] if {
    some host in input.affected_hosts
    not host in critical_services
}

# Create network policies to prevent lateral movement
create_policies[policy] if {
    policy := {
        "type": "deny_lateral_movement",
        "source_vlan": "User_VLAN",
        "destination_blocked": ["Admin_VLAN", "Finance_VLAN"],
        "blocked_protocols": ["RDP", "SMB", "WinRM"],
        "action": "drop",
        "log": true
    }
}

# Systems that remain accessible despite incident
get_protected_systems[sys] if {
    some sys in critical_services
    not sys in input.affected_hosts
}

# Denial reasons
deny_reason[reason] if {
    not has_clear_infection_scope
    reason := "Infection scope unclear - cannot determine blast radius"
}

deny_reason[reason] if {
    includes_critical_infrastructure
    reason := sprintf(
        "Critical systems affected (%v) - requires manual approval",
        [input.affected_hosts]
    )
}

deny_reason[reason] if {
    not sufficient_segmentation_available
    reason := "Network lacks sufficient segmentation for safe containment"
}

deny_reason[reason] if {
    affects_all_user_devices
    reason := sprintf(
        "Too many user devices affected (%.1f%%) - escalate to senior IR",
        [input.infected_device_percentage * 100]
    )
}
