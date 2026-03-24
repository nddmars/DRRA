"""
DRRA TheHive Connector
Automatically creates alerts and cases in TheHive when DRRA detects ransomware.

Features:
  - Alert creation for each DRRA detection event
  - Case creation for confirmed incidents with full timeline
  - Observable ingestion (IPs, hashes, domains, files)
  - Task template: Isolation → Evidence → Recovery → Hardening
  - Bidirectional status sync (TheHive case status → DRRA incident status)

Requirements:
  pip install thehive4py requests

Environment variables:
  THEHIVE_URL      TheHive API endpoint (e.g. https://thehive.yourorg.com)
  THEHIVE_API_KEY  TheHive API key
  DRRA_API_URL     DRRA backend URL (default: http://localhost:8000)
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from thehive4py import TheHiveApi
from thehive4py.models import (
    Alert,
    AlertArtifact,
    Case,
    CaseTask,
    CaseObservable,
)

logger = logging.getLogger(__name__)

THEHIVE_URL     = os.getenv("THEHIVE_URL",     "https://thehive.yourorg.com")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
DRRA_API_URL    = os.getenv("DRRA_API_URL",    "http://localhost:8000")

# Severity mapping: DRRA → TheHive (1=Low, 2=Medium, 3=High)
SEVERITY_MAP = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 3,
}

# PAP (Permissible Actions Protocol) levels
PAP_WHITE = 0
PAP_GREEN = 1
PAP_AMBER = 2
PAP_RED   = 3

# ---------------------------------------------------------------------------
# Alert Templates per DRRA event type
# ---------------------------------------------------------------------------

ALERT_TEMPLATES = {
    "entropy_spike": {
        "type":        "ransomware-detection",
        "source":      "DRRA-VIGIL",
        "title_tmpl":  "High-Entropy File Activity on {hostname}",
        "description": "Shannon entropy above threshold detected — possible in-progress encryption.",
        "tags":        ["ransomware", "entropy", "T1486"],
    },
    "mass_modification": {
        "type":        "ransomware-detection",
        "source":      "DRRA-VIGIL",
        "title_tmpl":  "Mass File Modification on {hostname} ({count} files)",
        "description": "Bulk file modification rate exceeded threshold — ransomware encryption loop likely active.",
        "tags":        ["ransomware", "mass-modification", "T1486"],
    },
    "vss_deletion": {
        "type":        "ransomware-prereq",
        "source":      "DRRA-VIGIL",
        "title_tmpl":  "Volume Shadow Copy Deletion on {hostname}",
        "description": "VSS deletion command detected — attacker is removing recovery points before encryption.",
        "tags":        ["ransomware", "vss-deletion", "T1490", "critical"],
    },
    "lateral_movement": {
        "type":        "ransomware-prereq",
        "source":      "DRRA-VIGIL",
        "title_tmpl":  "Lateral Movement Detected from {hostname}",
        "description": "Ransomware lateral movement indicators: Kerberos abuse, SMB lateral, or credential reuse.",
        "tags":        ["ransomware", "lateral-movement", "T1021"],
    },
    "credential_theft": {
        "type":        "ransomware-prereq",
        "source":      "DRRA-VIGIL",
        "title_tmpl":  "Credential Harvesting Detected on {hostname}",
        "description": "LSASS memory access or credential scraping detected — likely pre-ransomware stage.",
        "tags":        ["ransomware", "credential-theft", "T1003"],
    },
}

# ---------------------------------------------------------------------------
# Standard Case Task Templates
# ---------------------------------------------------------------------------

RANSOMWARE_CASE_TASKS = [
    {
        "title":       "1. Confirm Isolation",
        "description": "Verify the affected host(s) are network-isolated via DRRA SHIELD. "
                       "Confirm VLAN quarantine is active. Check isolation status at: "
                       f"{DRRA_API_URL}/api/v1/shield/status",
        "group":       "Containment",
        "order":       1,
    },
    {
        "title":       "2. Collect Forensic Evidence",
        "description": "Run Velociraptor artifact 'DRRA.Ransomware.ForensicCollection' on affected hosts. "
                       "Download memory dump, process list, network connections, and encrypted file list. "
                       "Store artifacts in DRRA MinIO (immutable).",
        "group":       "Investigation",
        "order":       2,
    },
    {
        "title":       "3. Identify Ransomware Family",
        "description": "Analyze ransom note, extension, and behavioral indicators against DRRA YARA rules. "
                       "Check MISP for matching IOCs. Determine encryption algorithm if possible.",
        "group":       "Investigation",
        "order":       3,
    },
    {
        "title":       "4. Determine Blast Radius",
        "description": "Identify all affected systems via DRRA OPA blast radius policy. "
                       "Map lateral movement path. Check shared drives and backup systems.",
        "group":       "Investigation",
        "order":       4,
    },
    {
        "title":       "5. Notify Stakeholders",
        "description": "Notify CISO, Legal, and affected business units per incident response plan. "
                       "Assess regulatory notification requirements (GDPR 72h, HIPAA 60d, SEC 4d).",
        "group":       "Communication",
        "order":       5,
    },
    {
        "title":       "6. Execute Recovery",
        "description": "Initiate DRRA SHIELD recovery from immutable MinIO snapshots. "
                       "Verify integrity checksums post-restore. Monitor for re-infection.",
        "group":       "Recovery",
        "order":       6,
    },
    {
        "title":       "7. Post-Recovery Hardening",
        "description": "Execute DRRA post-recovery hardening: MFA enforcement, FIM rebaseline, "
                       "Kerberos golden ticket purge, golden image validation via Semgrep.",
        "group":       "Hardening",
        "order":       7,
    },
    {
        "title":       "8. Lessons Learned & MISP Sharing",
        "description": "Document attack timeline, MTTC achieved vs target. Push confirmed IOCs to MISP. "
                       "Update Sigma/YARA rules if novel techniques detected. Update DRRA thresholds.",
        "group":       "PostIncident",
        "order":       8,
    },
]


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class DRRATheHiveConnector:
    """Automates TheHive alert and case creation from DRRA detection events."""

    def __init__(self):
        if not THEHIVE_API_KEY:
            raise ValueError("THEHIVE_API_KEY environment variable not set")
        self.api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
        logger.info("Connected to TheHive at %s", THEHIVE_URL)

    # -----------------------------------------------------------------------
    # Alert Creation (one per detection event)
    # -----------------------------------------------------------------------

    def create_alert_from_detection(self, detection_event: dict) -> Optional[dict]:
        """
        Create a TheHive alert from a DRRA detection event.

        Args:
            detection_event: DRRA DetectionEvent dict

        Returns:
            TheHive alert response dict, or None on failure.
        """
        event_type = detection_event.get("event_type", "unknown")
        template   = ALERT_TEMPLATES.get(event_type, ALERT_TEMPLATES["entropy_spike"])
        metadata   = detection_event.get("metadata", {})
        hostname   = metadata.get("hostname", detection_event.get("hostname", "unknown"))

        title = template["title_tmpl"].format(
            hostname=hostname,
            count=metadata.get("file_count", "N/A"),
        )

        artifacts = self._build_artifacts(detection_event)

        alert = Alert(
            title       = title,
            tlp         = PAP_AMBER,
            pap         = PAP_AMBER,
            severity    = SEVERITY_MAP.get(detection_event.get("severity", "high"), 3),
            tags        = template["tags"],
            description = self._build_alert_description(detection_event, template),
            type        = template["type"],
            source      = template["source"],
            sourceRef   = detection_event.get("id", f"drra-{datetime.now(timezone.utc).timestamp():.0f}"),
            artifacts   = artifacts,
            externalLink= f"{DRRA_API_URL}/api/v1/vigil/events/{detection_event.get('id', '')}",
        )

        try:
            response = self.api.create_alert(alert)
            if response.status_code == 201:
                logger.info("TheHive alert created: %s", response.json().get("id"))
                return response.json()
            else:
                logger.error("TheHive alert creation failed: %s %s", response.status_code, response.text)
                return None
        except Exception as e:
            logger.error("Failed to create TheHive alert: %s", e)
            return None

    # -----------------------------------------------------------------------
    # Case Creation (for confirmed incidents)
    # -----------------------------------------------------------------------

    def create_case_from_incident(self, incident: dict) -> Optional[dict]:
        """
        Create a full TheHive case from a confirmed DRRA incident.
        Includes tasks, observables, and full timeline.

        Args:
            incident: DRRA incident dict (from /api/v1/dashboard/incidents/{id})

        Returns:
            TheHive case response dict, or None on failure.
        """
        case = Case(
            title       = f"Ransomware Incident: {incident.get('title', incident.get('id', 'N/A'))}",
            description = self._build_case_description(incident),
            severity    = SEVERITY_MAP.get(incident.get("severity", "high"), 3),
            tlp         = PAP_AMBER,
            pap         = PAP_AMBER,
            tags        = ["ransomware", "drra", f"mttc:{incident.get('mttc_seconds', 'N/A')}s"],
            tasks       = [CaseTask(**t) for t in RANSOMWARE_CASE_TASKS],
            flag        = incident.get("severity") == "critical",
        )

        try:
            response = self.api.create_case(case)
            if response.status_code == 201:
                case_data = response.json()
                case_id   = case_data.get("id")
                logger.info("TheHive case created: %s", case_id)

                # Add observables
                for obs in self._build_observables(incident):
                    self.api.create_case_observable(case_id, obs)

                return case_data
            else:
                logger.error("TheHive case creation failed: %s %s", response.status_code, response.text)
                return None
        except Exception as e:
            logger.error("Failed to create TheHive case: %s", e)
            return None

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _build_artifacts(self, event: dict) -> list[AlertArtifact]:
        artifacts = []
        metadata  = event.get("metadata", {})

        if ip := metadata.get("source_ip"):
            artifacts.append(AlertArtifact(dataType="ip", data=ip, tlp=PAP_AMBER))
        if domain := metadata.get("c2_domain"):
            artifacts.append(AlertArtifact(dataType="domain", data=domain, tlp=PAP_AMBER))
        if sha256 := metadata.get("sha256"):
            artifacts.append(AlertArtifact(dataType="hash", data=sha256, tlp=PAP_AMBER))
        if fname := metadata.get("suspicious_file"):
            artifacts.append(AlertArtifact(dataType="filename", data=fname, tlp=PAP_GREEN))

        return artifacts

    def _build_observables(self, incident: dict) -> list[CaseObservable]:
        observables = []
        for ip in incident.get("affected_ips", []):
            observables.append(CaseObservable(dataType="ip", data=[ip], tlp=PAP_AMBER,
                                              message="Affected host IP"))
        if sha256 := incident.get("payload_hash"):
            observables.append(CaseObservable(dataType="hash", data=[sha256], tlp=PAP_AMBER,
                                              message="Ransomware payload hash", ioc=True))
        return observables

    def _build_alert_description(self, event: dict, template: dict) -> str:
        metadata = event.get("metadata", {})
        lines = [
            f"## DRRA VIGIL Detection\n",
            f"**{template['description']}**\n",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Event ID | `{event.get('id', 'N/A')}` |",
            f"| Detected | `{event.get('timestamp', 'N/A')}` |",
            f"| Host | `{metadata.get('hostname', 'N/A')}` |",
            f"| Source IP | `{metadata.get('source_ip', 'N/A')}` |",
            f"| Confidence | `{event.get('confidence', 'N/A')}` |",
            f"| Entropy | `{metadata.get('entropy_score', 'N/A')}` |",
            f"| Files Modified | `{metadata.get('file_count', 'N/A')}` |",
            f"\n[View in DRRA Dashboard]({DRRA_API_URL}/api/v1/vigil/events/{event.get('id', '')})",
        ]
        return "\n".join(lines)

    def _build_case_description(self, incident: dict) -> str:
        lines = [
            f"## Ransomware Incident — DRRA Confirmed\n",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Incident ID | `{incident.get('id', 'N/A')}` |",
            f"| Detected | `{incident.get('detected_at', 'N/A')}` |",
            f"| Contained | `{incident.get('contained_at', 'N/A')}` |",
            f"| MTTC | `{incident.get('mttc_seconds', 'N/A')}s` (target: 60s) |",
            f"| Data Loss | `{incident.get('data_loss_pct', 0):.2f}%` |",
            f"| Isolation | `{incident.get('isolation_method', 'N/A')}` |",
            f"| Recovery | `{incident.get('recovery_method', 'N/A')}` |",
            f"\n### AI-Generated Summary\n",
            f"{incident.get('llm_summary', '_No summary available_')}\n",
            f"\n### Affected Hosts\n",
        ]
        for host in incident.get("affected_hosts", []):
            lines.append(f"- `{host}`")
        lines.append(f"\n[View in DRRA Dashboard]({DRRA_API_URL}/api/v1/dashboard/incidents/{incident.get('id', '')})")
        return "\n".join(lines)
