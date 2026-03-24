"""
DRRA CrowdStrike Falcon Integration
Bidirectional integration between DRRA and CrowdStrike Falcon via the FalconPy SDK.

Features:
  - Pull CrowdStrike detections and enrich DRRA events
  - Trigger Falcon Real-Time Response (RTR) for isolation from DRRA SHIELD
  - Push confirmed IOCs to Falcon Custom IOA / Indicators
  - Sync CrowdStrike host containment status with DRRA
  - Stream Falcon Event Streaming API events into DRRA VIGIL

Requirements:
  pip install crowdstrike-falconpy

Environment variables:
  FALCON_CLIENT_ID      CrowdStrike OAuth2 client ID
  FALCON_CLIENT_SECRET  CrowdStrike OAuth2 client secret
  FALCON_BASE_URL       API base URL (default: https://api.crowdstrike.com)
  DRRA_API_URL          DRRA backend URL
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

from falconpy import (
    Detects,
    Hosts,
    RealTimeResponse,
    RealTimeResponseAdmin,
    IOC,
    EventStreams,
)
import requests

logger = logging.getLogger(__name__)

FALCON_CLIENT_ID     = os.getenv("FALCON_CLIENT_ID",     "")
FALCON_CLIENT_SECRET = os.getenv("FALCON_CLIENT_SECRET", "")
FALCON_BASE_URL      = os.getenv("FALCON_BASE_URL",      "https://api.crowdstrike.com")
DRRA_API_URL         = os.getenv("DRRA_API_URL",         "http://localhost:8000")

# Falcon severity to DRRA severity mapping
FALCON_SEVERITY_MAP = {
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

# DRRA event types → Falcon behavior descriptions to correlate
DRRA_TO_FALCON_BEHAVIOR = {
    "entropy_spike":     ["RANSOMWARE", "FILE_ENCRYPTION", "CRYPTO"],
    "mass_modification": ["RANSOMWARE", "BULK_FILE_MODIFICATION"],
    "vss_deletion":      ["VOLUME_SHADOW_COPY_DELETION", "INHIBIT_RECOVERY"],
    "lateral_movement":  ["LATERAL_MOVEMENT", "CREDENTIAL_THEFT", "KERBEROASTING"],
}


# ---------------------------------------------------------------------------
# Client wrapper
# ---------------------------------------------------------------------------

class DRRACrowdStrikeConnector:
    """Integrates DRRA detection and response with CrowdStrike Falcon."""

    def __init__(self):
        creds = dict(client_id=FALCON_CLIENT_ID, client_secret=FALCON_CLIENT_SECRET)
        base  = FALCON_BASE_URL

        self.detects  = Detects(base_url=base, **creds)
        self.hosts    = Hosts(base_url=base, **creds)
        self.rtr      = RealTimeResponse(base_url=base, **creds)
        self.rtr_adm  = RealTimeResponseAdmin(base_url=base, **creds)
        self.ioc      = IOC(base_url=base, **creds)
        self.streams  = EventStreams(base_url=base, **creds)
        logger.info("CrowdStrike Falcon SDK initialized")

    # -----------------------------------------------------------------------
    # DETECTION ENRICHMENT
    # -----------------------------------------------------------------------

    def get_recent_ransomware_detections(self, hours: int = 1) -> list[dict]:
        """
        Pull CrowdStrike detections related to ransomware from the last N hours.

        Returns:
            List of normalized detection dicts for DRRA VIGIL ingestion.
        """
        # Search for ransomware-related behaviors
        filter_str = (
            f"last_behavior:>'{datetime.now(timezone.utc).isoformat()[:-10]}Z' "
            "+ behaviors.tactic:'Ransomware'"
        )

        query_resp = self.detects.query_detections(
            filter=filter_str,
            limit=100,
        )
        if query_resp["status_code"] != 200:
            logger.error("Falcon detection query failed: %s", query_resp["body"])
            return []

        det_ids = query_resp["body"]["resources"]
        if not det_ids:
            return []

        details_resp = self.detects.get_detection_summaries(ids=det_ids)
        if details_resp["status_code"] != 200:
            return []

        return [
            self._normalize_falcon_detection(d)
            for d in details_resp["body"]["resources"]
        ]

    def _normalize_falcon_detection(self, det: dict) -> dict:
        """Map a Falcon detection to a DRRA DetectionEvent schema."""
        behaviors = det.get("behaviors", [{}])
        primary   = behaviors[0] if behaviors else {}

        return {
            "source":       "crowdstrike_falcon",
            "event_type":   self._map_falcon_tactic(primary.get("tactic", "")),
            "timestamp":    det.get("last_behavior"),
            "hostname":     det.get("device", {}).get("hostname"),
            "source_ip":    det.get("device", {}).get("local_ip"),
            "severity":     FALCON_SEVERITY_MAP.get(det.get("max_severity", 3), "medium"),
            "confidence":   det.get("max_severity", 3) / 5.0,
            "falcon_detection_id": det.get("detection_id"),
            "metadata": {
                "sha256":         primary.get("sha256"),
                "filename":       primary.get("filename"),
                "cmdline":        primary.get("cmdline"),
                "tactic":         primary.get("tactic"),
                "technique":      primary.get("technique"),
                "scenario":       primary.get("scenario"),
                "device_id":      det.get("device", {}).get("device_id"),
                "falcon_status":  det.get("status"),
            },
        }

    def _map_falcon_tactic(self, tactic: str) -> str:
        tactic_upper = tactic.upper()
        if "RANSOM" in tactic_upper or "ENCRYPT" in tactic_upper:
            return "entropy_spike"
        if "LATERAL" in tactic_upper:
            return "lateral_movement"
        if "CREDENTIAL" in tactic_upper or "KERBEROS" in tactic_upper:
            return "lateral_movement"
        return "entropy_spike"

    # -----------------------------------------------------------------------
    # HOST ISOLATION via Real-Time Response (RTR)
    # -----------------------------------------------------------------------

    def isolate_host(self, device_id: str, reason: str = "DRRA SHIELD isolation") -> dict:
        """
        Contain a host in CrowdStrike Falcon via Network Containment.
        This is faster than RTR for network isolation.

        Args:
            device_id: CrowdStrike device_id (AID)
            reason:    Human-readable reason for the audit log

        Returns:
            Result dict with success flag and status.
        """
        resp = self.hosts.perform_action(
            action_name="contain",
            ids=[device_id],
            body={"action_parameters": [{"name": "comment", "value": reason}]},
        )

        if resp["status_code"] in (200, 202):
            logger.info("CrowdStrike containment initiated for device %s", device_id)
            return {"success": True, "device_id": device_id, "action": "contain"}
        else:
            logger.error("CrowdStrike containment failed: %s", resp["body"])
            return {"success": False, "error": resp["body"]}

    def lift_isolation(self, device_id: str) -> dict:
        """Remove CrowdStrike network containment (post-recovery)."""
        resp = self.hosts.perform_action(
            action_name="lift_containment",
            ids=[device_id],
        )
        success = resp["status_code"] in (200, 202)
        return {"success": success, "device_id": device_id}

    def get_device_id_by_ip(self, ip_address: str) -> Optional[str]:
        """Resolve a host IP to a CrowdStrike device_id."""
        resp = self.hosts.query_devices_by_filter(
            filter=f"local_ip:'{ip_address}'",
            limit=1,
        )
        ids = resp.get("body", {}).get("resources", [])
        return ids[0] if ids else None

    # -----------------------------------------------------------------------
    # RTR: Run forensic commands on isolated hosts
    # -----------------------------------------------------------------------

    def run_forensic_commands(self, device_id: str) -> dict:
        """
        Open an RTR session and run DRRA forensic commands on an isolated host.
        Collects: process list, network connections, ransom note inventory.
        """
        results = {}

        # Open RTR session
        session_resp = self.rtr.init_session(
            body={"device_id": device_id, "queue_offline": True}
        )
        if session_resp["status_code"] != 201:
            return {"error": "Could not open RTR session"}

        session_id = session_resp["body"]["resources"][0]["session_id"]

        forensic_commands = [
            ("ps",      "ps",                                    "Process list"),
            ("netstat", "netstat -an",                           "Network connections"),
            ("ls",      "ls C:\\Users -recurse -filter *.TXT",  "Ransom note search"),
            ("reg",     "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Registry persistence"),
        ]

        for cmd_type, cmd, description in forensic_commands:
            cmd_resp = self.rtr.execute_command(
                body={
                    "session_id": session_id,
                    "base_command": cmd_type,
                    "command_string": cmd,
                }
            )
            results[description] = cmd_resp.get("body", {}).get("resources", [])

        # Close session
        self.rtr.delete_session(session_id=session_id)
        return results

    # -----------------------------------------------------------------------
    # IOC MANAGEMENT
    # -----------------------------------------------------------------------

    def push_iocs_from_drra(self, iocs: list[dict]) -> dict:
        """
        Push confirmed ransomware IOCs from DRRA to Falcon Custom Indicators.

        Args:
            iocs: List of IOC dicts with keys: type, value, severity, description

        Returns:
            CrowdStrike API response.
        """
        falcon_iocs = []
        for ioc in iocs:
            ioc_type = self._map_ioc_type(ioc.get("type", ""))
            if not ioc_type:
                continue
            falcon_iocs.append({
                "type":          ioc_type,
                "value":         ioc["value"],
                "action":        "detect",
                "severity":      ioc.get("severity", "high"),
                "source":        "DRRA",
                "description":   ioc.get("description", "DRRA confirmed ransomware IOC"),
                "platforms":     ["windows", "linux", "mac"],
                "applied_globally": True,
                "tags":          ["ransomware", "drra-confirmed"],
            })

        if not falcon_iocs:
            return {"success": True, "pushed": 0}

        resp = self.ioc.indicator_create_v1(body={"indicators": falcon_iocs})
        success = resp["status_code"] in (200, 201)
        pushed  = len(resp.get("body", {}).get("resources", []))
        logger.info("Pushed %d IOCs to CrowdStrike Falcon", pushed)
        return {"success": success, "pushed": pushed, "response": resp["body"]}

    def _map_ioc_type(self, drra_type: str) -> Optional[str]:
        mapping = {
            "sha256":   "sha256",
            "md5":      "md5",
            "sha1":     "sha1",
            "ip":       "ipv4",
            "domain":   "domain",
            "url":      "url",
        }
        return mapping.get(drra_type.lower())

    # -----------------------------------------------------------------------
    # DRRA → Falcon sync: isolate host when DRRA SHIELD fires
    # -----------------------------------------------------------------------

    def handle_drra_isolation_event(self, drra_event: dict) -> dict:
        """
        Called by DRRA SHIELD webhook when isolation is triggered.
        Finds the CrowdStrike device_id by IP and contains it in Falcon.

        Register this as a DRRA post-isolation webhook:
          DRRA_SHIELD_WEBHOOK_URL=http://localhost:5001/crowdstrike/isolate
        """
        target_ip = drra_event.get("target_ip") or drra_event.get("source_ip")
        if not target_ip:
            return {"success": False, "error": "No target IP in event"}

        device_id = self.get_device_id_by_ip(target_ip)
        if not device_id:
            return {"success": False, "error": f"No CrowdStrike device found for IP {target_ip}"}

        return self.isolate_host(
            device_id,
            reason=f"DRRA SHIELD: {drra_event.get('reason', 'Ransomware detected')}",
        )

    # -----------------------------------------------------------------------
    # STREAMING: Push Falcon events to DRRA VIGIL
    # -----------------------------------------------------------------------

    def stream_detections_to_drra(self, app_id: str = "drra-connector") -> None:
        """
        Subscribe to Falcon Event Streaming API and forward ransomware
        detections to DRRA VIGIL in real-time. Run as a background service.
        """
        discover_resp = self.streams.list_available_streams_oauth2(app_id=app_id)
        if discover_resp["status_code"] != 200:
            logger.error("Cannot discover Falcon streams: %s", discover_resp["body"])
            return

        resources = discover_resp["body"].get("resources", [])
        if not resources:
            logger.warning("No Falcon event streams available")
            return

        feed_url  = resources[0]["dataFeedURL"]
        token     = resources[0]["sessionToken"]["token"]

        logger.info("Subscribing to Falcon event stream: %s", feed_url)

        response = requests.get(
            feed_url,
            headers={"Authorization": f"Token {token}"},
            stream=True,
            timeout=None,
        )

        for line in response.iter_lines():
            if not line:
                continue
            try:
                import json
                event = json.loads(line)
                self._process_stream_event(event)
            except Exception as e:
                logger.debug("Stream parse error: %s", e)

    def _process_stream_event(self, event: dict) -> None:
        """Filter and forward relevant Falcon stream events to DRRA VIGIL."""
        meta = event.get("metadata", {})
        etype = meta.get("eventType", "")

        # Only forward detection-related events
        if etype not in ("DetectionSummaryEvent", "EppDetectionSummaryEvent",
                          "IncidentSummaryEvent", "RemoteResponseSessionEndEvent"):
            return

        evt = event.get("event", {})
        severity = evt.get("SeverityName", "medium").lower()
        if severity in ("low", "informational"):
            return

        drra_event = {
            "source":     "crowdstrike_stream",
            "event_type": self._map_falcon_tactic(evt.get("Tactic", "")),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "hostname":   evt.get("ComputerName"),
            "source_ip":  evt.get("LocalIP"),
            "severity":   severity,
            "confidence": min(1.0, evt.get("MaxSeverity", 50) / 100.0),
            "metadata":   {
                "sha256":    evt.get("SHA256String"),
                "filename":  evt.get("FileName"),
                "cmdline":   evt.get("CommandLine"),
                "tactic":    evt.get("Tactic"),
                "technique": evt.get("Technique"),
            },
        }

        try:
            requests.post(
                f"{DRRA_API_URL}/api/v1/vigil/events",
                json=drra_event,
                timeout=5,
            )
        except Exception as e:
            logger.warning("Failed to forward Falcon event to DRRA: %s", e)
