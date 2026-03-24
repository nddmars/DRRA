"""
DRRA MISP Connector
Bidirectional integration with MISP (Malware Information Sharing Platform).

Features:
  - Enrich DRRA detection events with MISP threat intelligence
  - Push confirmed DRRA incidents as MISP events for community sharing
  - Automated IOC lookup (IPs, domains, file hashes, process names)
  - Tag mapping: MITRE ATT&CK ↔ MISP taxonomy

Requirements:
  pip install pymisp requests

Environment variables:
  MISP_URL       MISP instance URL (e.g. https://misp.yourorg.com)
  MISP_KEY       MISP API key (from MISP → Event Actions → Automation)
  MISP_VERIFYCERT  true/false (default: true)
  DRRA_API_URL   DRRA backend URL (default: http://localhost:8000)
"""

import os
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Optional

import requests
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MISP_URL        = os.getenv("MISP_URL", "https://misp.yourorg.com")
MISP_KEY        = os.getenv("MISP_KEY", "")
MISP_VERIFYCERT = os.getenv("MISP_VERIFYCERT", "true").lower() == "true"
DRRA_API_URL    = os.getenv("DRRA_API_URL", "http://localhost:8000")

# MISP distribution levels
DISTRIBUTION_ORG_ONLY        = 0
DISTRIBUTION_COMMUNITY       = 1
DISTRIBUTION_CONNECTED_COMS  = 2
DISTRIBUTION_ALL_COMS        = 3

# Threat level IDs in MISP (1=High, 2=Medium, 3=Low, 4=Undefined)
THREAT_LEVEL_MAP = {
    "critical": 1,
    "high":     1,
    "medium":   2,
    "low":      3,
}

# DRRA event_type → MISP category/type mapping
IOC_TYPE_MAP = {
    "ip":           ("Network activity", "ip-dst"),
    "domain":       ("Network activity", "domain"),
    "url":          ("Network activity", "url"),
    "sha256":       ("Payload delivery",  "sha256"),
    "md5":          ("Payload delivery",  "md5"),
    "filename":     ("Artifacts dropped", "filename"),
    "process":      ("External analysis", "text"),
    "registry_key": ("External analysis", "regkey"),
    "email":        ("Payload delivery",  "email-src"),
}

# ---------------------------------------------------------------------------
# MISP Client
# ---------------------------------------------------------------------------

class DRRAMISPConnector:
    """Bridges DRRA detection events with MISP threat intelligence."""

    def __init__(self):
        if not MISP_KEY:
            raise ValueError("MISP_KEY environment variable not set")
        self.misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        logger.info("Connected to MISP at %s", MISP_URL)

    # -----------------------------------------------------------------------
    # ENRICHMENT: Look up IOCs from a DRRA detection event
    # -----------------------------------------------------------------------

    def enrich_detection_event(self, detection_event: dict) -> dict:
        """
        Enrich a DRRA detection event with MISP threat intelligence.
        Returns the original event dict with a 'misp_enrichment' key added.

        Args:
            detection_event: DRRA DetectionEvent dict (from /api/v1/vigil/events)

        Returns:
            Enriched dict with MISP matches, threat actor info, and MITRE tags.
        """
        enrichment = {
            "matched_events": [],
            "threat_actors":  [],
            "mitre_tags":     [],
            "galaxies":       [],
            "risk_score":     0,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        }

        iocs = self._extract_iocs(detection_event)
        logger.debug("Checking %d IOCs against MISP", len(iocs))

        for ioc_type, ioc_value in iocs:
            results = self._search_misp(ioc_type, ioc_value)
            for event in results:
                enrichment["matched_events"].append({
                    "misp_event_id":   event.get("id"),
                    "misp_event_uuid": event.get("uuid"),
                    "info":            event.get("info"),
                    "threat_level":    event.get("threat_level_id"),
                    "date":            event.get("date"),
                    "ioc":             f"{ioc_type}:{ioc_value}",
                })

                # Extract threat actors from event tags
                for tag in event.get("EventTag", []):
                    tag_name = tag.get("Tag", {}).get("name", "")
                    if "threat-actor:" in tag_name:
                        actor = tag_name.split("=")[-1].strip('"')
                        if actor not in enrichment["threat_actors"]:
                            enrichment["threat_actors"].append(actor)
                    if "mitre-attack:" in tag_name:
                        if tag_name not in enrichment["mitre_tags"]:
                            enrichment["mitre_tags"].append(tag_name)

                # Risk scoring: each MISP match increments score
                threat_lvl = int(event.get("threat_level_id", 4))
                enrichment["risk_score"] += max(0, (4 - threat_lvl) * 25)

        enrichment["risk_score"] = min(100, enrichment["risk_score"])
        detection_event["misp_enrichment"] = enrichment
        return detection_event

    def _extract_iocs(self, event: dict) -> list[tuple[str, str]]:
        """Extract IOC tuples (type, value) from a DRRA detection event."""
        iocs = []
        metadata = event.get("metadata", {})

        # Source IP
        if src_ip := metadata.get("source_ip") or event.get("source_ip"):
            if self._is_public_ip(src_ip):
                iocs.append(("ip", src_ip))

        # Process hashes
        for hash_type in ("sha256", "md5", "sha1"):
            if h := metadata.get(hash_type):
                iocs.append((hash_type, h.lower()))

        # Domains / URLs
        if domain := metadata.get("c2_domain"):
            iocs.append(("domain", domain))
        if url := metadata.get("c2_url"):
            iocs.append(("url", url))

        # Filename indicators
        if fname := metadata.get("suspicious_file"):
            iocs.append(("filename", fname))

        return iocs

    def _search_misp(self, ioc_type: str, ioc_value: str) -> list[dict]:
        """Search MISP for matching attributes."""
        try:
            category, attr_type = IOC_TYPE_MAP.get(ioc_type, ("", ""))
            results = self.misp.search(
                controller="attributes",
                type_attribute=attr_type if attr_type else None,
                value=ioc_value,
                include_event_tags=True,
                include_event_uuid=True,
                limit=10,
            )
            events = []
            if isinstance(results, dict) and "Attribute" in results:
                for attr in results["Attribute"]:
                    if "Event" in attr:
                        events.append(attr["Event"])
            return events
        except Exception as e:
            logger.warning("MISP search failed for %s:%s — %s", ioc_type, ioc_value, e)
            return []

    # -----------------------------------------------------------------------
    # PUBLISHING: Push DRRA incidents to MISP for community sharing
    # -----------------------------------------------------------------------

    def publish_incident(
        self,
        incident: dict,
        distribution: int = DISTRIBUTION_COMMUNITY,
        publish: bool = False,
    ) -> Optional[dict]:
        """
        Create a MISP event from a confirmed DRRA incident.

        Args:
            incident:     DRRA incident dict (from /api/v1/dashboard/incidents)
            distribution: MISP distribution level (default: community)
            publish:      Immediately publish to MISP (default: False — draft only)

        Returns:
            Created MISP event dict, or None on failure.
        """
        event = MISPEvent()
        event.info            = f"DRRA Incident: {incident.get('title', 'Ransomware Detection')}"
        event.distribution    = distribution
        event.threat_level_id = THREAT_LEVEL_MAP.get(incident.get("severity", "high"), 1)
        event.analysis        = 1  # Ongoing
        event.date            = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Tags
        self._add_tag(event, "tlp:amber")
        self._add_tag(event, "ransomware")
        self._add_tag(event, "drra:auto-generated")

        for tech in incident.get("mitre_techniques", []):
            self._add_tag(event, f"mitre-attack:attack-pattern=\"{tech}\"")

        # Attributes
        if src_ip := incident.get("source_ip"):
            attr = MISPAttribute()
            attr.category  = "Network activity"
            attr.type      = "ip-src"
            attr.value     = src_ip
            attr.to_ids    = True
            attr.comment   = "Observed ransomware source IP"
            event.add_attribute(**attr.to_dict())

        if sha256 := incident.get("payload_hash"):
            event.add_attribute(
                category="Payload delivery",
                type="sha256",
                value=sha256,
                to_ids=True,
                comment="Ransomware payload SHA256",
            )

        if ransom_note := incident.get("ransom_note_content"):
            event.add_attribute(
                category="External analysis",
                type="text",
                value=ransom_note[:65536],  # MISP 64KB limit
                to_ids=False,
                comment="Ransom note content (truncated)",
            )

        # Free-text narrative
        narrative = self._build_narrative(incident)
        event.add_attribute(
            category="External analysis",
            type="text",
            value=narrative,
            to_ids=False,
            comment="DRRA auto-generated incident summary",
        )

        try:
            created = self.misp.add_event(event)
            if publish and isinstance(created, MISPEvent):
                self.misp.publish(created)
                logger.info("MISP event published: %s", created.uuid)
            return created.to_dict() if isinstance(created, MISPEvent) else created
        except Exception as e:
            logger.error("Failed to create MISP event: %s", e)
            return None

    # -----------------------------------------------------------------------
    # IOC FEED: Pull active ransomware IOCs from MISP for DRRA blocklist
    # -----------------------------------------------------------------------

    def get_ransomware_ioc_feed(self) -> dict:
        """
        Pull current ransomware IOCs from MISP for DRRA's active blocklist.
        Returns a structured dict of IPs, domains, hashes for VIGIL/SHIELD.
        """
        feed = {"ips": [], "domains": [], "hashes": [], "urls": [], "last_updated": datetime.now(timezone.utc).isoformat()}

        try:
            results = self.misp.search(
                controller="attributes",
                tags=["ransomware"],
                type_attribute=["ip-dst", "ip-src", "domain", "sha256", "md5", "url"],
                to_ids=True,
                published=True,
                limit=1000,
            )
            if isinstance(results, dict):
                for attr in results.get("Attribute", []):
                    atype = attr.get("type", "")
                    value = attr.get("value", "")
                    if atype in ("ip-dst", "ip-src"):
                        feed["ips"].append(value)
                    elif atype == "domain":
                        feed["domains"].append(value)
                    elif atype in ("sha256", "md5"):
                        feed["hashes"].append({"type": atype, "value": value})
                    elif atype == "url":
                        feed["urls"].append(value)
        except Exception as e:
            logger.error("Failed to pull MISP IOC feed: %s", e)

        # Deduplicate
        feed["ips"]     = list(set(feed["ips"]))
        feed["domains"] = list(set(feed["domains"]))
        feed["urls"]    = list(set(feed["urls"]))
        return feed

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _add_tag(self, event: MISPEvent, tag_name: str) -> None:
        tag = MISPTag()
        tag.from_dict(name=tag_name)
        event.add_tag(tag)

    def _is_public_ip(self, ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _build_narrative(self, incident: dict) -> str:
        lines = [
            f"Source: DRRA (Distributed Resilience & Recovery Architecture)",
            f"Incident ID: {incident.get('id', 'N/A')}",
            f"Detected: {incident.get('detected_at', 'N/A')}",
            f"Contained: {incident.get('contained_at', 'N/A')}",
            f"MTTC: {incident.get('mttc_seconds', 'N/A')}s",
            f"Affected Hosts: {', '.join(incident.get('affected_hosts', []))}",
            f"Attack Vector: {incident.get('attack_vector', 'N/A')}",
            f"LLM Summary: {incident.get('llm_summary', 'N/A')}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone: push IOC feed to DRRA VIGIL
# ---------------------------------------------------------------------------

def sync_misp_to_drra():
    """Pull IOC feed from MISP and push to DRRA VIGIL blocklist endpoint."""
    connector = DRRAMISPConnector()
    feed = connector.get_ransomware_ioc_feed()

    resp = requests.post(
        f"{DRRA_API_URL}/api/v1/vigil/ioc-blocklist",
        json=feed,
        timeout=30,
    )
    resp.raise_for_status()
    logger.info(
        "Synced MISP IOC feed to DRRA: %d IPs, %d domains, %d hashes",
        len(feed["ips"]),
        len(feed["domains"]),
        len(feed["hashes"]),
    )
    return feed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sync_misp_to_drra()
