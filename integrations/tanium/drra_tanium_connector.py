"""
DRRA Tanium Integration
Connects DRRA to the Tanium platform for fleet-wide endpoint visibility,
real-time ransomware hunting, and automated remediation via Tanium Threat Response.

Features:
  - Live questions to detect ransomware activity across the fleet
  - Tanium Threat Response: push IOCs and trigger hunts
  - Tanium Deploy: push DRRA agent updates to endpoints
  - Tanium Protect: enforce application control policies post-incident
  - Real-time sensors for entropy monitoring
  - Automated isolation via Tanium Quarantine

Requirements:
  pip install pytan requests

Tanium API Docs: https://docs.tanium.com/platform_user/platform_user/console_rest_api.html

Environment variables:
  TANIUM_URL        Tanium server URL (e.g. https://tanium.yourorg.com)
  TANIUM_API_TOKEN  Tanium API token (Settings → API Tokens)
  DRRA_API_URL      DRRA backend URL
"""

import os
import logging
import json
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

TANIUM_URL       = os.getenv("TANIUM_URL",       "https://tanium.yourorg.com")
TANIUM_API_TOKEN = os.getenv("TANIUM_API_TOKEN", "")
DRRA_API_URL     = os.getenv("DRRA_API_URL",     "http://localhost:8000")


# ---------------------------------------------------------------------------
# Tanium REST API Client
# ---------------------------------------------------------------------------

class TaniumClient:
    """Thin wrapper around the Tanium Platform REST API."""

    def __init__(self):
        if not TANIUM_API_TOKEN:
            raise ValueError("TANIUM_API_TOKEN not set")
        self.base     = TANIUM_URL.rstrip("/")
        self.session  = requests.Session()
        self.session.headers.update({
            "session":      TANIUM_API_TOKEN,
            "Content-Type": "application/json",
        })

    def ask_question(self, question_text: str, timeout: int = 30) -> dict:
        """
        Ask a Tanium question and return results.

        Args:
            question_text: Natural language Tanium question string
            timeout:       Seconds to wait for results (default: 30)

        Returns:
            Parsed results dict with rows.
        """
        payload = {
            "question_text": question_text,
            "timeout_seconds": timeout,
        }
        resp = self.session.post(
            f"{self.base}/api/v2/questions",
            json=payload,
        )
        resp.raise_for_status()
        question_id = resp.json()["data"]["id"]

        # Poll for completion
        import time
        for _ in range(timeout):
            result = self.session.get(
                f"{self.base}/api/v2/result_data/question/{question_id}"
            )
            data = result.json().get("data", {})
            if data.get("result_sets", [{}])[0].get("finished", False):
                return data
            time.sleep(1)
        return {}

    def post_saved_question(self, name: str) -> dict:
        """Run a pre-saved Tanium question by name."""
        resp = self.session.get(
            f"{self.base}/api/v2/saved_questions",
            params={"name": name},
        )
        resp.raise_for_status()
        resources = resp.json().get("data", [])
        if not resources:
            raise ValueError(f"Saved question '{name}' not found")
        return self.ask_question(resources[0]["query_text"])

    def run_package(self, package_name: str, targeting_question: str) -> dict:
        """
        Deploy a Tanium package (action) to endpoints matching a targeting question.
        Used for remediation actions.
        """
        action_payload = {
            "package_spec": {"source_id": package_name},
            "target_group": {"targeting_question": {"query_text": targeting_question}},
        }
        resp = self.session.post(
            f"{self.base}/api/v2/actions",
            json=action_payload,
        )
        resp.raise_for_status()
        return resp.json()

    def get_endpoints(self, filter_str: str = "") -> list[dict]:
        """Get endpoint list, optionally filtered."""
        params = {"filter": filter_str} if filter_str else {}
        resp = self.session.get(f"{self.base}/api/v2/endpoints", params=params)
        resp.raise_for_status()
        return resp.json().get("data", {}).get("endpoints", [])


# ---------------------------------------------------------------------------
# DRRA Tanium Connector
# ---------------------------------------------------------------------------

class DRRATaniumConnector:
    """Integrates DRRA with Tanium for fleet-wide ransomware detection and response."""

    # Pre-defined Tanium questions for ransomware hunting
    HUNT_QUESTIONS = {
        "high_entropy_writes": (
            "Get File Write Entropy[C:\\,0.85,60] from all machines"
        ),
        "vss_deletion_processes": (
            "Get Running Processes[vssadmin.exe,wmic.exe,bcdedit.exe] "
            "containing \"delete\" OR \"shadowcopy\" from all machines"
        ),
        "ransomware_extensions": (
            "Get Files Exist[C:\\Users\\,*.locked,*.encrypted,*.ryk,*.hive,*.lockbit] "
            "from all machines"
        ),
        "ransom_notes": (
            "Get Files Exist[C:\\Users\\,HOW_TO_DECRYPT*,DECRYPT_FILES*,README.TXT,RECOVERY_INSTRUCTIONS*] "
            "from all machines"
        ),
        "lsass_memory_access": (
            "Get LSASS Memory Access Events[last 3600] from all machines "
            "where Running Processes[lsass.exe] exists"
        ),
        "lateral_movement_processes": (
            "Get Running Processes[psexec.exe,psexesvc.exe] from all machines"
        ),
        "cobalt_strike_indicators": (
            "Get Running Processes containing \"beacon\" "
            "OR Network Connections[50050] from all machines"
        ),
        "shadow_copy_count": (
            "Get Shadow Copy Count from all machines"
        ),
        "encrypted_file_count": (
            "Get File Count[C:\\Users\\,*.locked|*.encrypted|*.ryk|*.hive|*.lockbit] "
            "from all machines"
        ),
    }

    def __init__(self):
        self.client = TaniumClient()
        logger.info("Tanium connector initialized for %s", TANIUM_URL)

    # -----------------------------------------------------------------------
    # HUNTING: Fleet-wide ransomware hunt
    # -----------------------------------------------------------------------

    def run_ransomware_hunt(self, hunt_types: list[str] = None) -> dict:
        """
        Run a fleet-wide ransomware hunt using Tanium Live Questions.
        Returns findings organized by indicator type.

        Args:
            hunt_types: List of hunt types to run (default: all).
                        Options: entropy, vss, extensions, notes, lsass,
                                 lateral, cobalt_strike, shadows

        Returns:
            Dict of hunt results, keyed by indicator type.
        """
        type_map = {
            "entropy":       "high_entropy_writes",
            "vss":           "vss_deletion_processes",
            "extensions":    "ransomware_extensions",
            "notes":         "ransom_notes",
            "lsass":         "lsass_memory_access",
            "lateral":       "lateral_movement_processes",
            "cobalt_strike": "cobalt_strike_indicators",
            "shadows":       "shadow_copy_count",
        }

        selected = hunt_types or list(type_map.keys())
        results  = {
            "hunt_started":   datetime.now(timezone.utc).isoformat(),
            "total_endpoints": 0,
            "indicators":     {},
            "affected_hosts": [],
        }

        for hunt_type in selected:
            question_key = type_map.get(hunt_type)
            if not question_key:
                continue

            question = self.HUNT_QUESTIONS[question_key]
            logger.info("Running Tanium hunt: %s", hunt_type)

            try:
                data = self.client.ask_question(question, timeout=60)
                findings = self._parse_hunt_results(data, hunt_type)

                results["indicators"][hunt_type] = findings
                for host in findings.get("affected_hosts", []):
                    if host not in results["affected_hosts"]:
                        results["affected_hosts"].append(host)
            except Exception as e:
                logger.warning("Hunt '%s' failed: %s", hunt_type, e)
                results["indicators"][hunt_type] = {"error": str(e)}

        results["hunt_completed"] = datetime.now(timezone.utc).isoformat()
        results["total_affected"] = len(results["affected_hosts"])

        # Forward to DRRA VIGIL if any affected hosts found
        if results["affected_hosts"]:
            self._forward_hunt_to_drra(results)

        return results

    def _parse_hunt_results(self, data: dict, hunt_type: str) -> dict:
        """Parse Tanium question results into a normalized findings dict."""
        rows        = data.get("result_sets", [{}])[0].get("rows", [])
        findings    = {"count": len(rows), "affected_hosts": [], "details": []}
        null_result = "no results"

        for row in rows:
            columns = row.get("data", [])
            # Each column is a list of values; first is typically hostname/computer name
            hostname = columns[0][0].get("text", "") if columns else ""
            value    = columns[1][0].get("text", "") if len(columns) > 1 else ""

            if value.lower() in (null_result, "", "0", "none"):
                continue

            findings["affected_hosts"].append(hostname)
            findings["details"].append({
                "hostname": hostname,
                "value":    value,
                "type":     hunt_type,
            })

        return findings

    # -----------------------------------------------------------------------
    # ISOLATION: Quarantine endpoints via Tanium Quarantine package
    # -----------------------------------------------------------------------

    def quarantine_host(self, hostname: str, reason: str = "DRRA SHIELD") -> dict:
        """
        Quarantine a host using Tanium's Quarantine package (network isolation).
        Blocks all traffic except Tanium server communication.

        Args:
            hostname: Target hostname or IP
            reason:   Reason for quarantine (audit log)

        Returns:
            Action result dict.
        """
        logger.info("Quarantining host via Tanium: %s", hostname)
        try:
            result = self.client.run_package(
                package_name="Tanium Quarantine",
                targeting_question=f"Get Computer Name from all machines where Computer Name equals \"{hostname}\"",
            )
            return {"success": True, "hostname": hostname, "action_id": result.get("data", {}).get("id")}
        except Exception as e:
            logger.error("Tanium quarantine failed for %s: %s", hostname, e)
            return {"success": False, "hostname": hostname, "error": str(e)}

    def lift_quarantine(self, hostname: str) -> dict:
        """Remove Tanium quarantine from a host (post-recovery)."""
        try:
            result = self.client.run_package(
                package_name="Tanium Remove Quarantine",
                targeting_question=f"Get Computer Name from all machines where Computer Name equals \"{hostname}\"",
            )
            return {"success": True, "hostname": hostname}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # -----------------------------------------------------------------------
    # REMEDIATION: Run cleanup packages on infected hosts
    # -----------------------------------------------------------------------

    def run_ransomware_remediation(self, hostname: str) -> dict:
        """
        Execute DRRA remediation package on an infected host via Tanium Deploy.
        Steps: kill suspicious processes → delete ransomware artifacts → re-enable VSS

        This deploys the 'DRRA Ransomware Remediation' package which must be
        imported into Tanium Content from: tanium/packages/DRRA_Remediation.zip
        """
        remediation_steps = [
            ("DRRA - Kill Ransomware Processes",
             "Terminate known ransomware process patterns"),
            ("DRRA - Re-enable VSS",
             "Re-enable Volume Shadow Copy service and create snapshot"),
            ("DRRA - Deploy VIGIL Agent",
             "Install/update the DRRA VIGIL monitoring agent"),
        ]

        results = []
        for package_name, description in remediation_steps:
            try:
                result = self.client.run_package(
                    package_name=package_name,
                    targeting_question=f"Get Computer Name from all machines where Computer Name equals \"{hostname}\"",
                )
                results.append({
                    "package":     package_name,
                    "description": description,
                    "success":     True,
                    "action_id":   result.get("data", {}).get("id"),
                })
                logger.info("Deployed '%s' to %s", package_name, hostname)
            except Exception as e:
                results.append({
                    "package":     package_name,
                    "description": description,
                    "success":     False,
                    "error":       str(e),
                })

        return {"hostname": hostname, "steps": results}

    # -----------------------------------------------------------------------
    # IOC DISTRIBUTION: Push DRRA IOCs to Tanium Threat Response
    # -----------------------------------------------------------------------

    def push_iocs_to_threat_response(self, iocs: list[dict]) -> dict:
        """
        Push confirmed DRRA IOCs to Tanium Threat Response for fleet-wide scanning.

        Args:
            iocs: List of dicts with keys: type (hash|ip|domain|file), value, description

        Returns:
            Result dict.
        """
        pushed = 0
        errors = []

        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            value    = ioc.get("value", "")

            # Map to Tanium Threat Response IOC type
            tanium_type = {
                "sha256":  "file_hash",
                "md5":     "file_hash",
                "ip":      "ip_address",
                "domain":  "domain",
                "file":    "file_name",
            }.get(ioc_type)

            if not tanium_type:
                continue

            payload = {
                "type":        tanium_type,
                "value":       value,
                "description": ioc.get("description", "DRRA confirmed ransomware IOC"),
                "source":      "DRRA",
                "tags":        ["ransomware", "drra-auto"],
            }

            try:
                resp = self.client.session.post(
                    f"{TANIUM_URL}/api/v2/threat_response/intel/documents",
                    json=payload,
                )
                resp.raise_for_status()
                pushed += 1
            except Exception as e:
                errors.append(f"{ioc_type}:{value} — {e}")

        logger.info("Pushed %d IOCs to Tanium Threat Response (%d errors)", pushed, len(errors))
        return {"pushed": pushed, "errors": errors}

    # -----------------------------------------------------------------------
    # CONTINUOUS MONITORING: Scheduled sensor query
    # -----------------------------------------------------------------------

    def get_endpoint_risk_summary(self) -> list[dict]:
        """
        Run rapid fleet assessment questions and return a risk-ranked list
        of endpoints for DRRA Dashboard integration.
        """
        # Shadow copy counts (low count = higher risk)
        shadow_data = self.client.ask_question(
            "Get Shadow Copy Count and Computer Name from all machines"
        )

        # Encrypted file indicators
        encrypted_data = self.client.ask_question(
            "Get File Count[C:\\Users\\,*.locked|*.ryk|*.hive] and Computer Name from all machines"
        )

        risk_map: dict[str, dict] = {}

        for row in shadow_data.get("result_sets", [{}])[0].get("rows", []):
            cols     = row.get("data", [])
            hostname = cols[0][0]["text"] if cols else ""
            shadows  = int(cols[1][0]["text"]) if len(cols) > 1 else 0
            risk_map.setdefault(hostname, {})["shadow_count"]  = shadows
            risk_map[hostname]["shadow_risk"] = "high" if shadows == 0 else "low"

        for row in encrypted_data.get("result_sets", [{}])[0].get("rows", []):
            cols     = row.get("data", [])
            hostname = cols[0][0]["text"] if cols else ""
            count    = int(cols[1][0]["text"]) if len(cols) > 1 else 0
            risk_map.setdefault(hostname, {})["encrypted_file_count"] = count
            if count > 0:
                risk_map[hostname]["encrypted_risk"] = "critical"

        return [
            {"hostname": h, **v}
            for h, v in sorted(risk_map.items(), key=lambda x: x[1].get("encrypted_file_count", 0), reverse=True)
        ]

    # -----------------------------------------------------------------------
    # Internal: forward hunt findings to DRRA VIGIL
    # -----------------------------------------------------------------------

    def _forward_hunt_to_drra(self, hunt_results: dict) -> None:
        for host in hunt_results["affected_hosts"]:
            indicators = {
                k: v for k, v in hunt_results["indicators"].items()
                if host in v.get("affected_hosts", [])
            }
            event = {
                "source":     "tanium_hunt",
                "event_type": "entropy_spike" if "entropy" in indicators else "mass_modification",
                "timestamp":  hunt_results["hunt_completed"],
                "hostname":   host,
                "severity":   "high",
                "confidence": 0.85,
                "metadata":   {"tanium_indicators": indicators},
            }
            try:
                requests.post(
                    f"{DRRA_API_URL}/api/v1/vigil/events",
                    json=event,
                    timeout=5,
                )
            except Exception as e:
                logger.warning("Could not forward Tanium hunt result to DRRA: %s", e)
