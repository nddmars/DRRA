#!/usr/bin/env python3
"""
DRRA Splunk Add-on: VIGIL Events Scripted Input
Polls the DRRA VIGIL API and writes events to Splunk via stdout.

Runs every 30 seconds (configured in inputs.conf).
Persists a checkpoint file to avoid re-indexing events.
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration (set via Splunk Add-on Builder or environment)
# ---------------------------------------------------------------------------

DRRA_API_URL    = os.getenv("DRRA_API_URL",  "http://localhost:8000")
DRRA_API_KEY    = os.getenv("DRRA_API_KEY",  "")
CHECKPOINT_FILE = Path(os.getenv("SPLUNK_HOME", "/opt/splunk")) / "var/lib/splunk/modinputs/drra_vigil_checkpoint.txt"
LOOKBACK_MINUTES = int(os.getenv("DRRA_LOOKBACK_MINUTES", "2"))

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s drra_vigil_events: %(message)s",
)


def load_checkpoint() -> str:
    """Load last seen event timestamp from checkpoint file."""
    try:
        if CHECKPOINT_FILE.exists():
            return CHECKPOINT_FILE.read_text().strip()
    except Exception:
        pass
    # Default: look back LOOKBACK_MINUTES
    since = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
    return since.isoformat()


def save_checkpoint(timestamp: str) -> None:
    try:
        CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
        CHECKPOINT_FILE.write_text(timestamp)
    except Exception as e:
        logging.warning("Could not save checkpoint: %s", e)


def fetch_events(since: str) -> list[dict]:
    headers = {"Content-Type": "application/json"}
    if DRRA_API_KEY:
        headers["X-API-Key"] = DRRA_API_KEY

    try:
        resp = requests.get(
            f"{DRRA_API_URL}/api/v1/vigil/events",
            params={"since": since, "limit": 500},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("events", [])
    except Exception as e:
        logging.error("Failed to fetch VIGIL events: %s", e)
        return []


def emit_splunk_event(event: dict) -> None:
    """Write event to stdout in Splunk key=value or JSON format."""
    # Splunk scripted inputs: write one JSON event per line to stdout
    # Splunk will parse with the configured sourcetype (drra:vigil → json extraction)
    print(json.dumps(event))


def main():
    since = load_checkpoint()
    events = fetch_events(since)

    if not events:
        return

    latest_ts = since
    for event in events:
        emit_splunk_event(event)
        ts = event.get("timestamp", "")
        if ts > latest_ts:
            latest_ts = ts

    save_checkpoint(latest_ts)


if __name__ == "__main__":
    main()
