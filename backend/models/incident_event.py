"""
DRRA-002 — Canonical incident-event envelope.

DRRA currently has three unrelated event vocabularies:

  * the Rust watcher's ``FileModificationEvent`` (watchers/src/lib.rs),
  * the OTRF/Sysmon ingest features (vigil/ingest.py), and
  * the backend's ``DetectionEvent`` / ``TelemetryEvent`` (backend/models/schemas.py).

They do not agree on field names, timestamps, or severity, so every consumer
(detector, dashboard, audit, integrations) has to special-case each producer.
This module defines the ONE versioned envelope they all map onto, mirroring
``schemas/incident_event.schema.json``. Producers are migrated onto it
incrementally; the ``from_watcher_event`` adapter below is the first migration
and demonstrates that the envelope losslessly carries a real producer's data.

The pydantic model and the JSON Schema are kept in lockstep by
``tests/test_incident_event_schema.py`` (contract test), so the published
schema and the runtime model cannot silently diverge.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, Field

# Semantic version of the envelope. MUST match the ``const`` in
# schemas/incident_event.schema.json (enforced by the contract test).
SCHEMA_VERSION = "1.0.0"


class Component(str, Enum):
    WATCHER = "watcher"
    VIGIL = "vigil"
    SHIELD = "shield"
    GRAB = "grab"
    FORGE = "forge"
    INGEST = "ingest"
    INTEGRATION = "integration"


class Category(str, Enum):
    FILE_ACTIVITY = "file_activity"
    PROCESS = "process"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PRIVILEGE = "privilege"
    RECOVERY_INHIBITION = "recovery_inhibition"
    DETECTION = "detection"
    CONTAINMENT = "containment"
    RECOVERY = "recovery"
    TELEMETRY = "telemetry"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Producer(BaseModel):
    component: Component
    instance_id: Optional[str] = None
    version: Optional[str] = None


class Host(BaseModel):
    hostname: Optional[str] = None
    host_id: Optional[str] = None
    source: Optional[str] = None


class Subject(BaseModel):
    file_path: Optional[str] = None
    process_image: Optional[str] = None
    command_line: Optional[str] = None
    target_image: Optional[str] = None
    user: Optional[str] = None
    destination_port: Optional[int] = None


class Signals(BaseModel):
    entropy_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    file_size: Optional[int] = Field(default=None, ge=0)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    file_rename_rate: Optional[float] = Field(default=None, ge=0.0)
    lateral_movement_score: Optional[float] = Field(default=None, ge=0.0)
    privilege_escalation: Optional[float] = Field(default=None, ge=0.0)
    shadow_copy_deletion_rate: Optional[float] = Field(default=None, ge=0.0)


class RawRef(BaseModel):
    source_schema: Optional[str] = None
    source_event_id: Optional[str] = None


class IncidentEvent(BaseModel):
    """The canonical DRRA incident event (schema version SCHEMA_VERSION)."""

    schema_version: str = Field(default=SCHEMA_VERSION)
    event_id: str = Field(min_length=1)
    occurred_at: datetime
    ingested_at: Optional[datetime] = None
    producer: Producer
    host: Optional[Host] = None
    category: Category
    action: str = Field(min_length=1)
    severity: Severity
    subject: Optional[Subject] = None
    signals: Optional[Signals] = None
    labels: Optional[Dict[str, str]] = None
    raw_ref: Optional[RawRef] = None


# --- producer adapters ------------------------------------------------------

# The watcher emits a compact event_type; map it to the canonical action while
# keeping the category coarse (all four are file activity from the endpoint).
_WATCHER_ACTIONS = {"create", "modify", "remove", "rename"}


def from_watcher_event(evt: Dict) -> IncidentEvent:
    """Map a Rust-watcher ``FileModificationEvent`` (as posted to
    ``/api/v1/vigil/events``) onto the canonical envelope.

    High file entropy on a write is the endpoint's ransomware signal, so an
    entropy at/above the backend's encryption threshold is surfaced as ``high``
    severity; everything else is ``info`` until the detector scores it.
    """
    action = str(evt.get("event_type", "")).lower()
    if action not in _WATCHER_ACTIONS:
        raise ValueError(f"unknown watcher event_type: {evt.get('event_type')!r}")

    entropy = evt.get("entropy_score")
    severity = Severity.HIGH if (entropy is not None and entropy >= 0.85) else Severity.INFO

    ts = evt.get("timestamp")
    occurred_at = _parse_ts(ts) if ts else datetime.now(timezone.utc)

    return IncidentEvent(
        event_id=str(evt["event_id"]),
        occurred_at=occurred_at,
        producer=Producer(component=Component.WATCHER, instance_id=evt.get("source")),
        category=Category.FILE_ACTIVITY,
        action=action,
        severity=severity,
        subject=Subject(file_path=evt.get("file_path")),
        signals=Signals(
            entropy_score=entropy,
            file_size=evt.get("file_size"),
        ),
        raw_ref=RawRef(
            source_schema="watcher.FileModificationEvent",
            source_event_id=str(evt.get("event_id")),
        ),
    )


def _parse_ts(value: str) -> datetime:
    """Parse an RFC 3339 timestamp (the watcher emits ``chrono::Utc::rfc3339``)."""
    v = str(value).strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    return datetime.fromisoformat(v)
