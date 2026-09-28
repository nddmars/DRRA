"""
DRRA-002 — Contract tests for the canonical incident-event envelope.

These bind three things together so they cannot drift apart:
  1. the published JSON Schema (schemas/incident_event.schema.json),
  2. the runtime pydantic model (backend/models/incident_event.py), and
  3. a real producer's payload (the Rust watcher's FileModificationEvent).

No third-party JSON-Schema validator is required: pydantic (already a core
dependency) is the runtime validator, and the JSON Schema is cross-checked
structurally against the pydantic model's own generated schema.
"""

from __future__ import annotations

import json
import os
import sys

# Make backend/ importable the same way the app does.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_REPO, os.path.join(_REPO, "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.models.incident_event import (  # noqa: E402
    Category,
    IncidentEvent,
    SCHEMA_VERSION,
    Severity,
    from_watcher_event,
)

SCHEMA_PATH = os.path.join(_REPO, "schemas", "incident_event.schema.json")


def _load_schema() -> dict:
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def test_schema_file_is_present_and_wellformed():
    schema = _load_schema()
    assert schema["type"] == "object"
    assert schema["properties"], "schema declares no properties"


def test_version_constant_matches_published_schema():
    schema = _load_schema()
    const = schema["properties"]["schema_version"]["const"]
    assert const == SCHEMA_VERSION, (
        f"SCHEMA_VERSION={SCHEMA_VERSION!r} but schema const={const!r}"
    )


def test_model_and_schema_property_names_agree():
    schema = _load_schema()
    schema_props = set(schema["properties"])
    model_props = set(IncidentEvent.model_fields)
    assert schema_props == model_props, (
        f"model/schema property drift: only-in-schema={schema_props - model_props}, "
        f"only-in-model={model_props - schema_props}"
    )


def test_required_fields_agree():
    schema = _load_schema()
    schema_required = set(schema["required"])
    model_required = {
        name for name, f in IncidentEvent.model_fields.items() if f.is_required()
    }
    # schema_version is required-with-a-const in JSON Schema but has a default in
    # the model; that is the single intentional difference.
    assert schema_required - model_required == {"schema_version"}
    assert model_required - schema_required == set()


def test_category_enum_matches_schema():
    schema = _load_schema()
    schema_cats = set(schema["properties"]["category"]["enum"])
    model_cats = {c.value for c in Category}
    assert schema_cats == model_cats


def test_severity_enum_matches_schema():
    schema = _load_schema()
    schema_sev = set(schema["properties"]["severity"]["enum"])
    model_sev = {s.value for s in Severity}
    assert schema_sev == model_sev


def _watcher_payload(**overrides) -> dict:
    evt = {
        "event_id": "11111111-2222-3333-4444-555555555555",
        "timestamp": "2026-08-16T12:00:00.000000+00:00",
        "file_path": "/data/reports/q3.xlsx",
        "event_type": "modify",
        "file_size": 40960,
        "entropy_score": 0.97,
        "source": "file_watcher",
    }
    evt.update(overrides)
    return evt


def test_watcher_adapter_produces_valid_canonical_event():
    evt = from_watcher_event(_watcher_payload())
    assert isinstance(evt, IncidentEvent)
    assert evt.schema_version == SCHEMA_VERSION
    assert evt.category == Category.FILE_ACTIVITY
    assert evt.action == "modify"
    assert evt.subject.file_path == "/data/reports/q3.xlsx"
    assert evt.signals.entropy_score == 0.97
    # high entropy on a write surfaces as high severity
    assert evt.severity == Severity.HIGH
    # forensic pointer back to the raw producer event is preserved
    assert evt.raw_ref.source_schema == "watcher.FileModificationEvent"
    assert evt.raw_ref.source_event_id == evt.event_id


def test_watcher_adapter_low_entropy_is_info():
    evt = from_watcher_event(_watcher_payload(entropy_score=0.10, event_type="create"))
    assert evt.severity == Severity.INFO
    assert evt.action == "create"


def test_watcher_adapter_rejects_unknown_event_type():
    try:
        from_watcher_event(_watcher_payload(event_type="teleport"))
    except ValueError as exc:
        assert "unknown watcher event_type" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown event_type")


def test_canonical_event_roundtrips_through_json():
    evt = from_watcher_event(_watcher_payload())
    dumped = evt.model_dump_json()
    restored = IncidentEvent.model_validate_json(dumped)
    assert restored == evt


def test_no_unknown_top_level_keys_allowed_by_schema():
    # additionalProperties:false is the guard that stops producers from smuggling
    # un-adapted vendor fields into the canonical stream.
    schema = _load_schema()
    assert schema.get("additionalProperties") is False
