# DRRA Canonical Incident-Event Schema

**Version:** 1.0.0 · **Status:** Draft for review · **Last updated:** 2026-08-16

This document specifies the single versioned event envelope that every DRRA
producer emits and every consumer reads (DRRA-002). The machine-readable
contract is `schemas/incident_event.schema.json`; the runtime model is
`backend/models/incident_event.py`; the two are kept in lockstep by
`tests/test_incident_event_schema.py`.

## Why

DRRA grew three unrelated event vocabularies:

| Producer | Shape | Location |
|---|---|---|
| Rust endpoint watcher | `FileModificationEvent` (`event_id`, `timestamp`, `file_path`, `event_type`, `file_size`, `entropy_score`, `source`) | `watchers/src/lib.rs` |
| OTRF / Sysmon ingest | per-window IoB features (`file_rename_rate`, `lateral_movement_score`, `privilege_escalation`, `shadow_copy_deletion_rate`) | `vigil/ingest.py` |
| Backend API | `DetectionEvent`, `TelemetryEvent`, `BehaviorPattern` | `backend/models/schemas.py` |

They disagree on field names, timestamp formats, and severity. Every consumer —
the detector, the dashboard, the audit trail, external integrations — has to
special-case each producer, and there is no shared contract to test against.
This blocks dedup/backpressure (DRRA-013), tamper-evident audit (DRRA-007),
observability (DRRA-059), and stable API contracts (DRRA-062), all of which need
one event vocabulary underneath them.

## The envelope

The canonical event is an envelope with a required core and optional,
producer-populated detail. Full field definitions live in the JSON Schema; the
required core is:

| Field | Meaning |
|---|---|
| `schema_version` | Envelope version (`1.0.0`); consumers reject unknown major versions |
| `event_id` | Globally unique id (UUID recommended) |
| `occurred_at` | RFC 3339 source-clock time of the observed activity |
| `producer` | `{ component, instance_id?, version? }` — what emitted it |
| `category` | Coarse class: `file_activity`, `process`, `network`, `authentication`, `privilege`, `recovery_inhibition`, `detection`, `containment`, `recovery`, `telemetry` |
| `action` | Specific action within the category (`create`, `modify`, `logon`, `contain`, …) |
| `severity` | Normalised `info` / `low` / `medium` / `high` / `critical` |

Optional detail: `ingested_at` (receiver clock, for skew accounting — DRRA-008),
`host`, `subject` (the entity acted on), `signals` (stable numeric keys shared
across producers), `labels` (free-form tags, never used for authorization), and
`raw_ref` (a pointer back to the untransformed source event for chain of custody
— DRRA-043). `additionalProperties: false` is enforced at every level so a
producer cannot smuggle un-adapted vendor fields into the canonical stream.

## Migration via adapters

Producers are migrated incrementally. Each producer gets an **adapter** that maps
its native event onto the envelope; consumers only ever read the envelope. The
first adapter — `from_watcher_event()` in `backend/models/incident_event.py` —
maps the Rust watcher's `FileModificationEvent`:

- `event_type` → `action`, with `category = file_activity`
- `file_path` → `subject.file_path`
- `entropy_score`, `file_size` → `signals`
- entropy ≥ the backend encryption threshold (0.85) → `severity = high`
- original event preserved in `raw_ref` for forensics

The contract test proves this adapter yields a schema-valid canonical event and
round-trips through JSON without loss.

## Status (honest)

**Implemented:** the versioned schema, the runtime model, the watcher adapter,
and the contract test that binds them.

**Remaining (tracked):** wiring the OTRF ingest and the backend API models onto
the envelope, emitting canonical events from the live pipeline end to end, and
consumer-side contract tests for the dashboard/audit/integrations. Those land
with DRRA-013 / DRRA-007 / DRRA-059 / DRRA-062. Until a producer's adapter and
tests exist, it is not considered migrated.

## Versioning and compatibility

Semantic versioning. Additive, optional fields are a minor bump and backward
compatible. Removing/renaming a field or changing `required` is a major bump;
consumers reject an envelope whose major version they do not implement. The
version constant is asserted equal between the JSON Schema and the runtime model
by the contract test, so the published schema and the code cannot diverge.
