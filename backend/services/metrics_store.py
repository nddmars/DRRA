"""
In-process operational metrics store.

Services (VIGIL, SHIELD, GRAB) record measured incident outcomes here; the
dashboard reads aggregates from here. This replaces the hard-coded literals that
previously lived in the dashboard routes (MTTC 45.3, DI 87, ...) with values
derived from what the system actually did.

The store is intentionally simple and thread-safe. It is an in-memory ring
buffer suitable for a single backend process; in a multi-replica deployment the
same aggregation runs off the PostgreSQL ``incidents`` table (see
``DatabaseManager``), and this store acts as a hot cache. It is not a
persistence layer.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

from services.defensibility import (
    DefensibilityIndex,
    DefensibilityResult,
    IncidentRecord,
)


class MetricsStore:
    def __init__(self, maxlen: int = 5000) -> None:
        self._incidents: Deque[IncidentRecord] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._di = DefensibilityIndex()
        # Pending timers keyed by incident_id for live MTTD/MTTC measurement.
        self._attack_start: Dict[str, float] = {}
        self._detected_at: Dict[str, float] = {}

    # -- live timing helpers --------------------------------------------------
    def mark_attack_start(self, incident_id: str, ts: Optional[float] = None) -> None:
        with self._lock:
            self._attack_start[incident_id] = ts if ts is not None else _now()

    def mark_detected(self, incident_id: str, ts: Optional[float] = None) -> float:
        """Record detection time; returns MTTD seconds if attack start known."""
        t = ts if ts is not None else _now()
        with self._lock:
            self._detected_at[incident_id] = t
            start = self._attack_start.get(incident_id)
        return max(0.0, t - start) if start is not None else 0.0

    def mark_contained(self, incident_id: str, ts: Optional[float] = None) -> float:
        """Return MTTC seconds (detection → containment)."""
        t = ts if ts is not None else _now()
        with self._lock:
            detected = self._detected_at.get(incident_id)
        return max(0.0, t - detected) if detected is not None else 0.0

    # -- outcome recording ----------------------------------------------------
    def record_incident(self, incident: IncidentRecord) -> None:
        with self._lock:
            if not incident.timestamp:
                incident.timestamp = datetime.now(timezone.utc).isoformat()
            self._incidents.append(incident)
            self._attack_start.pop(incident.incident_id, None)
            self._detected_at.pop(incident.incident_id, None)

    # -- aggregates for the dashboard ----------------------------------------
    def snapshot(self) -> List[IncidentRecord]:
        with self._lock:
            return list(self._incidents)

    def defensibility(self) -> DefensibilityResult:
        return self._di.score_incidents(self.snapshot())

    def summary(self) -> Dict:
        incidents = self.snapshot()
        result = self._di.score_incidents(incidents)
        total = len(incidents)
        active = sum(1 for i in incidents if not i.immutability_intact)  # placeholder heuristic
        recovered = sum(1 for i in incidents if i.recovery_fidelity >= 0.999)
        return {
            "sample_size": total,
            "defensibility": result.as_dict(),
            "mttc_seconds": result.mttc_seconds,
            "mttd_seconds": result.mttd_seconds,
            "false_positive_rate": result.false_positive_rate,
            "apcr": result.apcr,
            "recovery_fidelity": result.recovery_fidelity,
            "incidents_total": total,
            "incidents_fully_recovered": recovered,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()
            self._attack_start.clear()
            self._detected_at.clear()


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


# Process-wide singleton used by the routers/services.
metrics_store = MetricsStore()
