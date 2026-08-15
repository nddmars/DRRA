"""
Dashboard routes — MTTC tracker, Defensibility Index, configuration.

All operational numbers here are derived from ``metrics_store`` (what the system
actually measured) via the canonical Defensibility Index engine. When no
incidents have been recorded yet the endpoints return honest zeros rather than
fabricated demo values.
"""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

from config import settings
from models.schemas import (
    DefensibilityIndex,
    IncidentMetrics,
    SystemHealth,
    DashboardSummary,
    DetectionEvent,
    ThreatLevel,
)
from services.defensibility import IncidentRecord
from services.metrics_store import metrics_store

router = APIRouter()


class IncidentOutcomeRequest(BaseModel):
    """A closed incident's measured outcome, reported by SHIELD/GRAB.

    Recording an outcome here is what feeds the Defensibility Index — these are
    measurements from a real (or replayed) incident, not display values.
    """

    incident_id: str
    detected: bool = True
    true_positive: bool = True
    mttd_seconds: float = Field(0.0, ge=0.0)
    mttc_seconds: float = Field(0.0, ge=0.0)
    apcr: float = Field(0.0, ge=0.0, le=1.0)
    recovery_fidelity: float = Field(1.0, ge=0.0, le=1.0)
    immutability_intact: bool = True
    scenario: str = ""


@router.post("/incidents")
async def record_incident(outcome: IncidentOutcomeRequest):
    """Record a closed incident's outcome into the Defensibility Index engine."""
    metrics_store.record_incident(
        IncidentRecord(
            incident_id=outcome.incident_id,
            detected=outcome.detected,
            true_positive=outcome.true_positive,
            mttd_seconds=outcome.mttd_seconds,
            mttc_seconds=outcome.mttc_seconds,
            apcr=outcome.apcr,
            recovery_fidelity=outcome.recovery_fidelity,
            immutability_intact=outcome.immutability_intact,
            scenario=outcome.scenario,
        )
    )
    result = metrics_store.defensibility()
    return {
        "status": "recorded",
        "incident_id": outcome.incident_id,
        "defensibility_index": result.as_dict()["defensibility_index"],
        "sample_size": result.sample_size,
    }


def _threat_level(value: str) -> ThreatLevel:
    try:
        return ThreatLevel(value)
    except ValueError:
        return ThreatLevel.LOW


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary():
    """Complete dashboard summary computed from recorded incident metrics."""
    summary = metrics_store.summary()
    di = summary["defensibility"]
    comp = di["components"]
    total = summary["incidents_total"]

    metrics = IncidentMetrics(
        total_incidents=total,
        active_incidents=0,
        total_files_affected=0,
        files_recovered=summary["incidents_fully_recovered"],
        mttc_average=round(summary["mttc_seconds"], 2),
        mttc_target=float(settings.MTTC_TARGET_SECONDS),
        mttc_achieved=(total > 0 and summary["mttc_seconds"] <= settings.MTTC_TARGET_SECONDS),
        containment_success_rate=round(comp["containment"], 4),
        data_loss_percentage=round((1.0 - summary["recovery_fidelity"]) * 100, 2),
    )

    defensibility = DefensibilityIndex(
        overall_score=di["score_0_100"],
        detection_score=int(round(comp["detection"] * 100)),
        isolation_score=int(round(comp["containment"] * 100)),
        recovery_score=int(round(comp["recovery"] * 100)),
        immutability_score=int(round(comp["prevention"] * 100)),
        timestamp=datetime.now(timezone.utc),
        community_percentile=None,
    )

    health = SystemHealth(
        status="healthy" if total else "idle",
        components={
            "vigil": "healthy",
            "shield": "operational",
            "grab": "healthy",
            "storage": "healthy" if getattr(metrics_store, "_di", None) else "unknown",
        },
        last_heartbeat=datetime.now(timezone.utc),
        uptime_seconds=0,
    )

    recent = metrics_store.snapshot()[-5:]
    recent_events = [
        DetectionEvent(
            event_id=i.incident_id,
            timestamp=datetime.now(timezone.utc),
            threat_type=i.scenario or "behavioral_anomaly",
            threat_level=ThreatLevel.CRITICAL if i.apcr > 0.5 else ThreatLevel.HIGH,
            affected_path="n/a",
            file_count=0,
            entropy_score=0.0,
            confidence=1.0 if i.true_positive else 0.5,
            details={"mttc_seconds": i.mttc_seconds, "apcr": i.apcr},
        )
        for i in recent
    ]

    return DashboardSummary(
        metrics=metrics,
        defensibility_index=defensibility,
        system_health=health,
        recent_events=recent_events,
        active_incidents=0,
    )


@router.get("/metrics/mttc")
async def get_mttc_metrics():
    """Mean Time to Contain, measured from recorded incidents."""
    summary = metrics_store.summary()
    mttc = summary["mttc_seconds"]
    target = float(settings.MTTC_TARGET_SECONDS)
    return {
        "current_mttc": round(mttc, 2),
        "target_mttc": target,
        "status": "beating_target" if (summary["incidents_total"] and mttc <= target) else "no_data"
        if not summary["incidents_total"]
        else "over_target",
        "sample_size": summary["incidents_total"],
        "details": {
            "mttd_seconds": round(summary["mttd_seconds"], 2),
            "mttc_seconds": round(mttc, 2),
            "false_positive_rate": round(summary["false_positive_rate"], 4),
        },
    }


@router.get("/defensibility-index")
async def get_defensibility_index():
    """Current Defensibility Index and component scores (measured)."""
    result = metrics_store.defensibility()
    d = result.as_dict()
    comp = d["components"]
    weights = d["weights"]
    di_score = d["score_0_100"]
    rank = (
        "A (Excellent)" if di_score >= 90 else
        "B (Strong)" if di_score >= 75 else
        "C (Adequate)" if di_score >= 60 else
        "D (At Risk)" if di_score > 0 else
        "N/A (no data)"
    )
    return {
        "defensibility_index": d["defensibility_index"],
        "overall_score": di_score,
        "max_score": 100,
        "rank": rank,
        "sample_size": d["sample_size"],
        "components": {
            "detection": {"score": comp["detection"], "weight": weights["detection"],
                          "description": "MTTD efficiency (1 - MTTD/T_drrt)"},
            "containment": {"score": comp["containment"], "weight": weights["containment"],
                            "description": "MTTC efficiency (1 - MTTC/90s)"},
            "prevention": {"score": comp["prevention"], "weight": weights["prevention"],
                           "description": "Prevention (1 - APCR)"},
            "recovery": {"score": comp["recovery"], "weight": weights["recovery"],
                         "description": "Recovery fidelity"},
        },
        "metrics": d["metrics"],
    }


@router.get("/config")
async def get_configuration():
    """Current system configuration and thresholds (reflects live settings)."""
    return {
        "thresholds": {
            "mass_modification_rate": settings.MASS_MODIFICATION_THRESHOLD,
            "entropy_threshold": settings.ENTROPY_THRESHOLD,
            "vigil_decision_threshold": settings.VIGIL_DECISION_THRESHOLD,
            "mttc_target_seconds": settings.MTTC_TARGET_SECONDS,
        },
        "defensibility_weights": {
            "detection": settings.DI_WEIGHT_DETECTION,
            "containment": settings.DI_WEIGHT_ISOLATION,
            "prevention": settings.DI_WEIGHT_RECOVERY,
            "recovery": settings.DI_WEIGHT_IMMUTABILITY,
        },
    }


@router.get("/incidents")
async def list_incidents(limit: int = 50):
    """List recorded incidents."""
    incidents = metrics_store.snapshot()[-limit:]
    return {
        "total_incidents": len(metrics_store.snapshot()),
        "incidents": [
            {
                "incident_id": i.incident_id,
                "scenario": i.scenario,
                "timestamp": i.timestamp,
                "mttd_seconds": i.mttd_seconds,
                "mttc_seconds": i.mttc_seconds,
                "apcr": i.apcr,
                "recovery_fidelity": i.recovery_fidelity,
                "true_positive": i.true_positive,
            }
            for i in incidents
        ],
    }


@router.get("/status")
async def dashboard_status():
    """Dashboard operational status."""
    return {
        "status": "operational",
        "sample_size": len(metrics_store.snapshot()),
        "components": {
            "metrics_collection": "healthy",
            "defensibility_engine": "healthy",
        },
    }
