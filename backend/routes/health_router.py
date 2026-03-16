"""
Route handler for health checks and system status.
"""

from fastapi import APIRouter
from datetime import datetime
from models.schemas import SystemHealth

router = APIRouter()

@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "Resilience Forge (DRRA)"
    }

@router.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe."""
    return {
        "ready": True,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe."""
    return {
        "alive": True,
        "timestamp": datetime.utcnow().isoformat()
    }
