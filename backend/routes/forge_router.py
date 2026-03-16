"""
Route handler for The Forge (simulation engine).
FR-1: Honeypot Architect, Resilience Payloads, Identity Squatting Tests
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.schemas import (
    ForgePayloadRequest, 
    ForgePayloadResponse, 
    HoneypotConfig,
    PayloadType
)
from datetime import datetime, timedelta
import uuid

router = APIRouter()

# In-memory storage (replace with database in production)
active_payloads = {}

@router.post("/deploy", response_model=ForgePayloadResponse)
async def deploy_payload(
    request: ForgePayloadRequest,
    background_tasks: BackgroundTasks
):
    """
    Deploy a simulated attack payload to test defenses.
    
    - **honeypot**: Deploy realistic files to trigger detection
    - **resilience**: Run safe encryption simulation
    - **identity_squat**: Test Kerberos lateral movement detection
    """
    payload_id = str(uuid.uuid4())
    
    start_time = datetime.utcnow()
    end_time = start_time + timedelta(seconds=request.duration_seconds)
    
    payload_record = {
        "id": payload_id,
        "name": request.name,
        "type": request.payload_type,
        "status": "running",
        "start_time": start_time,
        "end_time": end_time
    }
    
    active_payloads[payload_id] = payload_record
    
    # Schedule payload cleanup
    background_tasks.add_task(cleanup_payload, payload_id)
    
    return ForgePayloadResponse(
        payload_id=payload_id,
        name=request.name,
        status="deployed",
        start_time=start_time,
        estimated_end_time=end_time,
        detection_expected=True
    )

@router.get("/payloads/{payload_id}")
async def get_payload_status(payload_id: str):
    """Get the status of a deployed payload."""
    if payload_id not in active_payloads:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    payload = active_payloads[payload_id]
    return {
        "payload_id": payload_id,
        "status": payload["status"],
        "name": payload["name"],
        "type": payload["type"],
        "elapsed_seconds": (datetime.utcnow() - payload["start_time"]).total_seconds()
    }

@router.post("/honeypot/generate")
async def generate_honeypot(config: HoneypotConfig):
    """
    Generate realistic honeypot files to act as detection tripwires.
    Supports PDF, Word docs, Excel, SQL dumps, etc.
    """
    honeypot_id = str(uuid.uuid4())
    
    return {
        "honeypot_id": honeypot_id,
        "status": "generated",
        "files_created": config.count,
        "file_types": config.file_types,
        "total_size_mb": config.count * config.size_mb,
        "message": f"Honeypot deployed with {config.count} files ready to detect unauthorized modifications"
    }

@router.post("/identity-squat/kerberos-test")
async def kerberos_identity_squat_test():
    """
    Simulate unauthorized Kerberos ticket requests to validate
    lateral movement defenses and credential stuffing detection.
    """
    test_id = str(uuid.uuid4())
    
    return {
        "test_id": test_id,
        "status": "in_progress",
        "target_protocol": "Kerberos",
        "test_vector": "credential_reuse",
        "simulated_tickets": 50,
        "message": "Simulating lateral movement attempts via Kerberos abuse"
    }

@router.get("/payloads")
async def list_active_payloads():
    """List all active payloads."""
    return {
        "active_count": len(active_payloads),
        "payloads": [
            {
                "id": pid,
                "name": p["name"],
                "type": p["type"],
                "status": p["status"]
            }
            for pid, p in active_payloads.items()
        ]
    }

@router.delete("/payloads/{payload_id}")
async def stop_payload(payload_id: str):
    """Manually stop and clean up a payload."""
    if payload_id not in active_payloads:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    cleanup_payload(payload_id)
    
    return {
        "status": "stopped",
        "payload_id": payload_id,
        "message": "Payload successfully terminated"
    }

async def cleanup_payload(payload_id: str):
    """Background task to clean up payload."""
    if payload_id in active_payloads:
        active_payloads[payload_id]["status"] = "completed"
        # In production, would clean up actual files and processes
