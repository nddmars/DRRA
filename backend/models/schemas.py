"""
Pydantic models for Resilience Forge API.
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

# ============================================
# Forge (Simulation) Models
# ============================================

class PayloadType(str, Enum):
    HONEYPOT = "honeypot"
    RESILIENCE = "resilience"
    IDENTITY_SQUAT = "identity_squat"

class ForgePayloadRequest(BaseModel):
    """Request to deploy a simulated attack payload."""
    name: str = Field(..., min_length=1, max_length=100)
    payload_type: PayloadType
    target_path: str = Field(..., description="Target directory for honeypot/payload")
    duration_seconds: int = Field(default=60, ge=10, le=3600)
    intensity: float = Field(default=1.0, ge=0.1, le=10.0, description="Attack simulation intensity")
    
class ForgePayloadResponse(BaseModel):
    """Response from payload deployment."""
    payload_id: str
    name: str
    status: str = "deployed"
    start_time: datetime
    estimated_end_time: datetime
    detection_expected: bool

class HoneypotConfig(BaseModel):
    """Configuration for honeypot file generation."""
    file_types: List[str] = Field(default=["pdf", "docx", "xlsx", "sql"])
    count: int = Field(default=50, ge=1, le=1000)
    size_mb: float = Field(default=1.0, ge=0.1, le=100.0)

# ============================================
# Sentinel (Detection) Models
# ============================================

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionEvent(BaseModel):
    """Detected threat event."""
    event_id: str
    timestamp: datetime
    threat_type: str
    threat_level: ThreatLevel
    affected_path: str
    file_count: int
    entropy_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    details: Dict[str, Any]

class BehaviorPattern(BaseModel):
    """ML-detected behavioral pattern."""
    pattern_id: str
    pattern_name: str
    detection_method: str  # "mass_modification", "entropy", "kerberos", etc.
    confidence: float = Field(ge=0.0, le=1.0)
    affected_processes: List[str]
    affected_files: int

class TelemetryEvent(BaseModel):
    """Immutable telemetry event for logging."""
    event_id: str
    timestamp: datetime
    source: str  # "file_watcher", "network_monitor", "ml_detector", etc.
    event_type: str
    severity: ThreatLevel
    data: Dict[str, Any]

class LLMInsight(BaseModel):
    """LLM-generated analysis of attack."""
    insight_id: str
    threat_summary: str
    attack_vector: str
    recommended_actions: List[str]
    defensibility_gaps: List[str]

# ============================================
# Shield (Recovery & Isolation) Models
# ============================================

class IsolationAction(str, Enum):
    VLAN_ISOLATE = "vlan_isolate"
    NETWORK_QUARANTINE = "network_quarantine"
    PROCESS_KILL = "process_kill"
    FILE_LOCK = "file_lock"

class IsolationRequest(BaseModel):
    """Request to isolate affected resources."""
    resource_id: str
    action: IsolationAction
    reason: str
    preserve_logs: bool = True

class IsolationResponse(BaseModel):
    """Response to isolation request."""
    isolation_id: str
    status: str = "in_progress"
    action: IsolationAction
    resources_affected: int
    estimated_isolation_time: float

class RecoveryTask(BaseModel):
    """Automated recovery operation."""
    task_id: str
    status: str  # "pending", "in_progress", "completed", "failed"
    recovery_type: str  # "restore_snapshot", "revoke_credentials", "rebuild", etc.
    priority: int = Field(ge=1, le=5)
    start_time: Optional[datetime] = None
    completion_time: Optional[datetime] = None

class ObjectLockRequest(BaseModel):
    """Request to activate object lock on storage."""
    bucket_name: str
    retention_days: int = Field(ge=1, le=365)
    legal_hold: bool = False

# ============================================
# Dashboard Models
# ============================================

class DefensibilityIndex(BaseModel):
    """Defensibility Index score and components."""
    overall_score: int = Field(ge=0, le=100)
    detection_score: int = Field(ge=0, le=100)
    isolation_score: int = Field(ge=0, le=100)
    recovery_score: int = Field(ge=0, le=100)
    immutability_score: int = Field(ge=0, le=100)
    timestamp: datetime
    community_percentile: Optional[int] = None

class IncidentMetrics(BaseModel):
    """Real-time incident metrics."""
    total_incidents: int
    active_incidents: int
    total_files_affected: int
    files_recovered: int
    mttc_average: float  # Mean Time to Contain in seconds
    mttc_target: float
    mttc_achieved: bool
    containment_success_rate: float  # 0.0 to 1.0
    data_loss_percentage: float  # 0.0 to 100.0

class SystemHealth(BaseModel):
    """Overall system health status."""
    status: str  # "healthy", "degraded", "critical"
    components: Dict[str, str]  # Component name -> status
    last_heartbeat: datetime
    uptime_seconds: int

class DashboardSummary(BaseModel):
    """Complete dashboard summary."""
    metrics: IncidentMetrics
    defensibility_index: DefensibilityIndex
    system_health: SystemHealth
    recent_events: List[DetectionEvent]
    active_incidents: int
