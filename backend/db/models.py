"""
Database models for Resilience Forge
"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON, Enum
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class DetectionEventModel(Base):
    """Audit log of all detection events."""
    __tablename__ = "detection_events"
    
    event_id = Column(String(36), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String(100), index=True)
    threat_level = Column(String(20), index=True)
    affected_path = Column(String(512))
    file_count = Column(Integer)
    entropy_score = Column(Float)
    confidence = Column(Float)
    details = Column(JSON)
    response_action = Column(String(100), nullable=True)
    response_time_ms = Column(Float, nullable=True)
    
    def __repr__(self):
        return f"<DetectionEvent {self.event_id} - {self.threat_level}>"


class IsolationActionModel(Base):
    """Record of isolation/containment actions taken."""
    __tablename__ = "isolation_actions"
    
    isolation_id = Column(String(36), primary_key=True, index=True)
    incident_id = Column(String(36), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    action_type = Column(String(100), index=True)  # vlan_isolate, process_kill, file_lock, etc.
    resource_id = Column(String(256))
    status = Column(String(50), index=True)  # pending, in_progress, completed, failed
    duration_ms = Column(Float, nullable=True)
    affected_count = Column(Integer)
    details = Column(JSON)
    
    def __repr__(self):
        return f"<IsolationAction {self.isolation_id} - {self.action_type}>"


class RecoveryTaskModel(Base):
    """Automated recovery operations."""
    __tablename__ = "recovery_tasks"
    
    task_id = Column(String(36), primary_key=True, index=True)
    incident_id = Column(String(36), index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    recovery_type = Column(String(100), index=True)  # restore_snapshot, revoke_credentials, rebuild, etc.
    status = Column(String(50), index=True)  # pending, in_progress, completed, failed
    priority = Column(Integer)
    progress_percent = Column(Integer, default=0)
    files_recovered = Column(Integer, default=0)
    data_loss_percent = Column(Float, default=0.0)
    details = Column(JSON)
    
    def __repr__(self):
        return f"<RecoveryTask {self.task_id} - {self.recovery_type}>"


class IncidentModel(Base):
    """Master incident record."""
    __tablename__ = "incidents"
    
    incident_id = Column(String(36), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    detection_time = Column(DateTime, index=True)
    containment_time = Column(DateTime, nullable=True)
    recovery_time = Column(DateTime, nullable=True)
    severity = Column(String(50), index=True)  # low, medium, high, critical
    status = Column(String(50), index=True)  # active, contained, recovering, recovered
    affected_files_count = Column(Integer)
    files_recovered_count = Column(Integer, default=0)
    data_loss_percent = Column(Float, default=0.0)
    mttc_seconds = Column(Float, nullable=True)  # Mean Time to Contain
    defensibility_score = Column(Integer, nullable=True)  # 0-100
    details = Column(JSON)
    
    def __repr__(self):
        return f"<Incident {self.incident_id} - {self.severity}>"


class TelemetryEventModel(Base):
    """Immutable telemetry from write-once pipeline."""
    __tablename__ = "telemetry_events"
    
    event_id = Column(String(36), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(100), index=True)  # file_watcher, ml_detector, shield, etc.
    event_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)
    data = Column(JSON)
    minio_object_key = Column(String(512), nullable=True)  # Reference to immutable storage
    immutable = Column(Boolean, default=True)
    retention_until = Column(DateTime)
    
    def __repr__(self):
        return f"<TelemetryEvent {self.event_id} - {self.event_type}>"


class ConfigurationModel(Base):
    """System configuration and thresholds."""
    __tablename__ = "configuration"
    
    config_id = Column(String(36), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    config_name = Column(String(100), index=True)  # "production", "testing", "strict", etc.
    is_active = Column(Boolean, default=False, index=True)
    settings = Column(JSON)  # Full config as JSON
    version = Column(String(20))
    
    def __repr__(self):
        return f"<Configuration {self.config_name}>"


class DefensibilityIndexModel(Base):
    """Historical Defensibility Index scores."""
    __tablename__ = "defensibility_index_history"
    
    score_id = Column(String(36), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    overall_score = Column(Integer)
    detection_score = Column(Integer)
    isolation_score = Column(Integer)
    recovery_score = Column(Integer)
    immutability_score = Column(Integer)
    incident_id = Column(String(36), nullable=True, index=True)
    community_percentile = Column(Integer, nullable=True)
    
    def __repr__(self):
        return f"<DefensibilityIndex {self.score_id} - {self.overall_score}>"


class ForensicEvidenceModel(Base):
    """Preserved forensic evidence from incidents."""
    __tablename__ = "forensic_evidence"
    
    evidence_id = Column(String(36), primary_key=True, index=True)
    incident_id = Column(String(36), index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    evidence_type = Column(String(100))  # memory_dump, disk_image, process_trace, etc.
    minio_path = Column(String(512))  # Path to immutable storage
    size_bytes = Column(Integer)
    hash_sha256 = Column(String(64), unique=True)
    retention_until = Column(DateTime)
    description = Column(String(512))
    metadata = Column(JSON)
    
    def __repr__(self):
        return f"<ForensicEvidence {self.evidence_id}>"


class AlertConfigModel(Base):
    """Alert and notification configurations."""
    __tablename__ = "alert_configs"
    
    alert_id = Column(String(36), primary_key=True, index=True)
    alert_type = Column(String(100), index=True)
    enabled = Column(Boolean, default=True)
    threshold = Column(Float, nullable=True)
    channels = Column(JSON)  # email, slack, webhook, sms, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<AlertConfig {self.alert_type}>"
