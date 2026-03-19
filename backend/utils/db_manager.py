"""
Database utilities for persisting events and incidents to PostgreSQL.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List
from db.session import SessionLocal
from db.models import (
    DetectionEventModel,
    IsolationActionModel,
    RecoveryTaskModel,
    IncidentModel,
    TelemetryEventModel,
    DefensibilityIndexModel,
    ForensicEvidenceModel
)

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manager for database persistence operations."""
    
    @staticmethod
    def create_detection_event(
        event_id: str,
        timestamp: datetime,
        threat_type: str,
        threat_level: str,
        affected_path: str,
        file_count: int,
        entropy_score: float,
        confidence: float,
        details: dict
    ) -> Optional[str]:
        """Persist detection event to PostgreSQL."""
        try:
            db = SessionLocal()
            event = DetectionEventModel(
                event_id=event_id,
                timestamp=timestamp,
                threat_type=threat_type,
                threat_level=threat_level,
                affected_path=affected_path,
                file_count=file_count,
                entropy_score=entropy_score,
                confidence=confidence,
                details=details
            )
            db.add(event)
            db.commit()
            logger.info(f"Detection event persisted to PostgreSQL: {event_id}")
            db.close()
            return event_id
        except Exception as e:
            logger.error(f"Failed to persist detection event: {e}")
            return None
    
    @staticmethod
    def create_isolation_action(
        isolation_id: str,
        incident_id: str,
        action_type: str,
        resource_id: str,
        status: str,
        affected_count: int,
        details: dict
    ) -> Optional[str]:
        """Persist isolation action to PostgreSQL."""
        try:
            db = SessionLocal()
            action = IsolationActionModel(
                isolation_id=isolation_id,
                incident_id=incident_id,
                timestamp=datetime.now(timezone.utc),
                action_type=action_type,
                resource_id=resource_id,
                status=status,
                affected_count=affected_count,
                details=details
            )
            db.add(action)
            db.commit()
            logger.info(f"Isolation action persisted to PostgreSQL: {isolation_id}")
            db.close()
            return isolation_id
        except Exception as e:
            logger.error(f"Failed to persist isolation action: {e}")
            return None
    
    @staticmethod
    def create_recovery_task(
        task_id: str,
        incident_id: str,
        recovery_type: str,
        status: str,
        priority: int,
        details: dict
    ) -> Optional[str]:
        """Persist recovery task to PostgreSQL."""
        try:
            db = SessionLocal()
            task = RecoveryTaskModel(
                task_id=task_id,
                incident_id=incident_id,
                recovery_type=recovery_type,
                status=status,
                priority=priority,
                details=details
            )
            db.add(task)
            db.commit()
            logger.info(f"Recovery task persisted to PostgreSQL: {task_id}")
            db.close()
            return task_id
        except Exception as e:
            logger.error(f"Failed to persist recovery task: {e}")
            return None
    
    @staticmethod
    def create_incident(
        incident_id: str,
        severity: str,
        affected_files_count: int,
        details: dict
    ) -> Optional[str]:
        """Create master incident record."""
        try:
            db = SessionLocal()
            incident = IncidentModel(
                incident_id=incident_id,
                created_at=datetime.now(timezone.utc),
                detection_time=datetime.now(timezone.utc),
                severity=severity,
                status="active",
                affected_files_count=affected_files_count,
                details=details
            )
            db.add(incident)
            db.commit()
            logger.info(f"Incident created in PostgreSQL: {incident_id}")
            db.close()
            return incident_id
        except Exception as e:
            logger.error(f"Failed to create incident: {e}")
            return None
    
    @staticmethod
    def create_telemetry_event(
        event_id: str,
        source: str,
        event_type: str,
        severity: str,
        data: dict,
        minio_object_key: Optional[str] = None,
        retention_days: int = 365
    ) -> Optional[str]:
        """Persist immutable telemetry event."""
        try:
            db = SessionLocal()
            retention_until = datetime.now(timezone.utc).replace(day=datetime.now(timezone.utc).day + retention_days)
            
            telemetry = TelemetryEventModel(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                source=source,
                event_type=event_type,
                severity=severity,
                data=data,
                minio_object_key=minio_object_key,
                immutable=True,
                retention_until=retention_until
            )
            db.add(telemetry)
            db.commit()
            logger.info(f"Telemetry event persisted to PostgreSQL: {event_id}")
            db.close()
            return event_id
        except Exception as e:
            logger.error(f"Failed to persist telemetry event: {e}")
            return None
    
    @staticmethod
    def create_forensic_evidence(
        evidence_id: str,
        incident_id: str,
        evidence_type: str,
        minio_path: str,
        details: dict,
        retention_days: int = 365
    ) -> Optional[str]:
        """Create forensic evidence record."""
        try:
            db = SessionLocal()
            retention_until = datetime.now(timezone.utc).replace(day=datetime.now(timezone.utc).day + retention_days)
            
            evidence = ForensicEvidenceModel(
                evidence_id=evidence_id,
                incident_id=incident_id,
                created_at=datetime.now(timezone.utc),
                evidence_type=evidence_type,
                minio_path=minio_path,
                details=details,
                retention_until=retention_until,
                chain_of_custody=True
            )
            db.add(evidence)
            db.commit()
            logger.info(f"Forensic evidence recorded in PostgreSQL: {evidence_id}")
            db.close()
            return evidence_id
        except Exception as e:
            logger.error(f"Failed to create forensic evidence record: {e}")
            return None
    
    @staticmethod
    def get_detection_events(limit: int = 100, threat_level: Optional[str] = None) -> List[dict]:
        """Retrieve detection events from PostgreSQL."""
        try:
            db = SessionLocal()
            query = db.query(DetectionEventModel).order_by(DetectionEventModel.timestamp.desc())
            
            if threat_level:
                query = query.filter(DetectionEventModel.threat_level == threat_level)
            
            events = query.limit(limit).all()
            db.close()
            
            return [{
                'event_id': e.event_id,
                'timestamp': e.timestamp.isoformat(),
                'threat_type': e.threat_type,
                'threat_level': e.threat_level,
                'file_count': e.file_count,
                'confidence': e.confidence
            } for e in events]
        except Exception as e:
            logger.error(f"Failed to retrieve detection events: {e}")
            return []
    
    @staticmethod
    def get_incident(incident_id: str) -> Optional[dict]:
        """Retrieve incident details."""
        try:
            db = SessionLocal()
            incident = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            db.close()
            
            if incident:
                return {
                    'incident_id': incident.incident_id,
                    'severity': incident.severity,
                    'status': incident.status,
                    'affected_files': incident.affected_files_count,
                    'recovered_files': incident.files_recovered_count,
                    'data_loss_percent': incident.data_loss_percent,
                    'mttc_seconds': incident.mttc_seconds
                }
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve incident: {e}")
            return None

# Global database manager instance
db_manager = DatabaseManager()
