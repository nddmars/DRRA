"""
Service layer for Sentinel (Detection) operations.
Handles ML detection, telemetry, and LLM integration with entropy analysis and behavioral patterns.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import uuid
import math
from collections import defaultdict
import os

logger = logging.getLogger(__name__)

# ML Detection Thresholds
ENTROPY_THRESHOLD = 0.85  # High entropy indicates encryption
MASS_MODIFICATION_THRESHOLD = 0.15  # 15% of files modified in timeframe
MASS_MODIFICATION_TIMEFRAME = 60  # seconds

def calculate_entropy(file_path: str) -> float:
    """Calculate Shannon entropy of a file to detect encryption."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(10240)  # Read first 10KB
    except Exception as e:
        logger.debug(f"Could not read {file_path}: {e}")
        return 0.0
    
    if not data:
        return 0.0
    
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    
    # Shannon entropy = -sum(p * log2(p))
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        p = count / data_len
        entropy -= p * math.log2(p) if p > 0 else 0
    
    return min(entropy / 8.0, 1.0)  # Normalize to 0-1


class BehaviorPatternDetector:
    """ML detector for behavioral patterns indicating ransomware."""
    
    def __init__(self):
        self.file_access_history = defaultdict(list)  # path -> [(timestamp, action)]
        self.process_file_map = defaultdict(set)  # process_id -> set of files
        
    def detect_mass_modification(self, path: str, recent_files: List[str]) -> Optional[Dict]:
        """Detect mass file modification pattern."""
        if not recent_files:
            return None
        
        # Check how many files were modified recently
        modification_rate = len(recent_files)
        
        # If high percentage of files in directory modified rapidly, flag it
        try:
            total_files = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
            modification_percentage = modification_rate / total_files if total_files > 0 else 0
            
            if modification_percentage > MASS_MODIFICATION_THRESHOLD:
                return {
                    "pattern_type": "mass_modification",
                    "severity": "critical",
                    "files_affected": modification_rate,
                    "modification_percentage": modification_percentage,
                    "confidence": min(modification_percentage / 0.3, 1.0)  # Confidence increases with rate
                }
        except Exception as e:
            logger.debug(f"Could not analyze directory {path}: {e}")
        
        return None
    
    def detect_encryption_attempt(self, file_path: str) -> Optional[Dict]:
        """Detect encryption by analyzing file entropy."""
        entropy = calculate_entropy(file_path)
        
        if entropy > ENTROPY_THRESHOLD:
            return {
                "pattern_type": "encryption_detected",
                "severity": "critical",
                "entropy_score": entropy,
                "confidence": min((entropy - 0.7) / 0.3, 1.0)  # Confidence increases above threshold
            }
        return None
    
    def detect_lateral_movement(self, process_id: int, target_services: List[str]) -> Optional[Dict]:
        """Detect Kerberos/lateral movement patterns."""
        # Simplified detection: if a process is accessing multiple service accounts rapidly
        services_accessed = len(target_services)
        
        if services_accessed > 3:  # Multiple service account access
            return {
                "pattern_type": "lateral_movement",
                "severity": "high",
                "services_accessed": services_accessed,
                "process_id": process_id,
                "confidence": min(services_accessed / 10.0, 1.0)
            }
        return None
    
    def detect_vss_abuse(self, system_logs: Dict[str, Any]) -> Optional[Dict]:
        """Detect Volume Shadow Copy deletion/abuse."""
        if system_logs.get("vss_deletion_attempts", 0) > 0:
            return {
                "pattern_type": "vss_abuse",
                "severity": "critical",
                "vss_deletions": system_logs.get("vss_deletion_attempts"),
                "confidence": 0.95
            }
        return None


class SentinelService:
    """Service for detection and threat analysis."""
    
    def __init__(self):
        self.detection_events = {}  # In-memory for now, replace with DB
        self.pattern_detector = BehaviorPatternDetector()
        
    async def record_detection_event(
        self,
        threat_type: str,
        threat_level: str,
        affected_path: str,
        file_count: int,
        entropy_score: float,
        confidence: float,
        details: Dict[str, Any]
    ) -> str:
        """Record a detection event."""
        event_id = str(uuid.uuid4())
        
        event = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_type": threat_type,
            "threat_level": threat_level,
            "affected_path": affected_path,
            "file_count": file_count,
            "entropy_score": entropy_score,
            "confidence": confidence,
            "details": details
        }
        
        self.detection_events[event_id] = event
        logger.info(f"Detection event recorded: {event_id} - {threat_level}")
        
        return event_id
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent detection events."""
        return list(self.detection_events.values())[-limit:]
    
    async def analyze_path_for_threats(
        self,
        path: str,
        duration_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        Comprehensive threat analysis on a path.
        Detects mass modification, encryption, lateral movement, VSS abuse.
        """
        analysis_id = str(uuid.uuid4())
        
        patterns = []
        overall_threat_level = "low"
        
        # Simulate file access monitoring
        try:
            files_in_path = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            
            # Check for mass modification (in real scenario, this would be time-windowed)
            mass_mod = self.pattern_detector.detect_mass_modification(path, files_in_path[:int(len(files_in_path) * 0.2)])
            if mass_mod:
                patterns.append(mass_mod)
                overall_threat_level = "critical"
            
            # Check entropy of sample files
            for file_path_item in files_in_path[:5]:  # Sample first 5 files
                full_path = os.path.join(path, file_path_item)
                encryption = self.pattern_detector.detect_encryption_attempt(full_path)
                if encryption:
                    patterns.append(encryption)
                    overall_threat_level = "critical"
        except Exception as e:
            logger.debug(f"Could not analyze path {path}: {e}")
        
        return {
            "analysis_id": analysis_id,
            "status": "completed",
            "target_path": path,
            "duration": duration_seconds,
            "patterns_detected": patterns,
            "overall_threat_level": overall_threat_level
        }
    
    async def analyze_behavioral_pattern(
        self,
        path: str,
        process_id: int,
        duration_seconds: int
    ) -> Dict:
        """Analyze behavioral patterns in target path."""
        return {
            "analysis_id": str(uuid.uuid4()),
            "status": "analyzing",
            "target_path": path,
            "duration": duration_seconds,
            "patterns_detected": []
        }
    
    async def generate_llm_insight(
        self,
        event_id: str,
        gemini_api_key: Optional[str] = None
    ) -> Dict:
        """Generate LLM-based analysis of detection event."""
        insight_id = str(uuid.uuid4())
        
        event = self.detection_events.get(event_id)
        if not event:
            return {"error": "Event not found"}
        
        # In production, call Gemini API here
        threat_type = event.get("threat_type", "unknown")
        
        action_map = {
            "mass_modification": [
                "Isolate affected systems immediately",
                "Suspend active user sessions",
                "Trigger automated backup restoration",
                "Preserve forensic evidence in immutable storage"
            ],
            "encryption_detected": [
                "Block network traffic from affected system",
                "Activate immutable object locking on storage",
                "Prepare recovery from snapshot",
                "Alert security Operations Centre"
            ],
            "lateral_movement": [
                "Revoke compromised credentials immediately",
                "Segment network to prevent spread",
                "Review Kerberos ticket requests",
                "Analyze process memory for malicious code"
            ],
            "vss_abuse": [
                "Alert incident response team",
                "Recovery may require external data sources",
                "Check for ransomware note files"
            ]
        }
        
        recommended_actions = action_map.get(threat_type, ["Investigate suspicious activity"])
        
        return {
            "insight_id": insight_id,
            "event_id": event_id,
            "status": "completed",
            "threat_summary": f"Detected {event['threat_level']} severity {event['threat_type']} affecting {event['file_count']} files",
            "attack_vector": threat_type,
            "recommended_actions": recommended_actions,
            "defensibility_gaps": [
                "Enable real-time file integrity monitoring",
                "Enforce network micro-segmentation",
                "Implement immutable backup strategy"
            ]
        }



class TelemetryService:
    """Service for immutable telemetry management."""
    
    def __init__(self):
        self.telemetry_buffer = []
        self.buffer_size_threshold = 1000
        
    async def emit_telemetry(
        self,
        source: str,
        event_type: str,
        severity: str,
        data: Dict[str, Any]
    ) -> str:
        """Emit telemetry event to immutable pipeline."""
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "data": data
        }
        
        self.telemetry_buffer.append(event)
        
        # Auto-flush when buffer reaches threshold
        if len(self.telemetry_buffer) >= self.buffer_size_threshold:
            await self.flush_to_immutable_storage()
        
        return event["event_id"]
    
    async def flush_to_immutable_storage(self) -> int:
        """Flush telemetry buffer to MinIO immutable storage."""
        count = len(self.telemetry_buffer)
        
        # In production, write to MinIO here
        logger.info(f"Flushing {count} telemetry events to immutable storage")
        
        self.telemetry_buffer.clear()
        return count
    
    async def get_immutable_logs(self, limit: int = 50) -> List[Dict]:
        """Retrieve immutable logs (would come from MinIO)."""
        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "file_watcher",
                "event_type": "file_access",
                "severity": "info"
            }
        ] * limit


if __name__ == "__main__":
    import asyncio
    
    sentinel = SentinelService()
    telemetry = TelemetryService()
    
    # Example usage
    async def test():
        # Record event
        event_id = await sentinel.record_detection_event(
            threat_type="mass_modification",
            threat_level="high",
            affected_path="C:\\Users\\Documents",
            file_count=5000,
            entropy_score=0.87,
            confidence=0.94,
            details={"detected_time": "2024-02-19 10:00:00"}
        )
        print(f"Event recorded: {event_id}")
        
        # Emit telemetry
        tel_id = await telemetry.emit_telemetry(
            source="file_watcher",
            event_type="mass_modification_detected",
            severity="high",
            data={"file_count": 5000}
        )
        print(f"Telemetry emitted: {tel_id}")
    
    asyncio.run(test())
