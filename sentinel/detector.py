"""
Sentinel ML Detection Engine - Behavioral pattern detection
"""

import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

@dataclass
class FileActivity:
    """Single file activity record."""
    path: str
    operation: str  # "read", "write", "delete", "execute"
    timestamp: datetime
    process_id: int
    process_name: str
    entropy: float = 0.0
    size_bytes: int = 0

class BehavioralDetector:
    """ML-based behavioral pattern detector for ransomware."""
    
    def __init__(self):
        self.activity_window = {}  # path -> [activities]
        self.window_size_seconds = 60
        self.mass_modification_threshold = 0.15  # 15% file modification rate
        self.entropy_threshold = 0.85
        
    def analyze_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        High entropy (>0.85) indicates potential encryption.
        """
        if len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        # Shannon entropy: -sum(p * log2(p))
        entropy = -np.sum(probabilities * np.log2(probabilities))
        normalized_entropy = entropy / 8.0  # Max entropy is 8 for 256 possibilities
        
        return float(normalized_entropy)
    
    def detect_mass_modification(
        self, 
        directory: str, 
        duration_seconds: int = 60
    ) -> Tuple[bool, float, int]:
        """
        Detect if files in directory are being modified at high rate.
        
        Returns:
            Tuple[is_detected, modification_rate, file_count]
        """
        now = datetime.utcnow()
        cutoff_time = now - timedelta(seconds=duration_seconds)
        
        if directory not in self.activity_window:
            return False, 0.0, 0
        
        activities = self.activity_window[directory]
        recent_activities = [a for a in activities if a.timestamp >= cutoff_time]
        
        write_count = sum(1 for a in recent_activities if a.operation == "write")
        total_count = len(recent_activities)
        
        if total_count == 0:
            return False, 0.0, 0
        
        modification_rate = write_count / total_count
        is_detected = modification_rate > self.mass_modification_threshold
        
        return is_detected, modification_rate, len(set(a.path for a in recent_activities))
    
    def detect_encryption_entropy(self, file_path: str, data: bytes) -> Tuple[bool, float]:
        """
        Detect high entropy content indicating encryption.
        
        Returns:
            Tuple[is_high_entropy, entropy_score]
        """
        entropy = self.analyze_entropy(data)
        is_detected = entropy > self.entropy_threshold
        
        return is_detected, entropy
    
    def detect_lateral_movement(
        self, 
        original_process: str,
        child_processes: List[str]
    ) -> Tuple[bool, List[str]]:
        """
        Detect suspicious lateral movement via process spawning.
        Indicative of malware attempting privilege escalation or network access.
        """
        suspicious_procs = []
        dangerous_exes = ["powershell", "cmd", "psexec", "schtasks", "net", "wmic"]
        
        for child in child_processes:
            child_name = child.lower().split("\\")[-1] if "\\" in child else child.lower()
            if child_name in dangerous_exes:
                suspicious_procs.append(child)
        
        is_detected = len(suspicious_procs) > 0
        return is_detected, suspicious_procs
    
    def detect_vssadmin_abuse(self, command: str) -> bool:
        """
        Detect vssadmin (Volume Shadow Copy) deletion attempts.
        Ransomware commonly disables shadow copies to prevent recovery.
        """
        dangerous_patterns = [
            "vssadmin delete",
            "vssadmin resize",
            "shadow /delete",
            "bcdedit /set",
            "bootstatuspolicy",
            "disablesigcheck"
        ]
        
        command_lower = command.lower()
        return any(pattern in command_lower for pattern in dangerous_patterns)

class DefensibilityScorer:
    """Score system based on successful defensive layers (Defensibility Index)."""
    
    def __init__(self):
        self.max_score = 100
        self.weights = {
            "detection": 0.30,
            "isolation": 0.30,
            "recovery": 0.20,
            "immutability": 0.20
        }
    
    def calculate_score(
        self,
        detection_effectiveness: float,  # 0.0 to 1.0
        isolation_success: float,        # 0.0 to 1.0
        recovery_completeness: float,    # 0.0 to 1.0
        immutability_confidence: float   # 0.0 to 1.0
    ) -> int:
        """
        Calculate Defensibility Index.
        Unlike vuln scores, higher is better (0-100).
        
        Args:
            detection_effectiveness: How early was threat detected
            isolation_success: Did isolation prevent further damage
            recovery_completeness: What % of data was recovered
            immutability_confidence: Were logs tamper-proof
        
        Returns:
            Defensibility Index score (0-100)
        """
        weighted_score = (
            detection_effectiveness * self.weights["detection"] +
            isolation_success * self.weights["isolation"] +
            recovery_completeness * self.weights["recovery"] +
            immutability_confidence * self.weights["immutability"]
        )
        
        return int(weighted_score * self.max_score)
