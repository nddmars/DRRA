"""
Service layer for Forge (Simulation) operations.
Handles payload deployment, honeypot generation, and testing.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
import uuid
import os
import random
import string

logger = logging.getLogger(__name__)

class HoneypotGenerator:
    """Generates realistic honeypot files for detection testing."""
    
    FILE_TEMPLATES = {
        "pdf": b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n... [PDF content]",
        "docx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00... [DOCX content]",
        "xlsx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00... [XLSX content]",
        "sql": b"-- MySQL dump\nSET NAMES utf8mb4;\n-- Table structure...",
        "txt": b"Sensitive Data: Customer Records\n" + b"X" * 1000
    }
    
    @staticmethod
    def generate_file(file_type: str, size_mb: float, target_dir: str) -> Optional[str]:
        """Generate a single honeypot file."""
        try:
            file_name = f"honeypot_{uuid.uuid4().hex[:8]}.{file_type}"
            file_path = os.path.join(target_dir, file_name)
            
            # Prepare content
            if file_type in HoneypotGenerator.FILE_TEMPLATES:
                base_content = HoneypotGenerator.FILE_TEMPLATES[file_type]
            else:
                base_content = b"HONEYPOT_" + file_type.encode() + b"\n"
            
            # Expand to desired size
            size_bytes = int(size_mb * 1024 * 1024)
            with open(file_path, 'wb') as f:
                while f.tell() < size_bytes:
                    f.write(base_content)
                    # Padding with random data
                    padding = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                    f.write(padding.encode())
            
            # Set modified time to make it blend with real data
            os.utime(file_path, (datetime.now(timezone.utc).timestamp() - random.randint(86400, 2592000),) * 2)
            
            logger.info(f"Generated honeypot file: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to generate honeypot file: {e}")
            return None


class PayloadSimulator:
    """Simulates ransomware attack patterns without causing real damage."""
    
    @staticmethod
    def simulate_entropy_spike(target_files: List[str]) -> Dict[str, Any]:
        """
        Simulate encryption entropy without actually modifying files.
        Returns analysis of what would happen.
        """
        analysis = {
            "simulated_entropy": 0.87,  # High entropy indicating encryption
            "files_analyzed": len(target_files),
            "estimated_encryption_time": 5 * len(target_files),  # Seconds
            "would_trigger_detection": True
        }
        
        return analysis
    
    @staticmethod
    def simulate_mass_modification(target_dir: str, percentage: float = 0.2) -> Dict[str, Any]:
        """
        Simulate mass file modification pattern.
        Returns analysis of detection likelihood.
        """
        try:
            files = [f for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f))]
            affected_count = max(1, int(len(files) * percentage))
            
            return {
                "total_files": len(files),
                "affected_files": affected_count,
                "modification_percentage": (affected_count / len(files)) if files else 0,
                "estimated_time_seconds": affected_count * 0.1,
                "would_trigger_detection": (affected_count / len(files)) > 0.15 if files else False
            }
        except Exception as e:
            logger.error(f"Failed to simulate mass modification: {e}")
            return {"error": str(e)}


class ForgeService:
    """Service for simulation and testing operations."""
    
    def __init__(self):
        self.active_payloads = {}
        self.honeypots = {}
        self.identity_squat_tests = {}
        
    async def deploy_payload(
        self,
        name: str,
        payload_type: str,
        target_path: str,
        duration_seconds: int,
        intensity: float
    ) -> str:
        """Deploy a simulated attack payload."""
        payload_id = str(uuid.uuid4())
        
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        payload = {
            "payload_id": payload_id,
            "name": name,
            "type": payload_type,
            "target_path": target_path,
            "status": "running",
            "intensity": intensity,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "detection_triggered": False,
            "estimated_files_affected": int(1000 * intensity)
        }
        
        self.active_payloads[payload_id] = payload
        logger.info(f"Payload deployed: {payload_id} - {payload_type} in {target_path}")
        
        return payload_id
    
    async def get_payload_status(self, payload_id: str) -> Optional[Dict]:
        """Get status of deployed payload."""
        payload = self.active_payloads.get(payload_id)
        if not payload:
            return None
        
        elapsed = (
            datetime.now(timezone.utc) - datetime.fromisoformat(payload["start_time"]).replace(tzinfo=timezone.utc)
        ).total_seconds()
        
        # Simulate detection after a delay
        if elapsed > 10:
            payload["detection_triggered"] = True
            payload["status"] = "detected"
        
        return {
            "payload_id": payload_id,
            "name": payload["name"],
            "type": payload["type"],
            "status": payload["status"],
            "elapsed_seconds": elapsed,
            "detection_triggered": payload.get("detection_triggered", False)
        }
    
    async def generate_honeypot(
        self,
        file_types: List[str],
        count: int,
        size_mb: float,
        target_dir: str = "/tmp/honeypot"
    ) -> str:
        """Generate honeypot files for detection testing."""
        honeypot_id = str(uuid.uuid4())
        
        # Ensure target directory exists
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Could not create directory {target_dir}: {e}")
            target_dir = "/tmp"
        
        # Generate files
        generated_files = []
        for i in range(count):
            file_type = random.choice(file_types)
            file_path = HoneypotGenerator.generate_file(file_type, size_mb, target_dir)
            if file_path:
                generated_files.append(file_path)
        
        honeypot = {
            "honeypot_id": honeypot_id,
            "status": "generated",
            "file_types": file_types,
            "count": len(generated_files),
            "size_mb": size_mb,
            "total_size_mb": len(generated_files) * size_mb,
            "target_directory": target_dir,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": generated_files
        }
        
        self.honeypots[honeypot_id] = honeypot
        logger.info(f"Honeypot generated: {honeypot_id} with {len(generated_files)} files")
        
        return honeypot_id
    
    async def get_honeypot_status(self, honeypot_id: str) -> Optional[Dict]:
        """Get status of generated honeypot."""
        return self.honeypots.get(honeypot_id)
    
    async def kerberos_test(self, target_domain: str = "EXAMPLE.COM") -> str:
        """Simulate Kerberos lateral movement test."""
        test_id = str(uuid.uuid4())
        
        test = {
            "test_id": test_id,
            "status": "running",
            "type": "kerberos_identity_squat",
            "target_domain": target_domain,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "ticket_requests": [
                {"service": "cifs/server1", "status": "attempted"},
                {"service": "ldap/dc01", "status": "attempted"},
                {"service": "krbtgt/domain", "status": "attempted"}
            ],
            "unauthorized_accesses": 3,
            "detection_indicators": [
                "Multiple service account ticket requests from single source",
                "Abnormal Kerberos signing pattern",
                "Cross-domain trust exploitation attempts"
            ]
        }
        
        self.identity_squat_tests[test_id] = test
        logger.info(f"Kerberos identity squatting test started: {test_id}")
        
        return test_id
    
    async def get_kerberos_test_status(self, test_id: str) -> Optional[Dict]:
        """Get status of Kerberos test."""
        return self.identity_squat_tests.get(test_id)

    
    async def list_active_payloads(self) -> List[Dict]:
        """List all active payloads."""
        return [
            {
                "id": pid,
                "name": p["name"],
                "type": p["type"],
                "status": p["status"]
            }
            for pid, p in self.active_payloads.items()
        ]
    
    async def stop_payload(self, payload_id: str) -> bool:
        """Stop and clean up a payload."""
        if payload_id in self.active_payloads:
            self.active_payloads[payload_id]["status"] = "stopped"
            logger.info(f"Payload stopped: {payload_id}")
            return True
        return False


class ResiliencePayloadGenerator:
    """Generate safe, non-destructive encryption simulation payloads."""
    
    async def generate_entropy_simulation(
        self,
        target_files: int,
        entropy_target: float = 0.87
    ) -> Dict:
        """Generate entropy-increasing payload for testing."""
        return {
            "simulation_id": str(uuid.uuid4()),
            "type": "entropy_simulation",
            "target_files": target_files,
            "entropy_target": entropy_target,
            "status": "ready",
            "non_destructive": True
        }
    
    async def generate_mass_modification_sim(
        self,
        directory: str,
        modification_rate: float = 0.15,
        duration_seconds: int = 60
    ) -> Dict:
        """Generate mass file modification simulation."""
        return {
            "simulation_id": str(uuid.uuid4()),
            "type": "mass_modification_simulation",
            "target_directory": directory,
            "modification_rate": modification_rate,
            "duration": duration_seconds,
            "non_destructive": True,
            "status": "ready"
        }


if __name__ == "__main__":
    import asyncio
    
    forge = ForgeService()
    payload_gen = ResiliencePayloadGenerator()
    
    async def test():
        # Test payload deployment
        payload_id = await forge.deploy_payload(
            name="Test Payload",
            payload_type="honeypot",
            target_path="C:\\test",
            duration_seconds=60,
            intensity=1.0
        )
        print(f"Payload deployed: {payload_id}")
        
        # Test honeypot generation
        honeypot_id = await forge.generate_honeypot(
            file_types=["pdf", "docx"],
            count=50,
            size_mb=1.0
        )
        print(f"Honeypot generated: {honeypot_id}")
        
        # Test entropy simulation
        entropy_sim = await payload_gen.generate_entropy_simulation(1000)
        print(f"Entropy simulation: {entropy_sim}")
    
    asyncio.run(test())
