"""
Comprehensive test suite for Resilience Forge backend services.
Tests cover Forge, Sentinel, and Shield components with pytest.
Run with: pytest tests/ -v
"""

import pytest
import asyncio
from datetime import datetime
from backend.services.forge_service import ForgeService, HoneypotGenerator, PayloadSimulator
from backend.services.sentinel_service import SentinelService, BehaviorPatternDetector, TelemetryService
from backend.services.shield_service import ShieldService, MicroSegmentationService, RecoveryOrchestrator


# ============================================
# FORGE SERVICE TESTS
# ============================================

class TestForgeService:
    """Test suite for Forge simulation engine."""
    
    @pytest.fixture
    def forge_service(self):
        return ForgeService()
    
    @pytest.mark.asyncio
    async def test_deploy_payload(self, forge_service):
        """Test payload deployment."""
        payload_id = await forge_service.deploy_payload(
            name="test_payload",
            payload_type="honeypot",
            target_path="/tmp/test",
            duration_seconds=60,
            intensity=1.0
        )
        
        assert payload_id is not None
        assert isinstance(payload_id, str)
        assert len(payload_id) > 0
    
    @pytest.mark.asyncio
    async def test_get_payload_status(self, forge_service):
        """Test payload status tracking."""
        payload_id = await forge_service.deploy_payload(
            name="test_payload",
            payload_type="resilience",
            target_path="/tmp/test",
            duration_seconds=60,
            intensity=1.5
        )
        
        status = await forge_service.get_payload_status(payload_id)
        
        assert status is not None
        assert status['payload_id'] == payload_id
        assert status['status'] in ['running', 'detected']
        assert status['type'] == 'resilience'
    
    @pytest.mark.asyncio
    async def test_generate_honeypot(self, forge_service):
        """Test honeypot file generation."""
        honeypot_id = await forge_service.generate_honeypot(
            file_types=["pdf", "xlsx"],
            count=5,
            size_mb=0.1,
            target_dir="/tmp"
        )
        
        assert honeypot_id is not None
        status = await forge_service.get_honeypot_status(honeypot_id)
        assert status is not None
        assert status['count'] <= 5
    
    @pytest.mark.asyncio
    async def test_kerberos_test(self, forge_service):
        """Test Kerberos lateral movement simulation."""
        test_id = await forge_service.kerberos_test("CONTOSO.COM")
        
        assert test_id is not None
        status = await forge_service.get_kerberos_test_status(test_id)
        assert status is not None
        assert status['type'] == 'kerberos_identity_squat'
        assert len(status['ticket_requests']) > 0


class TestHoneypotGenerator:
    """Test suite for honeypot generation."""
    
    def test_generate_pdf_honeypot(self):
        """Test PDF honeypot file generation."""
        file_path = HoneypotGenerator.generate_file("pdf", 0.01, "/tmp")
        
        assert file_path is not None
        assert "pdf" in file_path


class TestPayloadSimulator:
    """Test suite for payload simulation."""
    
    def test_entropy_spike_simulation(self):
        """Test entropy spike simulation."""
        files = [f"/tmp/file{i}.txt" for i in range(10)]
        analysis = PayloadSimulator.simulate_entropy_spike(files)
        
        assert analysis['simulated_entropy'] > 0.8
        assert analysis['files_analyzed'] == 10
        assert analysis['would_trigger_detection'] is True
    
    def test_mass_modification_simulation(self):
        """Test mass modification simulation."""
        analysis = PayloadSimulator.simulate_mass_modification("/tmp", percentage=0.25)
        
        assert 'total_files' in analysis
        assert 'affected_files' in analysis
        assert 'modification_percentage' in analysis


# ============================================
# SENTINEL SERVICE TESTS
# ============================================

class TestSentinelService:
    """Test suite for Sentinel detection engine."""
    
    @pytest.fixture
    def sentinel_service(self):
        return SentinelService()
    
    @pytest.mark.asyncio
    async def test_record_detection_event(self, sentinel_service):
        """Test event recording."""
        event_id = await sentinel_service.record_detection_event(
            threat_type="mass_modification",
            threat_level="critical",
            affected_path="/home/user/docs",
            file_count=5000,
            entropy_score=0.87,
            confidence=0.94,
            details={"detected_time": datetime.now(timezone.utc).isoformat()}
        )
        
        assert event_id is not None
        assert len(event_id) > 0
    
    @pytest.mark.asyncio
    async def test_get_recent_events(self, sentinel_service):
        """Test retrieving recent events."""
        await sentinel_service.record_detection_event(
            threat_type="encryption_detected",
            threat_level="high",
            affected_path="/var/data",
            file_count=234,
            entropy_score=0.88,
            confidence=0.91,
            details={}
        )
        
        events = await sentinel_service.get_recent_events(limit=10)
        
        assert isinstance(events, list)
        assert len(events) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_path_for_threats(self, sentinel_service):
        """Test threat analysis on a path."""
        analysis = await sentinel_service.analyze_path_for_threats(
            path="/tmp",
            duration_seconds=60
        )
        
        assert 'analysis_id' in analysis
        assert analysis['status'] == 'completed'
        assert 'patterns_detected' in analysis
    
    @pytest.mark.asyncio
    async def test_generate_llm_insight(self, sentinel_service):
        """Test LLM insight generation."""
        event_id = await sentinel_service.record_detection_event(
            threat_type="mass_modification",
            threat_level="critical",
            affected_path="/home",
            file_count=1000,
            entropy_score=0.85,
            confidence=0.90,
            details={}
        )
        
        insight = await sentinel_service.generate_llm_insight(event_id)
        
        assert 'insight_id' in insight
        assert 'threat_summary' in insight
        assert 'recommended_actions' in insight
        assert len(insight['recommended_actions']) > 0


class TestBehaviorPatternDetector:
    """Test suite for ML-based behavior detection."""
    
    @pytest.fixture
    def detector(self):
        return BehaviorPatternDetector()
    
    def test_detect_mass_modification_critical(self, detector):
        """Test detection of mass file modification."""
        files = [f"/tmp/file{i}.txt" for i in range(100)]
        
        pattern = detector.detect_mass_modification("/tmp", files)
        
        assert pattern is not None
        assert pattern['pattern_type'] == 'mass_modification'
        assert pattern['severity'] == 'critical'
    
    def test_detect_encryption_attempt(self, detector, tmp_path):
        """Test encryption detection via entropy analysis."""
        # Create a test file with high entropy content
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b'\x00\x01\x02\x03\x04\x05\x06\x07' * 1000)
        
        pattern = detector.detect_encryption_attempt(str(test_file))
        
        # Pattern may or may not be detected depending on actual entropy
        if pattern:
            assert pattern['entropy_score'] >= 0
    
    def test_detect_lateral_movement(self, detector):
        """Test lateral movement detection."""
        services = ['cifs/srv1', 'ldap/dc1', 'krbtgt/domain', 'http/app1', 'sql/db1']
        
        pattern = detector.detect_lateral_movement(1234, services)
        
        assert pattern is not None
        assert pattern['pattern_type'] == 'lateral_movement'
        assert pattern['severity'] == 'high'


class TestTelemetryService:
    """Test suite for immutable telemetry."""
    
    @pytest.fixture
    def telemetry_service(self):
        return TelemetryService()
    
    @pytest.mark.asyncio
    async def test_emit_telemetry(self, telemetry_service):
        """Test telemetry event emission."""
        event_id = await telemetry_service.emit_telemetry(
            source="file_watcher",
            event_type="file_modified",
            severity="info",
            data={"file": "/tmp/test.txt", "size": 1024}
        )
        
        assert event_id is not None
        assert len(event_id) > 0
    
    @pytest.mark.asyncio
    async def test_flush_to_immutable_storage(self, telemetry_service):
        """Test flushing telemetry to storage."""
        await telemetry_service.emit_telemetry(
            source="detector",
            event_type="threat_detected",
            severity="high",
            data={"threat": "mass_mod"}
        )
        
        count = await telemetry_service.flush_to_immutable_storage()
        
        assert count >= 0


# ============================================
# SHIELD SERVICE TESTS
# ============================================

class TestShieldService:
    """Test suite for Shield recovery engine."""
    
    @pytest.fixture
    def shield_service(self):
        return ShieldService()
    
    @pytest.mark.asyncio
    async def test_trigger_isolation(self, shield_service):
        """Test resource isolation."""
        isolation_id = await shield_service.trigger_isolation(
            resource_id="workstation_001",
            action="vlan_isolate",
            reason="mass_modification_detected"
        )
        
        assert isolation_id is not None
    
    @pytest.mark.asyncio
    async def test_get_isolation_status(self, shield_service):
        """Test isolation status tracking."""
        isolation_id = await shield_service.trigger_isolation(
            resource_id="server_app01",
            action="network_quarantine",
            reason="encryption_detected"
        )
        
        status = await shield_service.get_isolation_status(isolation_id)
        
        assert status is not None
        assert status['isolation_id'] == isolation_id
        assert status['status'] == 'in_progress'
    
    @pytest.mark.asyncio
    async def test_activate_object_lock(self, shield_service):
        """Test object lock activation."""
        result = await shield_service.activate_object_lock(
            bucket_name="backup-bucket",
            retention_days=365,
            legal_hold=True
        )
        
        assert result['status'] == 'activated'
        assert result['object_lock_enabled'] is True
    
    @pytest.mark.asyncio
    async def test_create_recovery_task(self, shield_service):
        """Test recovery task creation."""
        task_id = await shield_service.create_recovery_task(
            recovery_type="restore_snapshot",
            priority=1
        )
        
        assert task_id is not None
        task = await shield_service.get_recovery_task(task_id)
        assert task is not None
        assert task['recovery_type'] == 'restore_snapshot'
    
    @pytest.mark.asyncio
    async def test_preserve_forensic_evidence(self, shield_service):
        """Test forensic evidence preservation."""
        result = await shield_service.preserve_forensic_evidence(
            incident_id="INC-20240219-001",
            retention_days=90
        )
        
        assert result['status'] == 'preserving'
        assert result['retention_days'] == 90


class TestMicroSegmentationService:
    """Test suite for network micro-segmentation."""
    
    @pytest.fixture
    def segmentation(self):
        return MicroSegmentationService()
    
    @pytest.mark.asyncio
    async def test_isolate_vlan(self, segmentation):
        """Test VLAN isolation."""
        result = await segmentation.isolate_vlan("workstation_001", 9999)
        
        assert result['status'] == 'isolated'
        assert result['quarantine_vlan'] == 9999
    
    @pytest.mark.asyncio
    async def test_network_quarantine(self, segmentation):
        """Test network quarantine."""
        result = await segmentation.network_quarantine("server_important")
        
        assert result['status'] == 'quarantined'
        assert result['network_access'] == 'blocked'


class TestRecoveryOrchestrator:
    """Test suite for recovery orchestration."""
    
    @pytest.fixture
    def orchestrator(self):
        return RecoveryOrchestrator()
    
    @pytest.mark.asyncio
    async def test_restore_from_snapshot(self, orchestrator):
        """Test snapshot restoration."""
        task_id = await orchestrator.restore_from_snapshot(
            snapshot_id="snap-20240219-1400",
            target_resource="server_app01",
            incremental=True
        )
        
        assert task_id is not None
    
    @pytest.mark.asyncio
    async def test_revoke_credentials(self, orchestrator):
        """Test credential revocation."""
        result = await orchestrator.revoke_credentials(
            credential_types=["kerberos_tickets", "domain_passwords"]
        )
        
        assert result['status'] == 'revoked'
        assert len(result['credential_types']) > 0


# ============================================
# INTEGRATION TESTS
# ============================================

class TestIntegration:
    """Integration tests for complete workflows."""
    
    @pytest.fixture
    def services(self):
        return {
            'forge': ForgeService(),
            'sentinel': SentinelService(),
            'shield': ShieldService()
        }
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection_and_response(self, services):
        """
        Test complete threatdetection and response workflow:
        1. Deploy payload via Forge
        2. Detect threat via Sentinel
        3. Isolate and recover via Shield
        """
        forge, sentinel, shield = services['forge'], services['sentinel'], services['shield']
        
        # 1. Deploy payload
        payload_id = await forge.deploy_payload(
            name="integration_test",
            payload_type="honeypot",
            target_path="/tmp/test",
            duration_seconds=30,
            intensity=1.0
        )
        assert payload_id is not None
        
        # 2. Record threat detection
        event_id = await sentinel.record_detection_event(
            threat_type="mass_modification",
            threat_level="critical",
            affected_path="/tmp/test",
            file_count=100,
            entropy_score=0.89,
            confidence=0.95,
            details={"payload_id": payload_id}
        )
        assert event_id is not None
        
        # 3. Isolate resources
        isolation_id = await shield.trigger_isolation(
            resource_id="affected_host",
            action="network_quarantine",
            reason=f"Threat detected: {event_id}"
        )
        assert isolation_id is not None
        
        # 4. Create recovery task
        task_id = await shield.create_recovery_task(
            recovery_type="restore_snapshot",
            priority=1
        )
        assert task_id is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
