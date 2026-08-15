"""Tests for the SHIELD containment orchestration layer."""

import pytest

from services.containment import (
    ContainmentOrchestrator,
    SimulationAdapter,
    build_adapter,
    SLA_SECONDS,
)


@pytest.fixture
def orchestrator():
    # speed=0 → instant execution; modelled latencies still drive the reported MTTC.
    return ContainmentOrchestrator(SimulationAdapter(speed=0))


async def test_containment_runs_three_actions(orchestrator):
    result = await orchestrator.contain("host-1", reason="test")
    actions = {a.action for a in result.actions}
    assert actions == {"edr_isolation", "firewall_quarantine", "forensic_snapshot"}


async def test_containment_succeeds_and_measures_mttc(orchestrator):
    result = await orchestrator.contain("host-1")
    assert result.success is True
    assert result.mttc_seconds > 0
    assert result.mttc_seconds <= SLA_SECONDS
    assert result.sla_met is True


async def test_mttc_is_concurrent_max_not_sum(orchestrator):
    """Concurrent execution → MTTC ~= slowest action, not the sum of all three."""
    result = await orchestrator.contain("host-1")
    total_if_serial = sum(a.duration_ms for a in result.actions) / 1000.0
    assert result.mttc_seconds < total_if_serial


def test_build_adapter_default():
    adapter = build_adapter(None)
    assert adapter.name == "simulation"


def test_build_adapter_crowdstrike_without_creds_is_graceful():
    # Selecting crowdstrike without FalconPy/creds must not raise at build time.
    adapter = build_adapter("crowdstrike")
    assert adapter.name == "crowdstrike"


async def test_containment_result_serializable(orchestrator):
    result = await orchestrator.contain("host-9")
    d = result.as_dict()
    assert d["provider"] == "simulation"
    assert d["sla_seconds"] == SLA_SECONDS
    assert len(d["actions"]) == 3
