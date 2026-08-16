"""Tests for DRRA-077 (reproducible lab-provisioning validator)."""

import importlib.util
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name="wsg_validate_lab"):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(REPO, "scripts", "validate_lab.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_lab_manifest_validates_clean():
    v = _load("wsg_vl1")
    r = v.validate()
    assert r["ok"], r["errors"]


def test_every_scenario_maps_to_a_real_dataset():
    v = _load("wsg_vl2")
    manifest = v.load_manifest()
    ids = v._dataset_ids()
    errors = v.check_scenarios_map_to_datasets(manifest, ids)
    assert errors == []
    # and the mapping is non-trivial (the lab actually references datasets)
    assert len(manifest["attack_scenarios"]) >= 3


def test_unpinned_box_is_rejected():
    v = _load("wsg_vl3")
    manifest = v.load_manifest()
    # corrupt a copy: float one endpoint box on "latest"
    manifest["endpoint_tier"]["hosts"][0]["box_version"] = "latest"
    errors = v.check_boxes_pinned(manifest)
    assert any("not version-pinned" in e for e in errors)


def test_floating_control_plane_image_is_rejected():
    v = _load("wsg_vl4")
    compose = v._load_compose()
    if compose is None:
        import pytest
        pytest.skip("PyYAML unavailable")
    manifest = v.load_manifest()
    # inject a floating tag and confirm the validator flags it
    compose["services"]["minio"]["image"] = "minio/minio:latest"
    errors = v.check_compose(manifest, compose)
    assert any("not pinned" in e for e in errors)


def test_duplicate_host_port_is_rejected():
    v = _load("wsg_vl5")
    compose = v._load_compose()
    if compose is None:
        import pytest
        pytest.skip("PyYAML unavailable")
    manifest = v.load_manifest()
    # force a collision on the postgres host port
    compose["services"]["redis"]["ports"] = ["7100:6379"]
    errors = v.check_compose(manifest, compose)
    assert any("host port 7100" in e for e in errors)
