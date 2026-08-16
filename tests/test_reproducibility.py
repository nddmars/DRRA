"""DRRA-078 — determinism of the seeded reproducibility bundle."""

import importlib.util
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_bundle_module():
    path = os.path.join(REPO, "scripts", "build_repro_bundle.py")
    spec = importlib.util.spec_from_file_location("wsg_repro", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wsg_repro"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_same_seed_reproduces_identical_raw_runs():
    m = _load_bundle_module()
    a = m.run_bundle(reps=6, seed=1234)
    b = m.run_bundle(reps=6, seed=1234)
    # raw per-run observations must be byte-identical run for run
    for cond in a["conditions"]:
        ra = a["conditions"][cond]["runs"]
        rb = b["conditions"][cond]["runs"]
        assert ra == rb, f"non-deterministic raw runs for {cond}"


def test_bundle_shape_and_seeds():
    m = _load_bundle_module()
    out = m.run_bundle(reps=5, seed=99)
    for cond, v in out["conditions"].items():
        assert len(v["runs"]) == 5
        # every run carries its declared per-run seed and required metrics
        for i, r in enumerate(v["runs"]):
            assert r["seed"] == f"99-{cond}-{i}"
            assert set(r) >= {"mttd_seconds", "mttc_seconds", "apcr",
                              "recovery_fidelity", "defensibility_index"}
        assert "defensibility_index" in v["aggregate"]


def test_different_seed_differs():
    m = _load_bundle_module()
    a = m.run_bundle(reps=6, seed=1)["conditions"]["A_change_healthcare"]["runs"]
    b = m.run_bundle(reps=6, seed=2)["conditions"]["A_change_healthcare"]["runs"]
    assert a != b
