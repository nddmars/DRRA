"""Tests for DRRA-081 (measured comparator harness).

These assert only inequalities that hold *structurally* — the two-stage
ensemble AND-gates the primary, so it can never flag more benign windows than
the primary alone — rather than exact FPR values, which depend on the
secondary-classifier backend (nondeterministic under TensorFlow in CI).
"""

import importlib.util
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _rows(res):
    return {r["architecture"].split(" ")[0]: r for r in res["architectures"]}


def test_comparator_reports_only_measured_axes():
    cmp = _load("wsg_cmp1", "scripts/run_comparator.py")
    res = cmp.evaluate(n_benign=300, n_pos=150, seed=4242, feedback_cycles=3)
    # only detection-quality axes are measured here; vendor operational values
    # are explicitly excluded, not fabricated
    assert res["measured_axes"] == ["fpr", "recall", "precision", "f1"]
    assert "external-tool MTTC" in res["excluded_axes"]["axes"]
    for row in res["architectures"]:
        assert set(["fpr", "recall", "precision", "f1", "fpr_95ci"]).issubset(row)


def test_ensemble_never_flags_more_benign_than_primary():
    cmp = _load("wsg_cmp2", "scripts/run_comparator.py")
    res = cmp.evaluate(n_benign=300, n_pos=150, seed=99, feedback_cycles=3)
    rows = res["architectures"]
    primary = rows[0]
    ensemble = rows[1]
    feedback = rows[2]
    # AND-gating: every two-stage config can only suppress primary FPs
    assert ensemble["fpr"] <= primary["fpr"] + 1e-9
    assert feedback["fpr"] <= primary["fpr"] + 1e-9
    # attacks still caught across all configurations
    assert all(r["recall"] >= 0.8 for r in rows)
    # suppressing false positives at equal recall cannot reduce precision/F1
    assert ensemble["precision"] >= primary["precision"] - 1e-9
    assert ensemble["f1"] >= primary["f1"] - 1e-9


def test_comparator_shared_eval_set_matches_fpr_study():
    # the comparator draws its held-out benign/positive sets from the same
    # generators (and seeds) as the FPR study, so the two are comparable
    import random
    cmp = _load("wsg_cmp3", "scripts/run_comparator.py")
    fpr = _load("wsg_fpr_cmp3", "scripts/run_fpr_eval.py")
    # deterministic generators: same seed -> identical held-out sets
    assert (cmp.benign_workloads(50, random.Random("benign-4242"))
            == fpr.benign_workloads(50, random.Random("benign-4242")))
    assert (cmp.ransomware_windows(50, random.Random("ranse-4242"))
            == fpr.ransomware_windows(50, random.Random("ranse-4242")))
