#!/usr/bin/env python3
"""
DRRA-083 — GRAB clean-room recovery drill runner.

Runs the four-stage recovery drill on a set of synthetic protected assets and
reports the MEASURED recovery fidelity, then folds it into the Defensibility
Index so the DI's recovery component is backed by an actual recovery rather than
a hand-authored literal.

Usage:
    python scripts/run_recovery_drill.py --assets 12
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from backend.services.grab_recovery import GrabRecoveryDrill  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_di = _load("wsg_di_drill", "backend/services/defensibility.py")
DefensibilityIndex = _di.DefensibilityIndex


def synthetic_assets(n: int):
    """Deterministic protected assets (documents, databases, configs)."""
    assets = {}
    for i in range(n):
        kind = ["documents", "databases", "configs"][i % 3]
        assets[f"{kind}/asset_{i:03d}.bin"] = (
            f"protected-asset-{i}-".encode() + bytes((i * 7 + j) % 256 for j in range(256))
        )
    return assets


def run(n_assets: int = 12):
    with tempfile.TemporaryDirectory(prefix="grab_drill_") as tmp:
        drill = GrabRecoveryDrill(tmp)
        report = drill.run(synthetic_assets(n_assets))

    di = DefensibilityIndex().score(
        mttd_seconds=2.5, mttc_seconds=7.8, apcr=0.20,
        recovery_fidelity=report.recovery_fidelity,   # MEASURED, not a literal
    )
    return report, di


def main():
    ap = argparse.ArgumentParser(description="GRAB clean-room recovery drill (DRRA-083)")
    ap.add_argument("--assets", type=int, default=12)
    args = ap.parse_args()
    report, di = run(args.assets)
    r = report.as_dict()

    print("\n## GRAB clean-room recovery drill (DRRA-083)\n")
    print(f"  recovery points        : {r['total_recovery_points']}")
    print(f"  passed all four stages : {r['passed_all_stages']}")
    print(f"  tamper attempt blocked : {r['tamper_attempt_blocked']}")
    print(f"  MEASURED recovery fidelity : {r['recovery_fidelity']*100:.1f}%")
    print(f"\n  Defensibility Index (with measured recovery component): "
          f"{di.defensibility_index:.4f}")
    print("\n  Stages per asset: integrity / completeness / isolation / immutability")


if __name__ == "__main__":
    main()
