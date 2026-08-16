#!/usr/bin/env python3
"""
DRRA-076 — Score the VIGIL model over real OTRF telemetry.

Ingests one or more downloaded OTRF datasets (run scripts/fetch_datasets.py
first), extracts the four IoB features per host/time-window from the raw events,
scores each window with the two-stage VIGIL ensemble, and reports what the model
does on genuine adversary telemetry — as opposed to synthetic scenario vectors.

Usage:
    python scripts/fetch_datasets.py
    python scripts/run_real_data.py                 # all fetched datasets
    python scripts/run_real_data.py --window 5      # window seconds
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from vigil.ingest import extract_windows          # noqa: E402
from vigil.ml_model import load_or_train_ensemble  # noqa: E402

OTRF = os.path.join(REPO, "data", "otrf")


def find_datasets():
    # recursive: OTRF archives nest event JSON at varying depths
    found = glob.glob(os.path.join(OTRF, "**", "*.json"), recursive=True)
    return sorted(p for p in found if os.path.basename(p) != "manifest.json")


def main():
    ap = argparse.ArgumentParser(description="Score VIGIL over real OTRF telemetry")
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--out", default="results/real_data_scoring.json")
    args = ap.parse_args()

    datasets = find_datasets()
    if not datasets:
        print("No datasets found under data/otrf/. Run: python scripts/fetch_datasets.py")
        return

    model = load_or_train_ensemble()
    print(f"[*] Model backend: {model.backend}\n")
    results = []
    for path in datasets:
        feats, stats = extract_windows(path, window_seconds=args.window)
        flagged = [w for w in feats if model.score(w.as_iob()).is_anomaly]
        peak_priv = max((w.privilege_escalation for w in feats), default=0.0)
        peak_file = max((w.file_rename_rate for w in feats), default=0.0)
        name = os.path.basename(os.path.dirname(path))
        results.append({
            "dataset": name,
            "events": stats.total_events,
            "malformed_lines": stats.malformed_lines,
            "signal_events": stats.signal_events,
            "total_signals": stats.total_signals,
            "windows": len(feats),
            "flagged": len(flagged),
            "peak_privesc_per_s": round(peak_priv, 3),
            "peak_file_per_s": round(peak_file, 3),
        })
        warn = ""
        if stats.total_events and stats.total_signals == 0:
            warn = "  [!] zero signals — possible schema mismatch"
        if stats.malformed_lines:
            warn += f"  [!] {stats.malformed_lines} malformed line(s)"
        print(f"  {name:22} events={stats.total_events:5}  malformed={stats.malformed_lines:3}  "
              f"signals={stats.total_signals:4}  windows={len(feats)}  flagged={len(flagged)}{warn}")

    os.makedirs(os.path.join(REPO, os.path.dirname(args.out)), exist_ok=True)
    with open(os.path.join(REPO, args.out), "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Wrote {args.out}")
    print("[note] Atomic single-technique datasets exercise one IoB family each; the two-stage "
          "ensemble is calibrated to flag the full ransomware chain (mass file + shadow-copy + "
          "privesc together), so credential-access-only captures are correctly not labeled "
          "ransomware. Real end-to-end true positives require a multi-stage compound dataset or "
          "a cyber-range run (DRRA-052/077).")


if __name__ == "__main__":
    main()
