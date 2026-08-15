#!/usr/bin/env python3
"""
DRRA-076 — Download the cited OTRF Security-Datasets and record provenance.

Fetches the exact public datasets the manuscript's scenarios are modeled on from
the Open Threat Research Foundation Security-Datasets repository (the successor
to Mordor), unzips them, and writes a manifest with the SHA-256 of every source
archive so results are traceable to immutable inputs (DRRA-057/075/084).

No enterprise or private telemetry is required — every dataset is public and
downloaded over HTTPS from raw.githubusercontent.com.

Usage:
    python scripts/fetch_datasets.py                 # download all
    python scripts/fetch_datasets.py --only lsass    # substring filter
    python scripts/fetch_datasets.py --list          # list without downloading
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.request
import zipfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(REPO, "data", "otrf")
BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"

# Curated public datasets covering the four IoB families. Paths verified against
# the OTRF Security-Datasets repository tree.
DATASETS = [
    {"id": "lsass_dump_comsvcs", "iob": "privilege_escalation (LSASS access, T1003.001)",
     "path": "credential_access/host/psh_lsass_memory_dump_comsvcs.zip"},
    {"id": "lsass_dumpert", "iob": "privilege_escalation (LSASS access, T1003.001)",
     "path": "credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip"},
    {"id": "smb_copy_lateral", "iob": "lateral_movement (SMB, T1021.002)",
     "path": "lateral_movement/network/covenant_copy_smb_CreateRequest.zip"},
    {"id": "wmi_lateral", "iob": "lateral_movement (WMI, T1047)",
     "path": "lateral_movement/network/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip"},
    {"id": "dcsync", "iob": "privilege_escalation / credential access (DCSync)",
     "path": "credential_access/network/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip"},
]


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_one(ds: dict) -> dict:
    url = BASE + ds["path"]
    os.makedirs(OUT, exist_ok=True)
    zpath = os.path.join(OUT, ds["id"] + ".zip")
    print(f"[*] {ds['id']}: {url}")
    urllib.request.urlretrieve(url, zpath)
    digest = sha256(zpath)
    extracted = []
    with zipfile.ZipFile(zpath) as z:
        z.extractall(os.path.join(OUT, ds["id"]))
        extracted = z.namelist()
    return {"id": ds["id"], "iob": ds["iob"], "source_url": url,
            "sha256": digest, "bytes": os.path.getsize(zpath), "files": extracted}


def main():
    ap = argparse.ArgumentParser(description="Fetch cited OTRF Security-Datasets")
    ap.add_argument("--only", help="substring filter on dataset id")
    ap.add_argument("--list", action="store_true", help="list datasets without downloading")
    args = ap.parse_args()

    selected = [d for d in DATASETS if not args.only or args.only in d["id"]]
    if args.list:
        for d in selected:
            print(f"{d['id']:22} {d['iob']:45} {BASE + d['path']}")
        return

    manifest = {"repository": "https://github.com/OTRF/Security-Datasets", "datasets": []}
    for d in selected:
        try:
            manifest["datasets"].append(fetch_one(d))
        except Exception as exc:  # network/path errors are reported, not fatal
            print(f"[!] {d['id']} failed: {exc}")
            manifest["datasets"].append({"id": d["id"], "error": str(exc)})

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    ok = sum(1 for d in manifest["datasets"] if "sha256" in d)
    print(f"\n[*] {ok}/{len(selected)} datasets fetched. Provenance manifest: data/otrf/manifest.json")


if __name__ == "__main__":
    main()
