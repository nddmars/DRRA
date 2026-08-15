#!/usr/bin/env python3
"""
DRRA-076 — Download the cited OTRF Security-Datasets and verify provenance.

Fetches the exact public datasets the manuscript's scenarios are modeled on from
the Open Threat Research Foundation Security-Datasets repository (the successor
to Mordor), verifies each archive against a **pinned commit** and a **known-good
SHA-256**, safely extracts it, and writes a manifest.

Defensible reproducibility (DRRA-057/075/084):
  * the upstream is pinned to an immutable commit SHA (not the moving ``master``);
  * every archive's SHA-256 is verified against an expected value before use —
    a mismatch is fatal;
  * ZIP extraction validates member paths (no absolute paths, no ``..`` escape);
  * a required dataset that fails to download or verify makes the run exit
    non-zero, so a broken fetch cannot masquerade as success.

No enterprise or private telemetry is required — every dataset is public and
downloaded over HTTPS from raw.githubusercontent.com.

Usage:
    python scripts/fetch_datasets.py                 # download + verify all
    python scripts/fetch_datasets.py --only lsass    # substring filter
    python scripts/fetch_datasets.py --list          # list without downloading
    python scripts/fetch_datasets.py --write-expected  # re-pin hashes (trusted env only)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import zipfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(REPO, "data", "otrf")

# Pinned to an immutable commit so the inputs cannot change under us.
PINNED_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
BASE_TMPL = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/"
             "{ref}/datasets/atomic/windows/")

# Curated public datasets covering the four IoB families, with known-good
# SHA-256 of each archive at PINNED_COMMIT. A download that does not match is
# rejected.
DATASETS = [
    {"id": "lsass_dump_comsvcs", "iob": "privilege_escalation (LSASS access, T1003.001)",
     "path": "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
     "sha256": "0af9e920220d746432f0972be83ad057629695540aecd68c15869d190786e1ae"},
    {"id": "lsass_dumpert", "iob": "privilege_escalation (LSASS access, T1003.001)",
     "path": "credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip",
     "sha256": "a28dbf708685a80edfb0b3d2a00c9bf196dd394fc1d61a933878841f4872a7ed"},
    {"id": "smb_copy_lateral", "iob": "lateral_movement (SMB, T1021.002)",
     "path": "lateral_movement/network/covenant_copy_smb_CreateRequest.zip",
     "sha256": "5bd11ee3b5f9595194808037a83b8abdb3f21c7202e823858c0187ee50f43907"},
    {"id": "wmi_lateral", "iob": "lateral_movement (WMI, T1047)",
     "path": "lateral_movement/network/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",
     "sha256": "369363603a15c43985e57cbffc4ff8379823acb36ca0cc8b00ff02b142f57b44"},
    {"id": "dcsync", "iob": "privilege_escalation / credential access (DCSync)",
     "path": "credential_access/network/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
     "sha256": "852104835d04f26cbff71db452324d863ca3f7352e6de1629adbceb987fc48ca"},
]


class VerificationError(RuntimeError):
    pass


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(zf: zipfile.ZipFile, dest: str) -> list:
    """Extract validating every member stays beneath dest (no abs/.. escape)."""
    dest_real = os.path.realpath(dest)
    names = []
    for member in zf.namelist():
        if member.endswith("/"):
            continue
        if os.path.isabs(member) or member.startswith(("/", "\\")) \
                or any(p == ".." for p in member.replace("\\", "/").split("/")):
            raise VerificationError(f"unsafe ZIP member path: {member!r}")
        target = os.path.realpath(os.path.join(dest_real, member))
        if os.path.commonpath([target, dest_real]) != dest_real:
            raise VerificationError(f"ZIP member escapes destination: {member!r}")
        names.append(member)
    zf.extractall(dest)   # safe: every member validated above
    return names


def fetch_one(ds: dict, ref: str, verify: bool = True) -> dict:
    url = BASE_TMPL.format(ref=ref) + ds["path"]
    os.makedirs(OUT, exist_ok=True)
    zpath = os.path.join(OUT, ds["id"] + ".zip")
    print(f"[*] {ds['id']}: {url}")
    urllib.request.urlretrieve(url, zpath)
    digest = sha256(zpath)
    expected = ds.get("sha256")
    if verify and expected and digest != expected:
        raise VerificationError(
            f"SHA-256 mismatch for {ds['id']}: expected {expected}, got {digest}")
    with zipfile.ZipFile(zpath) as z:
        extracted = _safe_extract(z, os.path.join(OUT, ds["id"]))
    return {"id": ds["id"], "iob": ds["iob"], "source_url": url, "ref": ref,
            "sha256": digest, "sha256_verified": bool(expected and digest == expected),
            "bytes": os.path.getsize(zpath), "files": extracted}


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch + verify cited OTRF Security-Datasets")
    ap.add_argument("--only", help="substring filter on dataset id")
    ap.add_argument("--ref", default=PINNED_COMMIT, help="pin to a specific commit SHA")
    ap.add_argument("--list", action="store_true", help="list datasets without downloading")
    ap.add_argument("--write-expected", action="store_true",
                    help="record downloaded hashes as expected (trusted env only)")
    args = ap.parse_args()

    selected = [d for d in DATASETS if not args.only or args.only in d["id"]]
    if args.list:
        for d in selected:
            print(f"{d['id']:22} {d['iob']:45} {BASE_TMPL.format(ref=args.ref) + d['path']}")
        return 0

    manifest = {"repository": "https://github.com/OTRF/Security-Datasets",
                "pinned_commit": args.ref, "datasets": []}
    failures = 0
    for d in selected:
        try:
            rec = fetch_one(d, args.ref, verify=not args.write_expected)
            manifest["datasets"].append(rec)
            if args.write_expected:
                print(f"    {d['id']} sha256 = {rec['sha256']}")
        except Exception as exc:
            print(f"[!] {d['id']} FAILED: {exc}", file=sys.stderr)
            manifest["datasets"].append({"id": d["id"], "error": str(exc)})
            failures += 1

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    ok = sum(1 for d in manifest["datasets"] if d.get("sha256_verified"))
    print(f"\n[*] {ok}/{len(selected)} datasets fetched and verified. "
          f"Manifest: data/otrf/manifest.json")
    if failures:
        print(f"[!] {failures} dataset(s) failed — exiting non-zero.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
