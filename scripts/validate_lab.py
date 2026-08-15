#!/usr/bin/env python3
"""
DRRA-077 — Reproducible lab-provisioning validator.

A "10-VM enterprise lab" only counts as evidence if it is *reproducible* — the
same topology, pinned versions, and attack scenarios every time. Standing up the
live VMs and collecting fresh telemetry is external evidence and remains future
work; what is implementable and testable now is the reproducibility of the lab
*definition*. This validator enforces that against lab/lab_manifest.json and the
control-plane docker-compose stack:

  1. every endpoint attack scenario maps to a real OTRF dataset that DRRA can
     already ingest (DRRA-076), so the lab's behaviour is replayable offline;
  2. every endpoint box is version-pinned (no floating "latest");
  3. the control-plane services named in the manifest all exist in the compose
     file, and none of them float on ":latest" (reproducible image pins);
  4. no two services publish the same host port.

Checks 3–4 read docker-compose.yml with PyYAML; if PyYAML is unavailable they
are skipped (reported as skipped, not passed). Checks 1–2 read JSON only and
always run.

Usage:
    python scripts/validate_lab.py            # exit non-zero on any failure
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MANIFEST = os.path.join(REPO, "lab", "lab_manifest.json")
COMPOSE = os.path.join(REPO, "docker-compose.yml")


def load_manifest(path=MANIFEST):
    with open(path) as f:
        return json.load(f)


def _dataset_ids():
    spec = importlib.util.spec_from_file_location(
        "wsg_fetch_datasets", os.path.join(REPO, "scripts", "fetch_datasets.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wsg_fetch_datasets"] = mod
    spec.loader.exec_module(mod)
    return {d["id"] for d in mod.DATASETS}


def check_scenarios_map_to_datasets(manifest, dataset_ids):
    """Every scenario's dataset must be a real, fetchable OTRF capture, and every
    endpoint host must reference declared scenarios."""
    errors = []
    scenario_ids = {s["id"] for s in manifest["attack_scenarios"]}
    for s in manifest["attack_scenarios"]:
        if s["dataset"] not in dataset_ids:
            errors.append(f"scenario '{s['id']}' references unknown dataset "
                          f"'{s['dataset']}' (not in fetch_datasets.DATASETS)")
    for host in manifest["endpoint_tier"]["hosts"]:
        for sc in host["scenarios"]:
            if sc not in scenario_ids:
                errors.append(f"host '{host['id']}' references undeclared "
                              f"scenario '{sc}'")
    return errors


def check_boxes_pinned(manifest):
    errors = []
    for host in manifest["endpoint_tier"]["hosts"]:
        v = str(host.get("box_version", "")).strip().lower()
        if not v or v == "latest":
            errors.append(f"host '{host['id']}' box is not version-pinned "
                          f"(box_version={host.get('box_version')!r})")
    return errors


def _load_compose():
    try:
        import yaml  # provided transitively via uvicorn[standard]
    except Exception:
        return None
    with open(COMPOSE) as f:
        return yaml.safe_load(f)


def check_compose(manifest, compose):
    """Control-plane services present + pinned; no duplicate host ports."""
    errors = []
    services = compose.get("services", {})
    for name in manifest["control_plane"]["services"]:
        if name not in services:
            errors.append(f"manifest control-plane service '{name}' missing "
                          f"from docker-compose.yml")

    # image pins for the manifest's control-plane services
    for name in manifest["control_plane"]["services"]:
        svc = services.get(name, {})
        image = svc.get("image")
        if image and (image.endswith(":latest") or ":" not in image.split("/")[-1]):
            errors.append(f"service '{name}' image '{image}' is not pinned "
                          f"(floating tag) — not reproducible")

    # host-port collisions across ALL services
    seen = {}
    for name, svc in services.items():
        for mapping in svc.get("ports", []) or []:
            host_port = str(mapping).split(":")[0].strip('"')
            if host_port in seen:
                errors.append(f"host port {host_port} published by both "
                              f"'{seen[host_port]}' and '{name}'")
            else:
                seen[host_port] = name
    return errors


def validate():
    manifest = load_manifest()
    dataset_ids = _dataset_ids()
    result = {"errors": [], "checks": {}, "skipped": []}

    e1 = check_scenarios_map_to_datasets(manifest, dataset_ids)
    result["checks"]["scenarios_map_to_datasets"] = not e1
    result["errors"] += e1

    e2 = check_boxes_pinned(manifest)
    result["checks"]["endpoint_boxes_pinned"] = not e2
    result["errors"] += e2

    compose = _load_compose()
    if compose is None:
        result["skipped"].append("compose_checks (PyYAML unavailable)")
    else:
        e3 = check_compose(manifest, compose)
        result["checks"]["compose_services_pinned_and_unique_ports"] = not e3
        result["errors"] += e3

    result["ok"] = not result["errors"]
    return result


def main():
    r = validate()
    print("\n## Reproducible lab-provisioning validation (DRRA-077)\n")
    for name, ok in r["checks"].items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    for s in r["skipped"]:
        print(f"  [SKIP] {s}")
    if r["errors"]:
        print("\nErrors:")
        for e in r["errors"]:
            print(f"  - {e}")
    print(f"\nResult: {'OK' if r['ok'] else 'FAILED'}")
    sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
