"""
GRAB clean-room recovery drill (DRRA-083).

The Defensibility Index consumes ``recovery_fidelity`` — "the proportion of
recovery points passing all four GRAB validation stages". Until now that number
was supplied as a literal; the four stages did not exist as executable code and
no recovery was actually performed. This module implements the drill so the
fidelity figure is *measured*, not asserted.

The drill, end to end:

  1. Back up a set of protected assets to an immutable, write-once store
     (compliance-mode Object Lock semantics: locked objects cannot be modified
     or deleted until their retention expires).
  2. Simulate a ransomware event: the *live* working copies are encrypted /
     mangled, and the attacker also attempts to tamper with the backup store.
  3. Recover into a fresh **clean room** — an isolated directory that never
     touched the compromised live path.
  4. Validate every recovered asset against four stages and report
     ``recovery_fidelity`` = assets passing ALL stages / total assets.

The four GRAB validation stages
-------------------------------
  * integrity     — restored bytes hash-match the manifest recorded at backup
  * completeness  — every expected recovery point is present in the clean room
  * isolation     — the clean room is disjoint from the compromised live path
                    (no attacker-controlled bytes leaked into recovery)
  * immutability  — the backup object was provably unmodified: the store
                    rejected the attacker's tamper attempt during retention

The immutable store here is filesystem-backed so the drill runs anywhere with no
external services. ``backend/utils/minio_client.py`` provides the production
equivalent (MinIO Object Lock); this module intentionally depends on neither the
web framework nor the database so it is runnable and testable standalone.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, field
from typing import Dict, List


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ImmutabilityError(RuntimeError):
    """Raised when a locked object is modified or deleted during retention."""


class WormFileStore:
    """A minimal write-once-read-many store with compliance-mode locking.

    Models the guarantee DRRA relies on from MinIO Object Lock: once written
    with a retention period, an object cannot be overwritten or deleted until
    that period elapses. Here retention is expressed as a monotonically counted
    "clock" the caller advances, so tests are deterministic (no wall-clock).
    """

    def __init__(self, root: str) -> None:
        self.root = root
        os.makedirs(root, exist_ok=True)
        self._locked_until: Dict[str, int] = {}
        self._clock = 0

    def tick(self, n: int = 1) -> None:
        self._clock += n

    def put(self, name: str, data: bytes, retention: int = 10) -> str:
        path = os.path.join(self.root, name)
        if name in self._locked_until and self._clock < self._locked_until[name]:
            raise ImmutabilityError(f"object '{name}' is locked (WORM retention)")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP)  # read-only on disk too
        self._locked_until[name] = self._clock + retention
        return path

    def get(self, name: str) -> bytes:
        with open(os.path.join(self.root, name), "rb") as f:
            return f.read()

    def names(self) -> List[str]:
        return sorted(self._locked_until)

    def delete(self, name: str) -> None:
        if name in self._locked_until and self._clock < self._locked_until[name]:
            raise ImmutabilityError(f"object '{name}' is locked (WORM retention)")
        path = os.path.join(self.root, name)
        if os.path.exists(path):
            os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
            os.remove(path)
        self._locked_until.pop(name, None)


@dataclass
class StageResult:
    integrity: bool = False
    completeness: bool = False
    isolation: bool = False
    immutability: bool = False

    @property
    def all_passed(self) -> bool:
        return all((self.integrity, self.completeness, self.isolation, self.immutability))

    def as_dict(self) -> Dict[str, bool]:
        return {
            "integrity": self.integrity,
            "completeness": self.completeness,
            "isolation": self.isolation,
            "immutability": self.immutability,
            "all_passed": self.all_passed,
        }


@dataclass
class DrillReport:
    total: int
    passed: int
    per_asset: Dict[str, StageResult] = field(default_factory=dict)
    tamper_attempt_blocked: bool = False

    @property
    def recovery_fidelity(self) -> float:
        return (self.passed / self.total) if self.total else 0.0

    def as_dict(self) -> Dict:
        return {
            "total_recovery_points": self.total,
            "passed_all_stages": self.passed,
            "recovery_fidelity": round(self.recovery_fidelity, 4),
            "tamper_attempt_blocked": self.tamper_attempt_blocked,
            "per_asset": {k: v.as_dict() for k, v in self.per_asset.items()},
        }


class GrabRecoveryDrill:
    """Runs the four-stage clean-room recovery drill and measures fidelity."""

    def __init__(self, workdir: str) -> None:
        self.workdir = workdir
        self.live_dir = os.path.join(workdir, "live")       # compromised at attack time
        self.clean_room = os.path.join(workdir, "clean_room")  # isolated recovery target
        self.store = WormFileStore(os.path.join(workdir, "immutable"))
        os.makedirs(self.live_dir, exist_ok=True)
        self._manifest: Dict[str, str] = {}  # name -> sha256 at backup time

    # -- stage 1: back up protected assets to the immutable store -------------
    def backup(self, assets: Dict[str, bytes], retention: int = 100) -> None:
        for name, data in assets.items():
            live_path = os.path.join(self.live_dir, name)
            os.makedirs(os.path.dirname(live_path), exist_ok=True)
            with open(live_path, "wb") as f:
                f.write(data)
            self.store.put(name, data, retention=retention)
            self._manifest[name] = _sha256(data)

    # -- stage 2: ransomware event -------------------------------------------
    def simulate_attack(self) -> bool:
        """Encrypt/mangle the live copies and try to tamper the backups.

        Returns True iff the immutable store BLOCKED every tamper attempt."""
        for name in list(self._manifest):
            # live copy is destroyed (as ransomware would)
            with open(os.path.join(self.live_dir, name), "wb") as f:
                f.write(b"ENCRYPTED_BY_RANSOMWARE")
        blocked = True
        for name in self.store.names():
            try:
                self.store.put(name, b"ENCRYPTED_BY_RANSOMWARE", retention=100)
                blocked = False  # a successful overwrite means immutability FAILED
            except ImmutabilityError:
                pass
            try:
                self.store.delete(name)
                blocked = False
            except ImmutabilityError:
                pass
        return blocked

    # -- stage 3: restore into an isolated clean room -------------------------
    def restore(self) -> None:
        if os.path.exists(self.clean_room):
            shutil.rmtree(self.clean_room)
        os.makedirs(self.clean_room, exist_ok=True)
        for name in self.store.names():
            dst = os.path.join(self.clean_room, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(self.store.get(name))

    # -- stage 4: validate ----------------------------------------------------
    def validate(self, tamper_blocked: bool) -> DrillReport:
        report = DrillReport(total=len(self._manifest), passed=0)
        report.tamper_attempt_blocked = tamper_blocked
        live_real = os.path.realpath(self.live_dir)
        clean_real = os.path.realpath(self.clean_room)

        for name, expected_hash in self._manifest.items():
            res = StageResult()
            restored_path = os.path.join(self.clean_room, name)

            # completeness: the recovery point exists in the clean room
            res.completeness = os.path.exists(restored_path)

            # integrity: restored bytes match the backup-time manifest
            if res.completeness:
                with open(restored_path, "rb") as f:
                    res.integrity = _sha256(f.read()) == expected_hash

            # isolation: clean room is disjoint from the compromised live path
            res.isolation = (
                os.path.commonpath([live_real, os.path.realpath(restored_path)])
                != live_real
            ) and clean_real != live_real

            # immutability: the store blocked the attacker's tamper attempt
            res.immutability = tamper_blocked

            report.per_asset[name] = res
            if res.all_passed:
                report.passed += 1
        return report

    def run(self, assets: Dict[str, bytes]) -> DrillReport:
        self.backup(assets)
        blocked = self.simulate_attack()
        self.restore()
        return self.validate(blocked)
