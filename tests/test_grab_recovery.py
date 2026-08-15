"""Tests for DRRA-083 (GRAB clean-room recovery drill).

Covers the happy path AND each failure mode, so the four validation stages are
shown to actually discriminate — a drill that always returns 100% would be
worthless as evidence.
"""

import os
import tempfile

import pytest

from backend.services.grab_recovery import (
    GrabRecoveryDrill,
    ImmutabilityError,
    WormFileStore,
)


def _assets(n=6):
    return {f"docs/asset_{i:02d}.bin": f"payload-{i}".encode() + bytes([i]) * 32
            for i in range(n)}


def test_full_drill_recovers_everything():
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        report = drill.run(_assets(8))
        assert report.total == 8
        assert report.passed == 8
        assert report.recovery_fidelity == 1.0
        assert report.tamper_attempt_blocked is True
        for res in report.per_asset.values():
            assert res.all_passed


def test_worm_store_blocks_overwrite_and_delete_during_retention():
    with tempfile.TemporaryDirectory() as tmp:
        store = WormFileStore(os.path.join(tmp, "s"))
        store.put("a", b"original", retention=5)
        with pytest.raises(ImmutabilityError):
            store.put("a", b"tampered", retention=5)
        with pytest.raises(ImmutabilityError):
            store.delete("a")
        assert store.get("a") == b"original"


def test_worm_store_allows_write_after_retention_expires():
    with tempfile.TemporaryDirectory() as tmp:
        store = WormFileStore(os.path.join(tmp, "s"))
        store.put("a", b"v1", retention=3)
        store.tick(3)                      # retention window elapses
        store.put("a", b"v2", retention=3)  # now permitted
        assert store.get("a") == b"v2"


def test_live_copies_are_destroyed_but_recovery_is_clean():
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        assets = _assets(5)
        drill.backup(assets)
        blocked = drill.simulate_attack()
        assert blocked is True
        # every live copy is now ransomware-encrypted...
        for name in assets:
            with open(os.path.join(drill.live_dir, name), "rb") as f:
                assert f.read() == b"ENCRYPTED_BY_RANSOMWARE"
        # ...but recovery from the immutable store restores the originals
        drill.restore()
        report = drill.validate(blocked)
        assert report.recovery_fidelity == 1.0


def test_integrity_stage_fails_on_corrupted_recovery_point():
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        assets = _assets(4)
        drill.backup(assets)
        blocked = drill.simulate_attack()
        drill.restore()
        # corrupt one recovered file inside the clean room
        victim = os.path.join(drill.clean_room, "docs/asset_00.bin")
        with open(victim, "wb") as f:
            f.write(b"corrupted-in-clean-room")
        report = drill.validate(blocked)
        assert report.passed == 3           # the corrupted one fails
        assert report.per_asset["docs/asset_00.bin"].integrity is False
        assert 0.0 < report.recovery_fidelity < 1.0


def test_missing_recovery_point_fails_completeness():
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        assets = _assets(4)
        drill.backup(assets)
        blocked = drill.simulate_attack()
        drill.restore()
        os.remove(os.path.join(drill.clean_room, "docs/asset_01.bin"))
        report = drill.validate(blocked)
        assert report.per_asset["docs/asset_01.bin"].completeness is False
        assert report.passed == 3


def test_immutability_failure_zeroes_all_assets():
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        drill.backup(_assets(4))
        drill.restore()
        # if the store had NOT blocked tampering, no asset can pass all stages
        report = drill.validate(tamper_blocked=False)
        assert report.passed == 0
        assert all(res.immutability is False for res in report.per_asset.values())


# --- DRRA-083 finding 4: path-traversal / escape safety ---------------------

def test_worm_store_rejects_absolute_and_traversal_names():
    from backend.services.grab_recovery import UnsafePathError
    with tempfile.TemporaryDirectory() as tmp:
        store = WormFileStore(os.path.join(tmp, "s"))
        for bad in ["../escape.bin", "a/../../escape.bin", "/etc/passwd",
                    "\\\\server\\share\\x", "C:\\windows\\x", "", "   "]:
            with pytest.raises(UnsafePathError):
                store.put(bad, b"x")


def test_drill_backup_rejects_unsafe_asset_name():
    from backend.services.grab_recovery import UnsafePathError
    with tempfile.TemporaryDirectory() as tmp:
        drill = GrabRecoveryDrill(tmp)
        with pytest.raises(UnsafePathError):
            drill.backup({"../../evil.bin": b"payload"})


def test_worm_store_blocks_symlink_escape():
    from backend.services.grab_recovery import UnsafePathError
    with tempfile.TemporaryDirectory() as tmp:
        outside = os.path.join(tmp, "outside")
        os.makedirs(outside)
        root = os.path.join(tmp, "s")
        store = WormFileStore(root)
        # plant a symlink inside the store root that points outside it
        link = os.path.join(store.root, "link")
        os.symlink(outside, link)
        with pytest.raises(UnsafePathError):
            store.put("link/escaped.bin", b"x")   # realpath escapes root -> rejected
