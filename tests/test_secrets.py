"""
DRRA-006 — External secrets resolution and fail-fast config enforcement.

Covers the secret provider (file-mount precedence, provider posture, rotation,
required-missing) and the production config gate (audit + hard failure on
insecure defaults).
"""

from __future__ import annotations

import os
import sys

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_REPO, os.path.join(_REPO, "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

from utils.secrets import get_secret, SecretResolutionError  # noqa: E402


# --- provider resolution ----------------------------------------------------

def test_env_value_is_used(monkeypatch):
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.setenv("DRRA_TEST_SECRET", "from-env")
    assert get_secret("DRRA_TEST_SECRET") == "from-env"


def test_default_used_when_unset(monkeypatch):
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET_FILE", raising=False)
    assert get_secret("DRRA_TEST_SECRET", "fallback") == "fallback"


def test_file_mount_takes_precedence_over_env(monkeypatch, tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file\n")  # trailing newline is stripped
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.setenv("DRRA_TEST_SECRET", "from-env")
    monkeypatch.setenv("DRRA_TEST_SECRET_FILE", str(secret_file))
    assert get_secret("DRRA_TEST_SECRET") == "from-file"


def test_file_provider_ignores_plain_env(monkeypatch):
    monkeypatch.setenv("SECRETS_PROVIDER", "file")
    monkeypatch.setenv("DRRA_TEST_SECRET", "from-env")
    monkeypatch.delenv("DRRA_TEST_SECRET_FILE", raising=False)
    # In file-only posture a plain env var must NOT satisfy the secret.
    assert get_secret("DRRA_TEST_SECRET", None) is None


def test_required_missing_raises(monkeypatch):
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET_FILE", raising=False)
    with pytest.raises(SecretResolutionError):
        get_secret("DRRA_TEST_SECRET", required=True)


def test_rotation_is_observed_on_next_read(monkeypatch, tmp_path):
    secret_file = tmp_path / "rotating"
    secret_file.write_text("v1")
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET", raising=False)
    monkeypatch.setenv("DRRA_TEST_SECRET_FILE", str(secret_file))
    assert get_secret("DRRA_TEST_SECRET") == "v1"
    secret_file.write_text("v2")  # simulate a secrets-manager rotation
    assert get_secret("DRRA_TEST_SECRET") == "v2"


def test_missing_file_raises_only_when_required(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.delenv("DRRA_TEST_SECRET", raising=False)
    monkeypatch.setenv("DRRA_TEST_SECRET_FILE", str(tmp_path / "does-not-exist"))
    # not required -> falls through to default
    assert get_secret("DRRA_TEST_SECRET", "fallback") == "fallback"
    # required -> the unreadable mount is an error
    with pytest.raises(SecretResolutionError):
        get_secret("DRRA_TEST_SECRET", "fallback", required=True)


# --- config enforcement -----------------------------------------------------

def _secure_env(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "a-real-32-byte-random-value-xxxxx")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "real-access-key")
    monkeypatch.setenv("MINIO_SECRET_KEY", "real-secret-key")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:realpw@db:5432/forge")
    monkeypatch.setenv("MINIO_SECURE", "true")


def test_audit_flags_insecure_defaults(monkeypatch):
    for k in ("SECRET_KEY", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
              "DATABASE_URL", "MINIO_SECURE", "SECRETS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    from config import Settings
    problems = Settings().assert_production_ready()
    joined = " ".join(problems).lower()
    assert "secret_key" in joined
    assert "minioadmin" in joined
    assert "default database password" in joined


def test_enforce_raises_on_insecure_defaults(monkeypatch):
    for k in ("SECRET_KEY", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
              "DATABASE_URL", "MINIO_SECURE", "SECRETS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    from config import Settings
    with pytest.raises(RuntimeError):
        Settings().enforce_secure_config()


def test_enforce_passes_with_real_secrets(monkeypatch):
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    _secure_env(monkeypatch)
    from config import Settings
    s = Settings()
    # should not raise
    s.enforce_secure_config()
    assert s.assert_production_ready() == []


def test_settings_reads_secret_from_file_mount(monkeypatch, tmp_path):
    for k in ("SECRET_KEY", "SECRETS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    key_file = tmp_path / "secret_key"
    key_file.write_text("file-mounted-secret-key")
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    from config import Settings
    s = Settings()
    assert s.SECRET_KEY == "file-mounted-secret-key"


def test_refresh_secrets_picks_up_rotation(monkeypatch, tmp_path):
    for k in ("SECRET_KEY", "SECRETS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    key_file = tmp_path / "secret_key"
    key_file.write_text("v1-key")
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    from config import Settings
    s = Settings()
    assert s.SECRET_KEY == "v1-key"
    key_file.write_text("v2-key")   # rotate the mounted secret
    s.refresh_secrets()
    assert s.SECRET_KEY == "v2-key"
