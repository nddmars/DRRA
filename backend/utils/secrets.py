"""
DRRA-006 — External secrets resolution.

Production deployments must not read secrets from baked-in defaults or from a
committed ``.env``. This module resolves a logical secret name from an external
provider, in priority order:

  1. ``{NAME}_FILE`` — a path to a file whose contents are the secret. This is
     the delivery mechanism used by every mainstream secrets manager mount:
     HashiCorp Vault Agent, Kubernetes Secrets, Docker/Swarm secrets, and the
     AWS/GCP secret CSI drivers all project a secret onto a file. The file is
     re-read on every call, so rotating the mounted file is picked up without a
     process restart (see ``rotation`` note below).
  2. ``{NAME}`` — a plain environment variable (developer convenience / CI).
  3. ``default`` — a caller-supplied fallback. In production the fail-fast audit
     (config.enforce_secure_config) rejects any secret still sitting on a known
     insecure default.

``SECRETS_PROVIDER`` selects the posture:
  * ``env``  (default) — resolve from ``_FILE`` mounts or environment.
  * ``file`` — resolve ONLY from ``_FILE`` mounts; a secret that is not backed
    by a file is treated as unset (a plain env var will NOT satisfy it). Use
    this to prove a deployment takes every secret from mounted files.

Rotation: because ``_FILE`` secrets are read on each ``get_secret`` call,
components that resolve a secret per use (or that call ``refresh`` on a settings
object) observe a rotated file immediately. Long-lived client connections that
captured a credential at open time (DB pool, object-store client) still need to
be re-established to pick up the new value — that re-establishment is tracked as
follow-up, not claimed here.
"""

from __future__ import annotations

import os
from typing import Optional


class SecretResolutionError(RuntimeError):
    """A required secret could not be resolved from any configured provider."""


def _provider() -> str:
    return os.getenv("SECRETS_PROVIDER", "env").strip().lower()


def _read_file_secret(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            # Trailing newline is conventional in mounted secret files; strip it
            # (but preserve any internal whitespace of the secret itself).
            return fh.read().rstrip("\n")
    except OSError:
        return None


def get_secret(name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """Resolve secret ``name`` from the configured provider.

    Precedence: ``{name}_FILE`` mount, then (in ``env`` provider) the ``{name}``
    environment variable, then ``default``. Raises ``SecretResolutionError`` when
    ``required`` is set and nothing but the (absent) default resolves.
    """
    file_env = os.getenv(f"{name}_FILE")
    if file_env:
        value = _read_file_secret(file_env)
        if value is not None:
            return value
        if required:
            raise SecretResolutionError(
                f"{name}_FILE is set to {file_env!r} but the file could not be read"
            )

    if _provider() != "file":
        env_value = os.getenv(name)
        if env_value is not None:
            return env_value

    if required and default is None:
        raise SecretResolutionError(
            f"required secret {name!r} is not set (no {name}_FILE mount"
            + ("" if _provider() == "file" else f", no {name} env var")
            + " and no default)"
        )
    return default
