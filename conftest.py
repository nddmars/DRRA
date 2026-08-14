"""
Pytest bootstrap for the DRRA test suite.

Fixes the import paths that previously made test collection fail:
  * the repo root is added so ``import backend.services...`` resolves;
  * ``backend/`` is added so the backend's own top-level imports
    (``from utils...``, ``from config import settings``) resolve.

Also provides the shared ``client`` fixture used by the API-level tests and a
helper for skipping tests that need live infrastructure (PostgreSQL, Kafka,
MinIO) when it is not available.
"""

import os
import socket
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.join(_REPO_ROOT, "backend")
for p in (_REPO_ROOT, _BACKEND):
    if p not in sys.path:
        sys.path.insert(0, p)

# Keep detection deterministic and offline for tests.
os.environ.setdefault("GEMINI_API_KEY", "")


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def infra_available() -> bool:
    """True only when the core backing services appear reachable."""
    return (
        _port_open("localhost", 5432)   # PostgreSQL
        and _port_open("localhost", 9092)  # Kafka
        and _port_open("localhost", 9000)  # MinIO
    )


requires_infra = pytest.mark.skipif(
    not infra_available(),
    reason="requires live PostgreSQL/Kafka/MinIO (start docker-compose stack)",
)


@pytest.fixture(scope="session")
def app():
    """Import and return the FastAPI app (path setup already done above)."""
    from main import app as fastapi_app

    return fastapi_app


@pytest.fixture
async def client(app):
    """Async HTTP client bound to the ASGI app for endpoint tests."""
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
