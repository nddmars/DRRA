"""Services package.

Intentionally free of eager submodule imports: importing a lightweight,
dependency-free service (e.g. ``services.defensibility``) must not drag in the
database/Kafka/MinIO stack. Import the concrete service module you need
directly, e.g. ``from services.vigil_service import VigilService``.

``VigilService`` and ``TelemetryService`` remain importable from this package
via lazy resolution for backwards compatibility.
"""

__all__ = ["VigilService", "TelemetryService"]


def __getattr__(name):  # PEP 562 lazy attribute access
    if name in ("VigilService", "TelemetryService"):
        from .vigil_service import VigilService, TelemetryService

        return {"VigilService": VigilService, "TelemetryService": TelemetryService}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
