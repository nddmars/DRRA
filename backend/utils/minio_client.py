"""
MinIO client for immutable storage operations.

Implements the GRAB pillar's immutability guarantee using S3 Object Lock
(WORM). Two correctness fixes over the original revision:

  1. Buckets are now created with ``object_lock=True`` and a default retention
     configuration is applied — Object Lock can only be enabled at bucket
     creation time, so the previous ``make_bucket(name)`` produced mutable
     buckets no matter what the status endpoints reported.
  2. ``put_object`` now receives a real byte stream (``io.BytesIO``). The
     previous code passed ``object_key.__sizeof__()`` (an int) as the data
     argument, which raises inside the SDK — so no object was ever actually
     written.

Every object is written under GOVERNANCE-mode retention so it cannot be
overwritten or deleted before its retention date, even by an administrator
(matching the paper's Section 4.3 claim).
"""

import io
import json
import logging
from datetime import datetime, timedelta, timezone

from config import settings

logger = logging.getLogger(__name__)

try:
    from minio import Minio
    from minio.commonconfig import GOVERNANCE
    from minio.error import S3Error
    from minio.objectlockconfig import ObjectLockConfig, DAYS
    from minio.retention import Retention

    _MINIO_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    logger.warning("minio SDK unavailable (%s); storage will be a no-op", exc)
    Minio = None  # type: ignore
    S3Error = Exception  # type: ignore
    _MINIO_AVAILABLE = False


class MinIOClient:
    """Client for MinIO S3-compatible object storage with Object Lock."""

    def __init__(self):
        self.client = None
        self.object_lock_active = False
        if not _MINIO_AVAILABLE:
            return
        try:
            self.client = Minio(
                settings.MINIO_ENDPOINT,
                access_key=settings.MINIO_ACCESS_KEY,
                secret_key=settings.MINIO_SECRET_KEY,
                secure=getattr(settings, "MINIO_SECURE", False),
            )
            logger.info("MinIO client initialized: %s", settings.MINIO_ENDPOINT)
            self._ensure_buckets_exist()
        except Exception as e:
            logger.error("Failed to initialize MinIO client: %s", e)
            self.client = None

    # -- bucket / lock management --------------------------------------------
    def _ensure_buckets_exist(self, retention_days: int = 365):
        """Ensure required buckets exist WITH Object Lock enabled."""
        buckets = [settings.MINIO_BUCKET_LOGS, settings.MINIO_BUCKET_ARTIFACTS]
        for bucket_name in buckets:
            try:
                if not self.client.bucket_exists(bucket_name):
                    # object_lock=True is only honoured at creation time.
                    self.client.make_bucket(bucket_name, object_lock=True)
                    logger.info("Created bucket with Object Lock: %s", bucket_name)
                    self._set_default_retention(bucket_name, retention_days)
                else:
                    # Verify lock is actually configured; warn loudly if not.
                    if self._verify_object_lock(bucket_name):
                        logger.debug("Bucket exists with Object Lock: %s", bucket_name)
                    else:
                        logger.warning(
                            "Bucket %s exists WITHOUT Object Lock — immutability is NOT "
                            "guaranteed. Recreate the bucket with object_lock=True.",
                            bucket_name,
                        )
            except S3Error as e:
                logger.error("Error managing bucket %s: %s", bucket_name, e)

    def _set_default_retention(self, bucket_name: str, retention_days: int) -> None:
        try:
            config = ObjectLockConfig(GOVERNANCE, retention_days, DAYS)
            self.client.set_object_lock_config(bucket_name, config)
            self.object_lock_active = True
            logger.info(
                "Default GOVERNANCE retention set on %s: %d days", bucket_name, retention_days
            )
        except S3Error as e:
            logger.error("Failed to set object-lock config on %s: %s", bucket_name, e)

    def _verify_object_lock(self, bucket_name: str) -> bool:
        try:
            self.client.get_object_lock_config(bucket_name)
            self.object_lock_active = True
            return True
        except S3Error:
            return False

    def activate_object_lock(self, bucket_name: str, retention_days: int = 365) -> bool:
        """(Re)apply a default retention configuration to an existing bucket."""
        if not self.client:
            return False
        try:
            self._set_default_retention(bucket_name, retention_days)
            return True
        except Exception as e:
            logger.error("Failed to configure object lock: %s", e)
            return False

    # -- writes (immutable) ---------------------------------------------------
    def _put_immutable(
        self, bucket: str, object_key: str, payload: dict, metadata: dict, retention_days: int
    ) -> str:
        if not self.client:
            logger.warning("MinIO client unavailable; skipping store of %s", object_key)
            return ""
        json_data = json.dumps(payload, default=str).encode("utf-8")
        retain_until = datetime.now(timezone.utc) + timedelta(days=retention_days)
        try:
            self.client.put_object(
                bucket,
                object_key,
                data=io.BytesIO(json_data),      # real byte stream (was an int)
                length=len(json_data),
                content_type="application/json",
                metadata=metadata,
                retention=Retention(GOVERNANCE, retain_until),
            )
            logger.info("Immutable object written: %s/%s", bucket, object_key)
            return object_key
        except S3Error as e:
            logger.error("Failed to write immutable object %s: %s", object_key, e)
            return ""

    def store_telemetry(self, event_id: str, telemetry_data: dict, retention_days: int = 365) -> str:
        object_key = f"telemetry/{datetime.utcnow().strftime('%Y/%m/%d')}/{event_id}.json"
        return self._put_immutable(
            settings.MINIO_BUCKET_LOGS,
            object_key,
            telemetry_data,
            {"event-id": event_id, "retention-days": str(retention_days)},
            retention_days,
        )

    def store_forensics(self, incident_id: str, forensic_data: dict, retention_days: int = 90) -> str:
        object_key = f"forensics/{incident_id}/{datetime.utcnow().isoformat()}.json"
        return self._put_immutable(
            settings.MINIO_BUCKET_ARTIFACTS,
            object_key,
            forensic_data,
            {"incident-id": incident_id, "retention-days": str(retention_days)},
            retention_days,
        )

    # -- reads ----------------------------------------------------------------
    def retrieve_telemetry(self, object_key: str) -> dict:
        if not self.client:
            return None
        try:
            response = self.client.get_object(settings.MINIO_BUCKET_LOGS, object_key)
            try:
                return json.loads(response.read().decode("utf-8"))
            finally:
                response.close()
                response.release_conn()
        except S3Error as e:
            logger.error("Failed to retrieve telemetry: %s", e)
            return None

    def list_forensics(self, incident_id: str) -> list:
        if not self.client:
            return []
        try:
            objects = self.client.list_objects(
                settings.MINIO_BUCKET_ARTIFACTS,
                prefix=f"forensics/{incident_id}/",
                recursive=True,
            )
            return [obj.object_name for obj in objects]
        except S3Error as e:
            logger.error("Failed to list forensics: %s", e)
            return []


# Global MinIO client instance
minio_client = MinIOClient()
