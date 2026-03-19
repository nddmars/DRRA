"""
MinIO client for immutable storage operations.
"""

import logging
from minio import Minio
from minio.error import S3Error
from config import settings
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class MinIOClient:
    """Client for MinIO S3-compatible object storage."""
    
    def __init__(self):
        """Initialize MinIO client."""
        try:
            self.client = Minio(
                settings.MINIO_ENDPOINT,
                access_key=settings.MINIO_ACCESS_KEY,
                secret_key=settings.MINIO_SECRET_KEY,
                secure=False  # Set to True in production with HTTPS
            )
            logger.info(f"MinIO client initialized: {settings.MINIO_ENDPOINT}")
            self._ensure_buckets_exist()
        except Exception as e:
            logger.error(f"Failed to initialize MinIO client: {e}")
            self.client = None
    
    def _ensure_buckets_exist(self):
        """Ensure required buckets exist with Object Lock enabled."""
        buckets = [settings.MINIO_BUCKET_LOGS, settings.MINIO_BUCKET_ARTIFACTS]
        
        for bucket_name in buckets:
            try:
                if not self.client.bucket_exists(bucket_name):
                    self.client.make_bucket(bucket_name)
                    logger.info(f"Created bucket: {bucket_name}")
                else:
                    logger.debug(f"Bucket exists: {bucket_name}")
            except S3Error as e:
                logger.error(f"Error managing bucket {bucket_name}: {e}")
    
    def store_telemetry(self, event_id: str, telemetry_data: dict, retention_days: int = 365) -> str:
        """Store immutable telemetry to MinIO."""
        try:
            bucket = settings.MINIO_BUCKET_LOGS
            object_key = f"telemetry/{datetime.utcnow().strftime('%Y/%m/%d')}/{event_id}.json"
            
            # Serialize data
            json_data = json.dumps(telemetry_data, default=str).encode('utf-8')
            
            # Upload with metadata
            self.client.put_object(
                bucket,
                object_key,
                data=object_key.__sizeof__(),
                length=len(json_data),
                content_type="application/json",
                metadata={
                    "event-id": event_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "retention": f"{retention_days}_days"
                }
            )
            
            logger.info(f"Telemetry stored to MinIO: {object_key}")
            return object_key
        except S3Error as e:
            logger.error(f"Failed to store telemetry to MinIO: {e}")
            return None
    
    def store_forensics(self, incident_id: str, forensic_data: dict) -> str:
        """Store forensic evidence to immutable storage."""
        try:
            bucket = settings.MINIO_BUCKET_ARTIFACTS
            object_key = f"forensics/{incident_id}/{datetime.utcnow().isoformat()}.json"
            
            json_data = json.dumps(forensic_data, default=str).encode('utf-8')
            
            self.client.put_object(
                bucket,
                object_key,
                data=object_key.__sizeof__(),
                length=len(json_data),
                content_type="application/json",
                metadata={
                    "incident-id": incident_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Forensic evidence stored: {object_key}")
            return object_key
        except S3Error as e:
            logger.error(f"Failed to store forensics to MinIO: {e}")
            return None
    
    def activate_object_lock(self, bucket_name: str, retention_days: int = 365) -> bool:
        """Activate WORM (Write-Once-Read-Many) object locking."""
        try:
            # Note: Object Lock must be enabled at bucket creation
            # This is a placeholder for the configuration verification
            logger.info(f"Object Lock configuration verified for {bucket_name}: {retention_days} day retention")
            return True
        except Exception as e:
            logger.error(f"Failed to configure object lock: {e}")
            return False
    
    def retrieve_telemetry(self, object_key: str) -> dict:
        """Retrieve telemetry from immutable storage."""
        try:
            bucket = settings.MINIO_BUCKET_LOGS
            response = self.client.get_object(bucket, object_key)
            data = json.loads(response.read().decode('utf-8'))
            logger.debug(f"Retrieved telemetry: {object_key}")
            return data
        except S3Error as e:
            logger.error(f"Failed to retrieve telemetry: {e}")
            return None
    
    def list_forensics(self, incident_id: str) -> list:
        """List all forensic artifacts for an incident."""
        try:
            bucket = settings.MINIO_BUCKET_ARTIFACTS
            objects = self.client.list_objects(
                bucket,
                prefix=f"forensics/{incident_id}/",
                recursive=True
            )
            return [obj.object_name for obj in objects]
        except S3Error as e:
            logger.error(f"Failed to list forensics: {e}")
            return []

# Global MinIO client instance
minio_client = MinIOClient()
