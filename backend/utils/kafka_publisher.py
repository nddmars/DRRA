"""
Kafka producer for event streaming and telemetry publishing.
"""

import logging
from kafka import KafkaProducer
from kafka.errors import KafkaError
from config import settings
import json
from typing import Optional

logger = logging.getLogger(__name__)

class KafkaEventPublisher:
    """Publisher for Kafka event topics."""
    
    # Topic names
    THREAT_EVENTS_TOPIC = "threat-events"
    ISOLATION_EVENTS_TOPIC = "isolation-events"
    RECOVERY_EVENTS_TOPIC = "recovery-events"
    TELEMETRY_TOPIC = "telemetry"
    
    def __init__(self):
        """Initialize Kafka producer."""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS.split(','),
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                acks='all',  # Wait for all replicas
                retries=3,
                max_in_flight_requests_per_connection=1,  # Preserve ordering
            )
            logger.info(f"Kafka producer initialized: {settings.KAFKA_BOOTSTRAP_SERVERS}")
        except Exception as e:
            logger.error(f"Failed to initialize Kafka producer: {e}")
            self.producer = None
    
    def publish_threat_event(self, event_data: dict) -> Optional[str]:
        """Publish threat detection event."""
        if not self.producer:
            logger.warning("Kafka producer not available")
            return None
        
        try:
            future = self.producer.send(
                self.THREAT_EVENTS_TOPIC,
                value=event_data,
                key=event_data.get('event_id', '').encode('utf-8')
            )
            
            # Wait for send to complete
            record_metadata = future.get(timeout=10)
            logger.info(f"Published threat event to Kafka: topic={record_metadata.topic}, partition={record_metadata.partition}, offset={record_metadata.offset}")
            return event_data.get('event_id')
        except KafkaError as e:
            logger.error(f"Failed to publish threat event to Kafka: {e}")
            return None
    
    def publish_isolation_event(self, event_data: dict) -> Optional[str]:
        """Publish isolation/containment action."""
        if not self.producer:
            logger.warning("Kafka producer not available")
            return None
        
        try:
            future = self.producer.send(
                self.ISOLATION_EVENTS_TOPIC,
                value=event_data,
                key=event_data.get('isolation_id', '').encode('utf-8')
            )
            
            record_metadata = future.get(timeout=10)
            logger.info(f"Published isolation event to Kafka: topic={record_metadata.topic}, partition={record_metadata.partition}")
            return event_data.get('isolation_id')
        except KafkaError as e:
            logger.error(f"Failed to publish isolation event to Kafka: {e}")
            return None
    
    def publish_recovery_event(self, event_data: dict) -> Optional[str]:
        """Publish recovery operation event."""
        if not self.producer:
            logger.warning("Kafka producer not available")
            return None
        
        try:
            future = self.producer.send(
                self.RECOVERY_EVENTS_TOPIC,
                value=event_data,
                key=event_data.get('task_id', '').encode('utf-8')
            )
            
            record_metadata = future.get(timeout=10)
            logger.info(f"Published recovery event to Kafka: topic={record_metadata.topic}")
            return event_data.get('task_id')
        except KafkaError as e:
            logger.error(f"Failed to publish recovery event to Kafka: {e}")
            return None
    
    def publish_telemetry(self, event_data: dict) -> Optional[str]:
        """Publish raw telemetry data."""
        if not self.producer:
            logger.warning("Kafka producer not available")
            return None
        
        try:
            future = self.producer.send(
                self.TELEMETRY_TOPIC,
                value=event_data
            )
            
            record_metadata = future.get(timeout=10)
            logger.debug(f"Published telemetry to Kafka: offset={record_metadata.offset}")
            return "published"
        except KafkaError as e:
            logger.error(f"Failed to publish telemetry to Kafka: {e}")
            return None
    
    def close(self):
        """Close producer and flush pending messages."""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            logger.info("Kafka producer closed")

# Global Kafka publisher instance
kafka_publisher = KafkaEventPublisher()
