"""
Resilience Forge (DRRA) - Main FastAPI Application

The core orchestration engine for ransomware defense and resilience testing.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
from contextlib import asynccontextmanager

from config import settings
from routes import (
    forge_router,
    vigil_router,
    shield_router,
    dashboard_router,
    health_router
)
from db.session import init_db
from utils.kafka_publisher import kafka_publisher
from utils.minio_client import minio_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan event handler."""
    logger.info("🔥 Resilience Forge starting up...")
    
    # Initialize database tables
    try:
        init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
    
    # Verify integrations
    logger.info(f"✅ MinIO client ready: {minio_client.client is not None}")
    logger.info(f"✅ Kafka producer ready: {kafka_publisher.producer is not None}")
    
    yield
    
    logger.info("🛡️ Resilience Forge shutting down...")
    # Close Kafka producer
    kafka_publisher.close()

# Create FastAPI application
app = FastAPI(
    title="Resilience Forge (DRRA)",
    description="Distributed Resilience & Recovery Architecture - Industry standard for ransomware-proof ecosystems",
    version="0.1.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router.router, prefix="/api/v1", tags=["Health"])
app.include_router(forge_router.router, prefix="/api/v1/forge", tags=["Forge Trigger"])
app.include_router(vigil_router.router, prefix="/api/v1/vigil", tags=["Vigil Detection"])
app.include_router(shield_router.router, prefix="/api/v1/shield", tags=["Shield Recovery"])
app.include_router(dashboard_router.router, prefix="/api/v1/dashboard", tags=["Dashboard"])

@app.get("/")
async def root():
    """Root endpoint with system status."""
    return {
        "name": "Resilience Forge (DRRA)",
        "tagline": "The industry standard for architecting, testing, and validating ransomware-proof ecosystems",
        "status": "operational",
        "version": "0.1.0"
    }

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
