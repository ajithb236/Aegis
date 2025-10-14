#entry point for server
#src\app\main.py
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.init_db import init_db
from app.utils.logger import get_logger

# Import routers
from app.api.v1 import alerts#, keymgmt


#init app
app = FastAPI(
    title="Aegis",
    description="A privacy-preserving alert exchange system with hybrid encryption, digital signatures, and homomorphic analytics.",
    version="1.0"
)

# Init logger
logger = get_logger()
logger.info("Starting application...")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing database connection...")
    await init_db()
    logger.info("Database connected successfully.")

#register routers
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
#app.include_router(keymgmt.router, prefix="/api/v1/keys", tags=["Key Management"])


@app.get("/", tags=["Root"])
async def root():
    """
    Landing route - confirms API is alive.
    """
    return {
        "message": "Server is running",
        "version": app.version
    }


@app.get("/health", tags=["System"])
async def health_check():
    """
    Basic system health check.
    """
    return {"status": "OK"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True
    )
