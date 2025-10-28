#entry point for server
#src\app\main.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.init_db import init_db
from app.utils.logger import get_logger



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
    
    # Load Paillier keys for homomorphic encryption
    try:
        from app.crypto.paillier_key_manager import load_paillier_keys
        public_key, private_key = load_paillier_keys()
        logger.info(f"Paillier keys loaded successfully (n={len(str(public_key.n))} digits)")
    except Exception as e:
        logger.warning(f"Failed to load Paillier keys: {e}")
        logger.warning("Run 'python src/scripts/init_paillier_keys.py' to generate keys")


from app.api.v1 import alerts, orgs, auth  # Add auth


app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(orgs.router, prefix="/api/v1/orgs", tags=["Organizations"])

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
    returns status
    """
    return {"status": "OK"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True
    )
