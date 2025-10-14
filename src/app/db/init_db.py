# src/app/db/init_db.py
import os
import asyncpg
from dotenv import load_dotenv
from pathlib import Path

# Load .env
env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(env_path)

DB_CONFIG = {
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "user"),
    "database": os.getenv("POSTGRES_DB", "threatintel"),
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", 5432)),
}

# -------------------- DB CONNECTION --------------------
async def get_db_connection():
    """Create and return an async PostgreSQL connection."""
    try:
        conn = await asyncpg.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"[DB ERROR] Connection failed: {e}")
        raise

# -------------------- INIT DB --------------------
async def init_db():
    """Initialize database tables from SQL file asynchronously."""
    conn = await get_db_connection()
    try:
        migration_path = os.path.join(os.path.dirname(__file__), "migrations/001_create_tables.sql")
        with open(migration_path, "r") as f:
            sql_script = f.read()
        await conn.execute(sql_script)
        print("[DB] Tables created or verified successfully.")
    except Exception as e:
        print(f"[DB ERROR] Initialization failed: {e}")
    finally:
        await conn.close()

# -------------------- SCRIPT RUN --------------------
if __name__ == "__main__":
    import asyncio
    asyncio.run(init_db())
