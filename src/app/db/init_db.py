# src/app/db/init_db.py
import os
import asyncpg
from dotenv import load_dotenv
from pathlib import Path
from typing import Optional

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

# Global connection pool
_pool: Optional[asyncpg.Pool] = None

# -------------------- POOL MANAGEMENT --------------------
async def get_pool() -> asyncpg.Pool:
    """Get or create the connection pool."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            **DB_CONFIG,
            min_size=2,
            max_size=10,
            command_timeout=60
        )
    return _pool

async def close_pool():
    """Close the connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None

#override close to release to pool,instead for actually closing connection
class PooledConnection:
    """Wrapper that releases connection to pool when close() is called."""
    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool
        self._closed = False

    async def close(self):
        """Release connection back to pool instead of closing it,reducing codebase changes."""
        if not self._closed:
            await self._pool.release(self._conn)
            self._closed = True

    def __getattr__(self, name):
        """Delegate all other methods to the og conn object."""
        return getattr(self._conn, name)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

#called by all modules
async def get_db_connection():
    """Create and return an async PostgreSQL connection from the pool."""
    try:
        pool = await get_pool()
        conn = await pool.acquire()
        return PooledConnection(conn, pool)
    except Exception as e:
        print(f"[DB ERROR] Connection failed: {e}")
        raise


async def init_db():
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


if __name__ == "__main__":
    import asyncio
    asyncio.run(init_db())