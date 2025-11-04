import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
from app.db.init_db import get_db_connection

async def run_migration(filename: str):
    conn = await get_db_connection()
    try:
        migration_path = Path(__file__).parent.parent  / "db" / "migrations" / filename
        with open(migration_path, "r") as f:
            sql = f.read()
        await conn.execute(sql) 
        print(f"Migration {filename} completed successfully")
    except Exception as e:
        print(f"Migration failed: {e}")
        raise
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration("003_add_encrypted_keys.sql"))