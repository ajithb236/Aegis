# src/app/scripts/reset_db.py
import sys
from pathlib import Path

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
from app.db.init_db import get_db_connection

async def main():
    conn = await get_db_connection()
    tables = ["alerts", "rsa_keys", "organizations", "audit_logs"]
    for t in tables:
        await conn.execute(f"TRUNCATE TABLE {t} RESTART IDENTITY CASCADE")
        print(f"Table {t} cleared.")
    await conn.close()

if __name__ == "__main__":
    asyncio.run(main())
