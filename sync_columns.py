import sys
from sqlalchemy import text

sys.path.append('.')
from src.db import engine

def sync():
    statements = [
        "ALTER TABLE certificates ADD COLUMN subject_cn VARCHAR(255) NULL",
        "ALTER TABLE pqc_classification ADD COLUMN updated_at DATETIME NULL"
    ]

    with engine.connect() as conn:
        for stmt in statements:
            try:
                 conn.execute(text(stmt))
                 print(f"Executed: {stmt}")
            except Exception as e:
                 print(f"Error executing '{stmt}': {e}")
        # Explicit commit if using transactions context
        conn.commit()

sync()
print("Synchronization attempt complete.")
