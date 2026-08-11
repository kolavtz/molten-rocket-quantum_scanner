import sys
from sqlalchemy import create_engine, inspect
import traceback

sys.path.append('.')
from src.db import engine
from src.models import Base

def check_drift():
    db_inspector = inspect(engine)
    discrepancies = []

    # Get local models
    for table_name, table_obj in Base.metadata.tables.items():
        if table_name not in db_inspector.get_table_names():
            discrepancies.append(f"Missing Table in DB: {table_name}")
            continue

        db_columns = {col['name'].lower(): col for col in db_inspector.get_columns(table_name)}
        model_columns = table_obj.columns

        for m_col in model_columns:
             if m_col.name.lower() not in db_columns:
                  discrepancies.append(f"Missing Column in DB: Table '{table_name}', Column '{m_col.name}'")

    if not discrepancies:
        print("Schema fully synchronized with live DB.")
    else:
        print("\n=== SCHEMA DRIFT DETECTED ===")
        for d in discrepancies:
            print(f"- {d}")
        print("\nRun corresponding ALTER statements to fix.")

check_drift()
