import sys
import os

# Ensure config can be loaded
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import create_engine, MetaData
from config import SQLALCHEMY_DATABASE_URI
import traceback

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URI)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    print("Found Tables in Database:")
    for table in metadata.sorted_tables:
        print(f"\nTable: {table.name}")
        for col in table.columns:
            pk = " (PK)" if col.primary_key else ""
            print(f"  - {col.name} ({col.type}){pk}")
except Exception as e:
    print("Failed to reflect database:")
    print(traceback.format_exc())
