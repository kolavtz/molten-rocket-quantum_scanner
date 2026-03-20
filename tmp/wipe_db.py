import sys
import os

# Ensure config can be loaded
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import create_engine, MetaData, text
from config import SQLALCHEMY_DATABASE_URI
import traceback

if __name__ == "__main__":
    try:
        print("Connecting to database...")
        engine = create_engine(SQLALCHEMY_DATABASE_URI)
        metadata = MetaData()
        
        print("Reflecting all legacy tables...")
        metadata.reflect(bind=engine)
        
        print(f"Dropping {len(metadata.sorted_tables)} existing tables...")
        with engine.begin() as conn:
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
            metadata.drop_all(bind=conn)
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
            
        print("Successfully wiped all tables.")
        
        print("Generating new ORM schemas...")
        from src.db import init_db
        init_db()
        print("Schema generation complete.")
        
    except Exception as e:
        err_path = os.path.join(os.path.dirname(__file__), 'err.log')
        with open(err_path, 'w', encoding='utf-8') as f:
            f.write(traceback.format_exc())
        print(f"Failure captured in {err_path}")
        sys.exit(1)
