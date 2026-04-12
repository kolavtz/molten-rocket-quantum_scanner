import sys
from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateColumn
from sqlalchemy.exc import CompileError
from sqlalchemy import String, Text

sys.path.append('.')
from src.db import engine
from src.models import Base

def fix_schema():
    print("Creating all missing tables...")
    try:
        Base.metadata.create_all(engine)
    except Exception as e:
        print(f"create_all error (ignoring): {e}")

    db_inspector = inspect(engine)
    
    with engine.begin() as conn:
        for table_name, table_obj in Base.metadata.tables.items():
            if table_name not in db_inspector.get_table_names():
                continue
                
            db_columns = {col['name'].lower(): col for col in db_inspector.get_columns(table_name)}
            model_columns = table_obj.columns

            for m_col in model_columns:
                if m_col.name.lower() not in db_columns:
                    if isinstance(m_col.type, String) and m_col.type.length is None:
                        m_col.type.length = 255
                    
                    try:
                        col_str = str(CreateColumn(m_col).compile(dialect=engine.dialect)).strip()
                        alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN {col_str};"
                        print(f"Executing: {alter_stmt}")
                        conn.execute(text(alter_stmt))
                    except Exception as e:
                        if 'Duplicate column name' not in str(e):
                            print(f"Error adding column {m_col.name} in table {table_name}: {e}")

if __name__ == '__main__':
    fix_schema()
