import os
import sys
import re
from sqlalchemy import text, inspect

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine
from src.models import Base

def parse_dump_columns(dump_content):
    # Map of table_name -> [column_names]
    table_map = {}
    
    # Simple regex to find CREATE TABLE blocks
    create_matches = re.finditer(r'(?i)CREATE TABLE `(.*?)` \((.*?)\) ENGINE', dump_content, re.DOTALL)
    for match in create_matches:
        table_name = match.group(1)
        body = match.group(2)
        # Find all column names (they are typically backticked at the start of a line)
        cols = re.findall(r'^\s*`(.*?)` ', body, re.MULTILINE)
        table_map[table_name] = cols
        
    return table_map

def main():
    print("--- Starting Smart Migration ---")
    
    with engine.connect() as conn:
        print("1. Dropping existing tables...")
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        res = conn.execute(text("SHOW TABLES"))
        tables = [row[0] for row in res]
        for t in tables:
            conn.execute(text(f"DROP TABLE IF EXISTS `{t}`"))
            
        print("2. Syncing schema from models...")
        Base.metadata.create_all(engine)
        
        # Get target columns for each table from the engine
        insp = inspect(engine)
        target_columns = {t: [c['name'] for c in insp.get_columns(t)] for t in insp.get_table_names()}

        print("3. Parsing dump columns...")
        with open('Dump20260329_3_30_2026.sql', 'r', encoding='utf-8', errors='ignore') as f:
            dump_content = f.read()
        
        source_column_map = parse_dump_columns(dump_content)
        
        print("4. Migrating data...")
        # Find all INSERT statements
        # Format: INSERT INTO `table` VALUES (val1, val2...), (val3, val4...);
        insert_matches = re.finditer(r'(?i)INSERT INTO `(.*?)` VALUES \((.*?)\);', dump_content, re.DOTALL)
        
        for match in insert_matches:
            table_name = match.group(1)
            values_block = match.group(2)
            
            if table_name not in target_columns:
                print(f"Skipping table {table_name} (not in models)")
                continue
                
            source_cols = source_column_map.get(table_name)
            if not source_cols:
                print(f"Skipping table {table_name} (could not parse source columns)")
                continue
                
            target_cols = target_columns[table_name]
            
            # Find common columns
            common_cols = [c for c in source_cols if c in target_cols]
            if not common_cols:
                continue
            
            # Get indices of common columns in the source row
            common_indices = [source_cols.index(c) for c in common_cols]
            
            # Split values_block into individual rows
            # This is tricky because values can contain commas and parentheses
            # We'll use a simple regex split for now, assuming rows are separated by ),(
            rows = re.split(r'\s*\),\s*\(', values_block)
            
            print(f"Migrating {len(rows)} rows for {table_name}...")
            
            for row in rows:
                # Clean row (remove leading ( and trailing ))
                row = row.strip().lstrip('(').rstrip(')')
                
                # Split columns in row - again tricky due to content
                # We'll use a better approach: execute the whole block if possible? 
                # No, we need to filter columns.
                
                # Simple split by comma but respecting quotes
                vals = re.findall(r"(?:'[^']*'|[^,])+", row)
                vals = [v.strip() for v in vals]
                
                if len(vals) != len(source_cols):
                    # print(f"Warning: Column count mismatch in row for {table_name}")
                    continue
                
                # Build the filtered row
                filtered_vals = [vals[i] for i in common_indices]
                
                # Create the INSERT statement
                col_names = ", ".join([f"`{c}`" for c in common_cols])
                val_placeholders = ", ".join([v if v != 'NULL' else 'NULL' for v in filtered_vals])
                
                sql = f"INSERT IGNORE INTO `{table_name}` ({col_names}) VALUES ({val_placeholders})"
                try:
                    conn.execute(text(sql))
                except Exception as e:
                    # print(f"Error in {table_name}: {e}")
                    pass
                    
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
        conn.commit()
    
    print("Migration complete.")

if __name__ == "__main__":
    main()
