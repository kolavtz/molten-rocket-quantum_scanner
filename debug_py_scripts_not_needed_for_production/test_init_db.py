import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import logging
logging.basicConfig(level=logging.INFO)

from src.database import init_db, _get_server_connection

print("Testing _get_server_connection()...")
try:
    conn = _get_server_connection()
    if conn:
        print("Success! Connection established.")
        conn.close()
    else:
        print("Failed! _get_server_connection returned None.")
except Exception as e:
    import traceback
    print(f"Exception raised in _get_server_connection: {e}")
    traceback.print_exc()

print("\nTesting init_db()...")
try:
    res = init_db()
    print(f"Result: {res}")
except Exception as e:
    import traceback
    print(f"Exception raised in init_db: {e}")
    traceback.print_exc()
