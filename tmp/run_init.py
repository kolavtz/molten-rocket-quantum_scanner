import traceback
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.db import init_db

if __name__ == "__main__":
    try:
        init_db()
    except Exception as e:
        with open('tmp/err.log', 'w', encoding='utf-8') as f:
            f.write(traceback.format_exc())
        print("Failure captured in err.log")
        sys.exit(1)
