import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

print("Testing Scheduler Import & Setup...")
try:
    from src.scheduler import start_scheduler
    print("SUCCESS: start_scheduler imported.")
    
    # We won't start the thread to block but we verified import chains
    from web.app import app
    print("SUCCESS: app.py imported without breaking cyclic dependencies.")
except Exception as e:
    print(f"ERROR: Startup validation failed: {e}")
    sys.exit(1)

print("All Verification Passed.")
sys.exit(0)
