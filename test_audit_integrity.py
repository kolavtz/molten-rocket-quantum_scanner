
import sys, os
import uuid
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from src import database as db

# Temporarily mock the connection to simplify if MySQL is unstable in CI environment
# But better to use actual if possible.
# Actually, I'll rely on the existing tests if they exist, or use a mock.

def test_audit_logic():
    print("Testing Audit Trail Integrity...")
    
    # Standardize precision to seconds as per our fix
    t1 = datetime.now(timezone.utc).replace(microsecond=0)
    # Simulate the payload used in database.py
    payload = {
        "event": "test",
        "created_at": t1.isoformat(timespec="seconds")
    }
    
    # Verify we can compute a stable hash
    h1 = db._compute_audit_hash(payload, "0"*64)
    print(f"Hash 1: {h1}")
    
    # Re-simulate with same data
    h2 = db._compute_audit_hash(payload, "0"*64)
    print(f"Hash 2: {h2}")
    
    if h1 == h2:
        print("PASS: Stable hashing verified.")
    else:
        print("FAIL: Hash mismatch for identical payload.")
        sys.exit(1)
        
    # Test verify_audit_log_chain (briefly, checking return signature)
    try:
        ok, stats = db.verify_audit_log_chain()
        print(f"Audit verification call returned: {ok}, {stats}")
    except Exception as e:
        print(f"Audit verification CRASHED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_audit_logic()
