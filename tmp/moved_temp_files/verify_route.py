import sys
import os

# Add current directory to path
sys.path.append(os.path.abspath('.'))

try:
    from web.app import app
    print("Flask app imported successfully.")
    
    with app.app_context():
        # We can also add a test request context to avoid SERVER_NAME issues
        with app.test_request_context():
            try:
                url = app.url_for('main.index')
                print(f"SUCCESS: 'main.index' built URL: {url}")
            except Exception as e:
                print(f"FAILED to build 'main.index': {e}")
                sys.exit(1)
                
            try:
                # Double check dashboard.index still fails (to prove the test is valid)
                url_fail = app.url_for('dashboard.index')
                print(f"WARNING: 'dashboard.index' built URL? {url_fail}")
            except Exception as e:
                print(f"CONFIRMED: 'dashboard.index' failed as expected: {e}")

except Exception as e:
    print(f"ERROR during verification: {e}")
    # If it's a DB connection error or import error, it might not be fatal for route building
    # But if it stops before url_for, we can't be 100% automatedly verified.
    # We will see from output.
