"""
COPY THIS INTO YOUR web/app.py

This is the exact code needed to integrate all API endpoints.
Find the location marked by [INSERT HERE] comments in your existing app.py
"""

# ============================================================================
# ADD THIS IMPORT AT THE TOP OF YOUR web/app.py
# ============================================================================

from web.blueprints.api_blueprint_init import register_api_blueprints

# ============================================================================
# ADD THIS CODE IN YOUR FLASK APP INITIALIZATION SECTION
# (Usually after creating the Flask app instance and before app.run())
# ============================================================================

def setup_api_endpoints(app):
    """Initialize all API endpoints."""
    try:
        register_api_blueprints(app)
        print("✅ API endpoints registered successfully")
        print("   Available endpoints:")
        print("      GET  /api/home/metrics")
        print("      GET  /api/assets")
        print("      GET  /api/discovery")
        print("      GET  /api/cbom/metrics")
        print("      GET  /api/cbom/entries")
        print("      GET  /api/pqc-posture/metrics")
        print("      GET  /api/pqc-posture/assets")
        print("      GET  /api/cyber-rating")
        print("      GET  /api/reports/scheduled")
        print("      GET  /api/reports/ondemand")
        print("      GET  /api/admin/api-keys")
        print("      GET  /api/docs")
        print("      GET  /docs")
    except Exception as e:
        print(f"⚠️  Could not register API endpoints: {e}")


# ============================================================================
# IN YOUR MAIN SECTION (around line 1750+), ADD THIS:
# ============================================================================

if __name__ == "__main__":
    # ... your existing setup code ...
    
    # Setup API endpoints [INSERT HERE]
    setup_api_endpoints(app)
    
    # ... rest of your code ...
    app.run(debug=True, host='0.0.0.0', port=5000)


# ============================================================================
# EXAMPLE: Complete pattern for your app.py
# ============================================================================

"""
# At the very top of web/app.py:

from flask import Flask
from flask_login import LoginManager
from web.blueprints.api_blueprint_init import register_api_blueprints

# ... other imports ...

app = Flask(__name__)

# Configure app
app.config.update(
    DEBUG=True,
    SECRET_KEY='your-secret-key',
    # ... other config ...
)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)

# ... register other blueprints ...

# Register API endpoints here ← INSERT THIS
def setup_api_endpoints(app):
    try:
        register_api_blueprints(app)
        print("✅ API endpoints ready")
    except Exception as e:
        print(f"⚠️  API setup failed: {e}")

setup_api_endpoints(app)

# ... define routes and run app ...

if __name__ == "__main__":
    app.run(debug=True)
"""


# ============================================================================
# OPTIONAL: Create API Keys for Testing
# ============================================================================

def create_test_api_key():
    """
    Run this once to create a test API key.
    
    Usage:
        python -c "from web.app import create_test_api_key; create_test_api_key()"
    """
    from src.db import SessionLocal
    from middleware.api_auth import APIKey
    
    db = SessionLocal()
    
    # Check if test key already exists
    existing = db.query(APIKey).filter(APIKey.name == "Test API Key").first()
    if existing:
        print(f"Test key already exists: {existing.key}")
        db.close()
        return
    
    # Create new test key
    test_key = APIKey.generate_key()
    api_key = APIKey(
        key=test_key,
        name="Test API Key",
        user_id=None,
        is_active=True
    )
    
    db.add(api_key)
    db.commit()
    db.close()
    
    print(f"✅ Test API key created: {test_key}")
    print(f"   Use in requests: curl -H 'X-API-Key: {test_key}' http://localhost:5000/api/assets")


# ============================================================================
# OPTIONAL: Migration to Create api_keys Table
# ============================================================================

def create_api_keys_table():
    """
    Run this to create the api_keys table if it doesn't exist.
    
    Usage:
        python -c "from web.app import create_api_keys_table; create_api_keys_table()"
    """
    from src.db import engine
    from middleware.api_auth import APIKey
    
    try:
        APIKey.__table__.create(engine, checkfirst=True)
        print("✅ API Keys table created successfully")
    except Exception as e:
        print(f"⚠️  Could not create table: {e}")
        print("   This is normal if table already exists")


# ============================================================================
# QUICK VERIFICATION SCRIPT
# ============================================================================

def verify_api_setup():
    """
    Run this to verify API setup is correct.
    
    Usage:
        python -c "from web.app import verify_api_setup; verify_api_setup()"
    """
    import requests
    
    print("🔍 Verifying API Setup...")
    print()
    
    base_url = "http://localhost:5000"
    endpoints = [
        "/api/docs",
        "/api/home/metrics",
        "/api/assets",
        "/api/cbom/metrics",
        "/api/pqc-posture/metrics",
        "/api/cyber-rating",
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✅" if response.status_code == 200 else "⚠️"
            print(f"{status} {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint}: {str(e)}")
    
    print()
    print("If you see ✅ for all endpoints, API is ready!")
    print("If you see 401, you need to be logged in or provide API key header")


# ============================================================================
# END OF INTEGRATION CODE
# ============================================================================
