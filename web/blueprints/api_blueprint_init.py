"""
API Blueprint Initialization
Registers all API endpoints with Flask application
"""

import os
from flask import Blueprint, Flask

def register_api_blueprints(app: Flask):
    """
    Register all API blueprints with the Flask application.
    
    Call this in your main app.py during Flask app setup.
    """
    
    try:
        from web.blueprints.api_incidents import api_incidents
        # from web.blueprints.api_admin import api_admin  # TODO: APIKey model not yet implemented
        from web.blueprints.api_docs import api_docs
        # AI assistant blueprint
        from web.blueprints.api_ai import api_ai

        # Register only non-overlapping blueprints by default.
        # Authoritative dashboard endpoints are served from web.routes.dashboard_api.
        app.register_blueprint(api_incidents)
        # app.register_blueprint(api_admin)  # TODO: APIKey model not yet implemented
        app.register_blueprint(api_docs)
        app.register_blueprint(api_ai)

        # Optional fallback switch to restore legacy overlapping blueprint registrations.
        # Use only for temporary migration compatibility.
        if str(os.environ.get("QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS", "")).strip().lower() in {"1", "true", "yes", "on"}:
            from web.blueprints.api_home import api_home
            from web.blueprints.api_assets import api_assets
            from web.blueprints.api_cbom import api_cbom
            from web.blueprints.api_pqc import api_pqc
            from web.blueprints.api_cyber import api_cyber
            from web.blueprints.api_reports import api_reports

            app.register_blueprint(api_home)
            app.register_blueprint(api_assets)
            app.register_blueprint(api_cbom)
            app.register_blueprint(api_pqc)
            app.register_blueprint(api_cyber)
            app.register_blueprint(api_reports)
            print("⚠️ Legacy overlapping dashboard API blueprints are enabled via QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS")
        
        print("✅ API blueprints registered successfully")
        return True
    
    except ImportError as e:
        print(f"❌ Failed to register API blueprints: {e}")
        return False


def register_api_auth_model(db):
    """
    Register the APIKey model with the database.
    
    Call this after initializing your database.
    """
    
    try:
        from middleware.api_auth import APIKey
        from src.db import Base
        
        # This will ensure the api_keys table is created
        # Only call this if using SQLAlchemy's declarative base
        # Base.metadata.create_all(db.engine)
        
        print("✅ API Key model registered")
        return True
    
    except Exception as e:
        print(f"⚠️  Could not register API Key model: {e}")
        return False
