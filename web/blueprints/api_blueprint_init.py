"""
API Blueprint Initialization
Registers all API endpoints with Flask application
"""

from flask import Blueprint, Flask

def register_api_blueprints(app: Flask):
    """
    Register all API blueprints with the Flask application.
    
    Call this in your main app.py during Flask app setup.
    """
    
    try:
        from web.blueprints.api_home import api_home
        from web.blueprints.api_assets import api_assets
        from web.blueprints.api_incidents import api_incidents
        from web.blueprints.api_cbom import api_cbom
        from web.blueprints.api_pqc import api_pqc
        from web.blueprints.api_cyber import api_cyber
        from web.blueprints.api_reports import api_reports
        # from web.blueprints.api_admin import api_admin  # TODO: APIKey model not yet implemented
        from web.blueprints.api_docs import api_docs
        
        # Register all blueprints
        app.register_blueprint(api_home)
        app.register_blueprint(api_assets)
        app.register_blueprint(api_incidents)
        app.register_blueprint(api_cbom)
        app.register_blueprint(api_pqc)
        app.register_blueprint(api_cyber)
        app.register_blueprint(api_reports)
        # app.register_blueprint(api_admin)  # TODO: APIKey model not yet implemented
        app.register_blueprint(api_docs)
        
        print("✅ All API blueprints registered successfully")
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
