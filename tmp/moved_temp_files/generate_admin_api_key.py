import sys
import os
import secrets
sys.path.insert(0, os.path.dirname(__file__))

from src import database as db

# Initialize DB
db.init_db()

# Check users
users = db.list_users()
admin_user = next((u for u in users if u["username"] == "admin"), None)

if admin_user:
    # Generate API key
    new_key = secrets.token_hex(16)
    
    # Update user in DB
    # Usually db.update_user or direct SQL is needed
    # Let's see if there is an update_user in src.database or direct SQL exec
    # We can use db_session or raw connection
    # Let's check src/database.py for update functions first or just execute raw SQL
    
    import sqlalchemy as sa
    from src.db import db_session
    
    try:
        # Direct update using SQLAlchemy
        res = db_session.execute(
            sa.text("UPDATE users SET api_key = :key WHERE username = :user"),
            {"key": new_key, "user": "admin"}
        )
        db_session.commit()
        print(f"API Key updated for admin.")
        print(f"Admin API Key: {new_key}")
    except Exception as e:
        print(f"SQL Update failed: {e}")
        db_session.rollback()
else:
    print("Admin user not found.")
