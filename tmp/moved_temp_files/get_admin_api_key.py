import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src import database as db

# Initialize DB
db.init_db()

# Check users
users = db.list_users()
admin_user = next((u for u in users if u["username"] == "admin"), None)

if admin_user:
    print(f"Admin User: {admin_user['username']}")
    print(f"API Key: {admin_user.get('api_key') or 'No API Key'}")
else:
    print("Admin user not found.")
