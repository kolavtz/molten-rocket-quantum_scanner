import sys
import json
from flask import session

sys.path.append('.')
from web.app import app
from src.db import db_session
from src.models import Asset, User

app.config['WTF_CSRF_ENABLED'] = False

with app.test_client() as client:
    # Ensure user exists for flask-login loader
    user = db_session.query(User).filter(User.id == '1786cc59-27f5-4ecf-8716-223b3bb1b287').first()
    if not user:
        user = User(id='1786cc59-27f5-4ecf-8716-223b3bb1b287', username='admin_test', role='Admin')
        db_session.add(user)
        db_session.commit()
    elif user.role != 'Admin':
        user.role = 'Admin'
        db_session.commit()

    with client.session_transaction() as sess:
        # Mock auth
        sess['user_id'] = '1786cc59-27f5-4ecf-8716-223b3bb1b287'
        sess['_fresh'] = True

    # 1. Create a dummy asset if necessary
    asset = db_session.query(Asset).filter(Asset.is_deleted == False).first()
    if not asset:
         print("No active assets to test delete.")
         sys.exit(0)

    print(f"Testing individual delete route on asset ID: {asset.id} ({asset.name})")

    response = client.post(
        f'/api/assets/{asset.id}/delete',
        headers={'Accept': 'application/json'}
    )

    print(f"Response Status: {response.status_code}")
    print(f"Redirect Location: {response.headers.get('Location')}")
    print("Response Body:")
    try:
        print(json.dumps(response.get_json(), indent=2))
    except Exception:
        print(response.get_data(as_text=True))

    db_session.commit()
