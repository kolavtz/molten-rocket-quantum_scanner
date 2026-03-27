
import sys
import os
from flask import Flask

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

from web.routes.assets import _decorate_asset_rows, _build_headers

app = Flask(__name__)

with app.test_request_context():
    rows = [
        {"id": 1, "name": "test.com", "url": "https://test.com", "risk_level": "High", "cert_status": "Valid"}
    ]
    csrf_token = "mock-token"
    
    decorated = _decorate_asset_rows(rows, csrf_token)
    headers = _build_headers()
    
    print("--- DECORATED ROWS ---")
    for row in decorated:
        print(f"ID: {row.get('id')}")
        print(f"Name (HTML): {row.get('name')}")
        print(f"Select (HTML): {row.get('select_html')}")
        print("-" * 20)
        
    print("\n--- HEADERS ---")
    for h in headers:
        if h['field'] == 'name':
            print(f"Field: {h['field']}, Safe: {h.get('safe')}")
