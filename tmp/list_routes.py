import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from web.app import app

print("=== ROUTES ===")
for rule in app.url_map.iter_rules():
    print(f"Rule: {rule.rule} -> Endpoint: {rule.endpoint} ({rule.methods})")
print("==============")
