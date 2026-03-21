import sys
import os
import traceback
sys.path.insert(0, os.path.dirname(__file__))

# Import app to initialize config and context
from web.app import _build_asset_inventory_view, app

# Run in application context if needed
with app.app_context():
    try:
        print("Invoking _build_asset_inventory_view()...")
        res = _build_asset_inventory_view()
        print("Success! Return Keys:", res.keys())
    except Exception as e:
        print(f"Exception caught: {e}")
        with open("debug_error.txt", "w") as f:
            f.write(traceback.format_exc())
        print("Traceback written to debug_error.txt")
