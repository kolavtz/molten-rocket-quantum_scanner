
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
try:
    from web.app import app
    print("App imported successfully")
    with app.app_context():
        print("App context created successfully")
except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)
