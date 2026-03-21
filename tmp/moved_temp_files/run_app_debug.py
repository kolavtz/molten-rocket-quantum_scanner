from web.app import app
import os
import traceback

if __name__ == '__main__':
    print("Starting Flask directly...")
    try:
        with open("app_start_debug.txt", "w") as f:
            f.write("Starting app.run...\n")
        app.run(host='127.0.0.1', port=5001, debug=False, ssl_context='adhoc')
    except Exception as e:
        with open("app_start_debug.txt", "a") as f:
            f.write(f"Exception: {str(e)}\n")
            f.write(traceback.format_exc())
        print(f"Exception happened: {e}")
