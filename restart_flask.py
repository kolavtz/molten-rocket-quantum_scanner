import subprocess
import os
import sys
import time

def kill_port(port):
    print(f"Checking port {port}...")
    try:
        # On Windows: netstat -ano | findstr LISTENING | findstr :[port]
        output = subprocess.check_output(f'netstat -ano | findstr LISTENING | findstr :{port}', shell=True).decode()
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) > 4:
                pid = parts[-1]
                print(f"Killing PID {pid} listening on {port}...")
                subprocess.run(f'taskkill /F /PID {pid}', shell=True)
    except subprocess.CalledProcessError:
        print(f"No active listeners found on port {port}")
    except Exception as e:
        print(f"Error checking port {port}: {e}")

# Kill 5000 and 5001
kill_port(5000)
kill_port(5001)

print("Starting Flask app in background...")
env = os.environ.copy()
env["FLASK_APP"] = "web/app.py"

# Start the process in the background
# We use creationflags=subprocess.CREATE_NEW_PROCESS_GROUP on Windows to avoid keeping parent handles
try:
    process = subprocess.Popen(
        [sys.executable, "web/app.py"],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        cwd=".",
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"Started successfully with new PID: {process.pid}")
    # Give it a few seconds to boot before the script ends
    time.sleep(5)
except Exception as e:
    print(f"Fail: {e}")
