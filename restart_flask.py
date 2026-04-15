import subprocess
import os
import sys
import time

def kill_port(port):
    print(f"Checking port {port}...")
    try:
        # On Windows: avoid shell=True; run netstat and parse output in Python
        output = subprocess.check_output(["netstat", "-ano"]).decode(errors='ignore')
        for line in output.strip().splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                if parts:
                    pid = parts[-1]
                    print(f"Killing PID {pid} listening on {port}...")
                    # Use argument list to avoid shell injection
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False)
                    except Exception:
                        # Fall back to non-throwing call
                        subprocess.call(["taskkill", "/F", "/PID", str(pid)])
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
