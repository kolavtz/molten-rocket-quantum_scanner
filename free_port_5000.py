import subprocess
import os

try:
    # Find process listening on port 5000
    out = subprocess.check_output("netstat -ano | findstr :5000", shell=True).decode()
    pids = set()
    for line in out.strip().split("\n"):
        if "LISTENING" in line:
            parts = line.split()
            if parts:
                pid = parts[-1]
                pids.add(int(pid))
    
    current_pid = os.getpid()
    for pid in pids:
        if pid != current_pid:
            print(f"Killing previous PID {pid} listening on 5000...")
            subprocess.call(f"taskkill /F /PID {pid}", shell=True)

except Exception as e:
    print(f"No previous process found or error: {e}")

print("Port 5000 is ready.")
