import os

app_path = "web/app.py"

with open(app_path, "r", encoding="utf-8") as f:
    text = f.read()

guard_code = """
def _check_concurrency():
    import subprocess
    import atexit
    import time
    
    pid_file = os.path.join(os.path.dirname(__file__), "app_instance.pid")
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                old_pid = int(f.read().strip())
        except Exception:
            old_pid = None
        
        if old_pid and old_pid != os.getpid():
            # Check if alive on Windows
            cmd = f'tasklist /FI "PID eq {old_pid}" /NH'
            try:
                out = subprocess.check_output(cmd, shell=True).decode()
                if str(old_pid) in out:
                    print(f"\\n[!] ALERT: Another instance of {app.import_name} is already running (PID: {old_pid}).")
                    if sys.stdin.isatty():
                        ans = input("Should I end the previous session to start this app? [y/N]: ").strip().lower()
                        if ans == 'y':
                            print(f"Terminating PID {old_pid}...")
                            subprocess.call(f'taskkill /F /PID {old_pid}', shell=True)
                            time.sleep(1)
                            if os.path.exists(pid_file): os.remove(pid_file)
                        else:
                            print("Redirecting to previous instance. Exiting Startup Guard.")
                            sys.exit(0)
                    else:
                        print("Non-interactive mode: Another instance is running. Exiting.")
                        sys.exit(0)
            except Exception:
                pass

    # Save current PID
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    def _cleanup_pid():
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    if int(f.read().strip()) == os.getpid():
                        os.remove(pid_file)
            except Exception:
                pass
    atexit.register(_cleanup_pid)

"""

# Insert _check_concurrency above __main__ or inside it
trigger_string = 'if __name__ == "__main__":'
if trigger_string in text and "_check_concurrency" not in text:
    # Insert function definition above __main__
    text = text.replace(trigger_string, guard_code + "\n" + trigger_string)
    
    # Insert call INSIDE __main__ immediately after the first print statements or at start
    text = text.replace(
        'if __name__ == "__main__":\n    print(f"\\n{\'=\'*60}")',
        'if __name__ == "__main__":\n    _check_concurrency()\n    print(f"\\n{\'=\'*60}")'
    )
    
    with open(app_path, "w", encoding="utf-8") as f:
        f.write(text)
    print("Concurrency guard applied successfully.")
else:
    print("Guard already applied or trigger string not found.")
