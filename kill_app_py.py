import os
import sys
import subprocess

def main():
    try:
        # Get process list from WMIC on Windows
        output = subprocess.check_output(
            'wmic process where "name=\'python.exe\'" get ProcessId,CommandLine', 
            shell=True, 
            text=True
        )
        current_pid = os.getpid()
        print(f"[*] Current script PID: {current_pid}")
        
        killed_count = 0
        lines = output.strip().split("\n")
        # Header: CommandLine | ProcessId
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if not parts:
                continue
            pid_str = parts[-1]
            try:
                pid = int(pid_str)
            except ValueError:
                continue
                
            cmdline = " ".join(parts[:-1]).lower()
            
            # Identify app.py processes to kill, excluding current script
            if pid != current_pid and ("app.py" in cmdline or "web\\app.py" in cmdline or "web/app.py" in cmdline):
                print(f"[*] Terminating redundant app.py pid {pid} -> {cmdline[:60]}...")
                subprocess.call(["taskkill", "/F", "/PID", str(pid)])
                killed_count += 1
                
        print(f"[✅] Terminated {killed_count} matching processes.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
