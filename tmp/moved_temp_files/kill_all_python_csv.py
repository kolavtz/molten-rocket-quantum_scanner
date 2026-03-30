import os
import sys
import subprocess
import csv

def main():
    current_pid = os.getpid()
    print(f"[*] Current script PID: {current_pid}")
    
    try:
        # Run wmic to get processes in CSV format
        output = subprocess.check_output(
            'wmic process where "name=\'python.exe\'" get ProcessId,CommandLine /format:csv',
            shell=True,
            text=True
        )
        
        killed_count = 0
        reader = csv.reader(output.strip().splitlines())
        for row in reader:
            if not row or len(row) < 3:
                continue
            # Header may appear: Node, CommandLine, ProcessId
            if row[1].lower() == "commandline":
                continue
                
            cmdline = row[1].lower()
            pid_str = row[2]
            
            try:
                pid = int(pid_str)
            except ValueError:
                continue
                
            if pid == current_pid:
                continue
                
            # Aggressive but safer: Kill any python script in the .venv or web directory
            if "app.py" in cmdline or ".venv" in cmdline or "test_" in cmdline or "seed_" in cmdline:
                print(f"[*] Terminating overlapping PID {pid} ({cmdline[:60]})...")
                subprocess.call(["taskkill", "/F", "/PID", str(pid)])
                killed_count += 1
                
        print(f"[✅] Terminated {killed_count} matching processes.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
