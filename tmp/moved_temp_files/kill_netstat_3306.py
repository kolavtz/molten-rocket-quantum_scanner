import subprocess
import os

def main():
    try:
        # Get netstat output for port 3306
        output = subprocess.check_output('netstat -ano | findstr 3306', shell=True, text=True)
        current_pid = os.getpid()
        print(f"[*] Current script PID: {current_pid}")
        
        killed_count = 0
        pids_to_kill = set()
        
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            pid_str = parts[-1]
            try:
                pid = int(pid_str)
                # Avoid killing mysql daemon itself! WE ONLY KILL CLIENTS connecting to it.
                # In netstat: LocalAddress | ForeignAddress | State | PID
                # Client ports are usually high (e.g., 54000). MySQL port is 3306.
                local_addr = parts[1]
                foreign_addr = parts[2]
                
                # If foreign addr is 3306 or [::1]:3306, it is a CLIENT session!
                if ":3306" in foreign_addr:
                    if pid != current_pid and pid > 0:
                        pids_to_kill.add(pid)
                        
            except ValueError:
                continue

        print(f"[*] Candidate PIDs to term holding 3306 clients: {pids_to_kill}")
        for pid in pids_to_kill:
            print(f"[*] Terminating PID {pid}...")
            subprocess.call(["taskkill", "/F", "/PID", str(pid)])
            killed_count += 1
            
        print(f"[✅] Terminated {killed_count} matching processes.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
