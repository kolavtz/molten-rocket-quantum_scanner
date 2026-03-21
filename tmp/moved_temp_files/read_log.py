import os

log_path = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\app.log"
out_path = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\app_log_tail.txt"

if os.path.exists(log_path):
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("--- LAST 10000 CHARACTERS OF LOG ---\n")
        f.write(content[-10000:])
        f.write("\n--- END OF LOG ---\n")
    print(f"Written tail to {out_path}")
else:
    with open(out_path, "w") as f:
        f.write("Log file not found.\n")
    print("Log file not found.")
