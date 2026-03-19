import subprocess
import sys

res = subprocess.run([r".venv\Scripts\python.exe", "-m", "pytest", "-v", "tests/"], capture_output=True, text=True)

out_file = r"c:\Users\saura\OneDrive - betterlivings international school\Downloads\Code\molten-rocket-quantum_scanner\tmp\pytest_full.txt"

with open(out_file, "w", encoding="utf-8") as f:
    f.write("=== STDOUT ===\n")
    f.write(res.stdout)
    f.write("\n=== STDERR ===\n")
    f.write(res.stderr)
    f.write(f"\nEXIT CODE: {res.returncode}\n")

print(f"Done writing to {out_file}")
