import os
from web.app import app

out_path = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\routes.txt"

with open(out_path, "w") as f:
    f.write("--- FLASK ROUTES ---\n")
    for rule in app.url_map.iter_rules():
        f.write(f"{rule.rule} -> {rule.endpoint} (Methods: {','.join(rule.methods)})\n")
print(f"Written to {out_path}")
