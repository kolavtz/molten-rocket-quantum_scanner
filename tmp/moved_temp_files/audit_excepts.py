import sys
filepath = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\web\app.py"

try:
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
except Exception as e:
    print(f"Failed to read: {e}")
    sys.exit(1)

out_lines = ["=== Targeted Audit of Route Fallbacks ===\n"]

for i, line in enumerate(lines):
    if "except" in line:
        # Check surrounding lines for route
        route = None
        for j in range(i, max(0, i - 150), -1):
            if "@app.route" in lines[j]:
                route = lines[j].strip()
                break
        
        if not route:
            continue

        # Check if following 10 lines contain 'vm =' or 'return render_template' or 'return jsonify'
        is_fallback = False
        fallback_lines = []
        for k in range(i, min(len(lines), i + 15)):
            fallback_lines.append(f"{k+1}: {lines[k].rstrip()}")
            ltext = lines[k].lower()
            if "vm =" in ltext or "return render_template" in ltext or "return jsonify" in ltext or "page_data =" in ltext:
                is_fallback = True
        
        if is_fallback:
            out_lines.append(f"\n--- {route} (Line {i+1}) ---\n")
            for fl in fallback_lines:
                out_lines.append(fl + "\n")

with open("audit_output.txt", "w", encoding="utf-8") as f:
    f.writelines(out_lines)

print("Audit written to audit_output.txt")
