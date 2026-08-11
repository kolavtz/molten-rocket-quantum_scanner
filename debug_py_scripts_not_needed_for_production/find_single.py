with open("web/app.py", "r", encoding="utf-8") as f:
    for i, line in enumerate(f):
        if "def _single" in line:
            print(f"Found at Line {i+1}: {line.strip()}")
            break
