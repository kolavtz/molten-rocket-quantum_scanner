with open("web/app.py", "r", encoding="utf-8") as f:
    for i, line in enumerate(f):
        if "def load_theme" in line:
            print(f"Found at Line {i+1}: {line.strip()}")
        elif "load_theme" in line and "=" in line:
            print(f"Assign at Line {i+1}: {line.strip()}")
