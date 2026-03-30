with open("web/app.py", "r", encoding="utf-8") as f:
    lines = f.readlines()
    # Lines 3376 to 3417 are indices 3375 to 3417 (0-indexed)
    target = "".join(lines[3375:3417])
    print("---TARGET---")
    print(repr(target))
    print("---END---")
