import sys
import os
sys.path.append(os.getcwd())

from web.app import app

with open("tmp/routes.txt", "w") as f:
    for rule in app.url_map.iter_rules():
        f.write(f"{rule.rule} -> {rule.endpoint} ({rule.methods})\n")

print("Routes dumped to tmp/routes.txt")
