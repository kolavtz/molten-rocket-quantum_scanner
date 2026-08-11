with open("web/routes/assets.py", "r") as f:
    content = f.read()

find_expr = '    if getattr(current_user, "role", "") not in ALLOWED_DELETE_ROLES:'
replace_expr = '    user_role = str(getattr(current_user, "role", "") or "").strip().title()\n    if user_role not in ALLOWED_DELETE_ROLES:'

# Count finding
count = content.count(find_expr)
if count == 2:
    content = content.replace(find_expr, replace_expr)
    with open("web/routes/assets.py", "w") as f:
        f.write(content)
    print("SUCCESS: Patched both individual and bulk delete routes!")
else:
    print(f"FAIL: Found {count} instances instead of 2.")
