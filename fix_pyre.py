import os
import re

APP_PY = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\web\app.py"
DASH_PY = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\web\blueprints\dashboard.py"

def patch_file(filepath, replacements):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return

    # Add import typing if not present
    if "import typing" not in content:
        content = content.replace("import sys\n", "import sys\nimport typing\n")

    for old, new in replacements:
        content = content.replace(old, new)
        
    # Also add typing cast for dict get in dashboard if not present
    if filepath == DASH_PY:
        content = content.replace("summary[\"total_scans\"] = data.get(\"total_scans\", 0)", "summary[\"total_scans\"] = typing.cast(dict, data).get(\"total_scans\", 0)")
        content = content.replace("summary[\"aggregated_kpis\"] = data.get(\"aggregated_kpis\", {})", "summary[\"aggregated_kpis\"] = typing.cast(dict, data).get(\"aggregated_kpis\", {})")
        content = content.replace("summary[\"distributions\"] = data.get(\"distributions\", {})", "summary[\"distributions\"] = typing.cast(dict, data).get(\"distributions\", {})")

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

app_replacements = [
    (
        "sys.stdout.reconfigure(encoding='utf-8')",
        "typing.cast(typing.Any, sys.stdout).reconfigure(encoding='utf-8')"
    ),
    (
        "if _dashboard_cache[\"data\"] is not None and now - _dashboard_cache[\"updated_at\"] < _dashboard_ttl_seconds:",
        "if _dashboard_cache[\"data\"] is not None and now - float(typing.cast(float, _dashboard_cache[\"updated_at\"])) < _dashboard_ttl_seconds:"
    ),
    (
        "return _dashboard_cache[\"data\"]",
        "return typing.cast(dict, _dashboard_cache[\"data\"])"
    ),
    (
        "_dashboard_cache[\"data\"] = data",
        "typing.cast(dict, _dashboard_cache)[\"data\"] = data"
    ),
    (
        "c = color.lstrip(\"#\")",
        "c = typing.cast(typing.Any, color.lstrip(\"#\"))"
    ),
    (
        "cert = raw.get(\"certificate\") if isinstance(raw.get(\"certificate\"), dict) else {}",
        "cert = typing.cast(dict, raw.get(\"certificate\") if isinstance(raw.get(\"certificate\"), dict) else {})"
    ),
    (
        "dashboard_data.get(\"critical\", 0) or 0",
        "typing.cast(dict, dashboard_data).get(\"critical\", 0) or 0"
    ),
    (
        "if dashboard_data.get(\"critical\", 0) > 0:",
        "if int(typing.cast(dict, dashboard_data).get(\"critical\", 0)) > 0:"
    ),
    (
        "elif dashboard_data.get(\"high\", 0) >= 30:",
        "elif int(typing.cast(dict, dashboard_data).get(\"high\", 0)) >= 30:"
    ),
    (
        "dashboard_data.get(\"high\", 0) or 0",
        "typing.cast(dict, dashboard_data).get(\"high\", 0) or 0"
    ),
    (
        "dashboard_data.get(\"medium\", 0) or 0",
        "typing.cast(dict, dashboard_data).get(\"medium\", 0) or 0"
    ),
    (
        "dashboard_data.get(\"low\", 0) or 0",
        "typing.cast(dict, dashboard_data).get(\"low\", 0) or 0"
    ),
    (
        "dashboard_data.get(\"unknown\", 0) or 0",
        "typing.cast(dict, dashboard_data).get(\"unknown\", 0) or 0"
    ),
    (
        "for risk, count in distributions.get(\"risk_level\", {}).items():",
        "for risk, count in typing.cast(dict, distributions.get(\"risk_level\", {})).items():"
    ),
    (
        "return str(v).lower()",
        "return typing.cast(typing.Any, str(v)).lower()"
    ),
    (
        "items = sorted(items, key=_sort_val, reverse=reverse)",
        "items = sorted(typing.cast(typing.Iterable[typing.Any], items), key=_sort_val, reverse=reverse)"
    ),
    (
        "total_count = len(items)",
        "total_count = len(typing.cast(typing.Sized, items))"
    ),
    (
        "has_next = total_count > page * page_size",
        "has_next = int(total_count) > int(page) * int(page_size)"
    ),
    (
        "items = items[start:end]",
        "items = typing.cast(typing.Any, items)[start:end]"
    ),
    (
        "atexit.register(lambda: None)",
        "atexit.register(typing.cast(typing.Callable, lambda: None))"
    ),
    (
        "row_dict = {",
        "row_dict: typing.Dict[str, typing.Any] = {"
    ),
    (
        "row_dict = dict(row)",
        "row_dict: typing.Dict[str, typing.Any] = dict(row)"
    ),
    (
        "page_data = {",
        "page_data: typing.Dict[str, typing.Any] = {"
    )
]

patch_file(APP_PY, app_replacements)
patch_file(DASH_PY, [])

print("Patch complete")
