import os

filepath = "web/app.py"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

new_function = """@app.route("/recycle-bin", methods=["GET", "POST"])
@login_required
def recycle_bin():
    \"\"\"Isolated dashboard for soft-deleted assets and scans.\"\"\"
    from src.db import db_session
    from src.models import Asset, Scan
    
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "restore_assets":
                asset_ids = request.form.getlist("asset_ids")
                if asset_ids:
                    asset_ids = [int(aid) for aid in asset_ids]
                    assets_to_restore = db_session.query(Asset).filter(Asset.id.in_(asset_ids)).all()
                    for asset in assets_to_restore:
                        asset.is_deleted = False
                    db_session.commit()
                    flash(f"Successfully restored {len(assets_to_restore)} asset(s).", "success")
                    
            elif action == "restore_scans":
                scan_ids = request.form.getlist("scan_ids")
                if scan_ids:
                    scan_ids = [int(sid) for sid in scan_ids]
                    scans_to_restore = db_session.query(Scan).filter(Scan.id.in_(scan_ids)).all()
                    for scan in scans_to_restore:
                        scan.is_deleted = False
                    db_session.commit()
                    flash(f"Successfully restored {len(scans_to_restore)} scan(s).", "success")
        except Exception as e:
            db_session.rollback()
            flash(f"Error restoring items: {str(e)}", "danger")
            
        return redirect(url_for("recycle_bin"))

    # GET Request
    try:
        deleted_assets = db_session.query(Asset).filter(Asset.is_deleted == True).all()
        deleted_scans = db_session.query(Scan).filter(Scan.is_deleted == True).all()
        vm = {
            "empty": not deleted_assets and not deleted_scans,
            "assets": deleted_assets,
            "scans": deleted_scans,
        }
    except Exception:
        vm = {
            "empty": True,
            "assets": [],
            "scans": []
        }
    
    return render_template("recycle_bin.html", vm=vm)"""

lines = content.split('\n')
start_idx = -1
end_idx = -1

for i, line in enumerate(lines):
    if '@app.route("/recycle-bin")' in line:
        start_idx = i
    if start_idx != -1 and 'return render_template("inventory.html"' in line:
        end_idx = i
        break

if start_idx != -1 and end_idx != -1:
    new_lines = lines[:start_idx] + [new_function] + lines[end_idx+1:]
    with open(filepath, "w", encoding="utf-8", newline='\n') as f:
        f.write('\n'.join(new_lines))
    print("REPLACED SUCCESS")
else:
    print(f"COULD NOT FIND FUNCTION. Start: {start_idx}, End: {end_idx}")
