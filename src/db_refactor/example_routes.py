from flask import Blueprint, request, render_template, redirect, url_for, flash
from sqlalchemy.orm import Session
from datetime import datetime, timezone
# Assuming models and db_session are correctly imported from the app's structure
from .table_helper import paginate_query
from .models import Asset, Scan, DiscoveryItem

refactor_bp = Blueprint('refactor', __name__)

@refactor_bp.route("/assets")
def asset_inventory(db_session: Session):
    # Retrieve query params
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 25, type=int)
    sort = request.args.get('sort', 'name')
    order = request.args.get('order', 'asc')
    q = request.args.get('q', '')

    # Base Query: MUST filter out soft-deleted records!
    query = db_session.query(Asset).filter(Asset.is_deleted == False)

    # Searchable columns
    searchable_columns = [Asset.name, Asset.url, Asset.ipv4, Asset.owner]

    page_data = paginate_query(
        query=query, 
        model=Asset, 
        page=page, 
        page_size=page_size, 
        sort_field=sort, 
        sort_dir=order, 
        search_term=q, 
        searchable_columns=searchable_columns
    )

    return render_template("asset_inventory_v2.html", page_data=page_data)


@refactor_bp.route("/discovery")
def discovery(db_session: Session):
    tab = request.args.get('tab', 'domains')
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 25, type=int)
    sort = request.args.get('sort', 'detection_date')
    order = request.args.get('order', 'desc')
    q = request.args.get('q', '')

    query = db_session.query(DiscoveryItem).filter(
        DiscoveryItem.is_deleted == False,
        DiscoveryItem.type == tab
    )

    page_data = paginate_query(
        query=query, 
        model=DiscoveryItem, 
        page=page, 
        page_size=page_size, 
        sort_field=sort, 
        sort_dir=order, 
        search_term=q, 
        searchable_columns=[DiscoveryItem.status]
    )

    return render_template("discovery_v2.html", page_data=page_data, current_tab=tab)

# ==========================================
# DELETION ROUTES
# ==========================================
# Assumes @admin_required or similar enforces RBAC

@refactor_bp.route("/assets/<int:id>/delete", methods=["POST"])
def delete_asset(id, db_session: Session, current_user):
    asset = db_session.query(Asset).filter(Asset.id == id, Asset.is_deleted == False).first()
    if not asset:
        flash("Asset not found.", "error")
        return redirect(url_for("refactor.asset_inventory"))

    # Soft Delete Phase
    # Setting is_deleted=True removes it from normal views.
    asset.is_deleted = True
    asset.deleted_at = datetime.now(timezone.utc)
    asset.deleted_by_user_id = current_user.id
    
    # Cascade soft deletes manually to discovery_items or certificates if required by UX rules
    # or rely solely on asset.is_deleted=True (requiring all relational queries to explicitly check parent Asset via join).
    # Opting for marking them physically as deleted for ease of querying:
    for di in asset.discovery_items:
        di.is_deleted = True
        di.deleted_at = datetime.now(timezone.utc)
        di.deleted_by_user_id = current_user.id
        
    for cert in asset.certificates:
        cert.is_deleted = True
        cert.deleted_at = datetime.now(timezone.utc)
        cert.deleted_by_user_id = current_user.id

    db_session.commit()
    flash(f"Asset '{asset.name}' has been moved to the Recycle Bin.", "success")
    return redirect(url_for("refactor.asset_inventory"))

@refactor_bp.route("/admin/recycle-bin")
def recycle_bin(db_session: Session):
    # Simply flip the filter to True.
    page = request.args.get('page', 1, type=int)
    
    query = db_session.query(Asset).filter(Asset.is_deleted == True)
    page_data = paginate_query(query, Asset, page, 50, 'deleted_at', 'desc', '', [])
    
    return render_template("recycle_bin.html", page_data=page_data)

@refactor_bp.route("/admin/recycle-bin/assets/<int:id>/restore", methods=["POST"])
def restore_asset(id, db_session: Session):
    asset = db_session.query(Asset).filter(Asset.id == id, Asset.is_deleted == True).first()
    if asset:
        asset.is_deleted = False
        asset.deleted_at = None
        asset.deleted_by_user_id = None
        
        # Restore children
        for di in asset.discovery_items:
            di.is_deleted = False
            di.deleted_at = None
            di.deleted_by_user_id = None
            
        db_session.commit()
        flash("Asset restored successfully.", "success")
        
    return redirect(url_for("refactor.recycle_bin"))

@refactor_bp.route("/admin/recycle-bin/assets/<int:id>/destroy", methods=["POST"])
def destroy_asset(id, db_session: Session):
    asset = db_session.query(Asset).filter(Asset.id == id, Asset.is_deleted == True).first()
    if asset:
        # DB-level ON DELETE CASCADE activates and cascades hard deletes 
        # to all dependent tables implicitly mapped in MySQL DDL.
        db_session.delete(asset)
        db_session.commit()
        flash("Asset fully purged from database.", "warning")
        
    return redirect(url_for("refactor.recycle_bin"))
