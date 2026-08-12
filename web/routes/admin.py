"""
Admin User Management Blueprint Routes

Endpoints for user provisioning, role update, password reset, 2FA reset, API key regeneration, and user deletion.
"""

import logging
import uuid
from typing import List, Optional
from werkzeug.security import generate_password_hash
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    Response,
)
from flask_login import current_user, login_required
from flask_mail import Message

from src import database as db

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin_routes", __name__, url_prefix="/admin/users")

ADMIN_ROLES = {"Admin"}


def _expects_json() -> bool:
    if request.is_json:
        return True
    x_requested_with = str(request.headers.get("X-Requested-With", "") or "").strip().lower()
    if x_requested_with == "xmlhttprequest":
        return True
    best = str(request.accept_mimetypes.best or "").strip().lower()
    return best == "application/json"


def _check_admin_permission():
    if not getattr(current_user, "is_authenticated", False):
        return jsonify({"status": "error", "message": "Authentication required."}), 401
    user_role = db.normalize_role(getattr(current_user, "role", "Viewer"))
    if user_role not in {"Admin"}:
        return jsonify({"status": "error", "message": "Admin authorization required."}), 403
    return None


@admin_bp.route("", methods=["GET", "POST"])
@login_required
def admin_users():
    err = _check_admin_permission()
    if err:
        return err

    if request.method == "POST":
        employee_id = (request.form.get("employee_id") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        username = (request.form.get("username") or "").strip()
        role = db.normalize_role(request.form.get("role") or "Viewer")

        if not employee_id or not email or not username:
            flash("Employee ID, email, and username are required.", "error")
            return redirect(url_for("admin_routes.admin_users"))

        temp_password = uuid.uuid4().hex
        invited_user_id = db.create_invited_user(
            employee_id=employee_id,
            username=username,
            email=email,
            role=role,
            created_by=getattr(current_user, "id", None),
            password_hash=generate_password_hash(temp_password),
        )

        if not invited_user_id:
            flash("Failed to create user. Check for duplicate username/email/employee ID.", "error")
            return redirect(url_for("admin_routes.admin_users"))

        flash(f"User {username} invited successfully.", "success")
        return redirect(url_for("admin_routes.admin_users"))

    users = db.list_users()
    return render_template("admin_users.html", users=users)


@admin_bp.route("/<user_id>/update", methods=["POST"])
@login_required
def update_user(user_id: str):
    err = _check_admin_permission()
    if err:
        return err

    wants_json = _expects_json()
    if request.is_json:
        data = request.get_json(silent=True) or {}
        role = db.normalize_role(data.get("role") or "Viewer")
        is_active = data.get("is_active", True)
    else:
        role = db.normalize_role(request.form.get("role") or "Viewer")
        is_active = request.form.get("is_active") == "on"

    if db.update_user_profile(user_id, role=role, is_active=is_active):
        if wants_json:
            return jsonify({
                "status": "success",
                "message": "User profile updated.",
                "user_id": user_id,
                "role": role,
                "is_active": is_active,
            }), 200
        flash("User profile updated.", "success")
    else:
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to update user profile."}), 500
        flash("Failed to update user profile.", "error")

    return redirect(url_for("admin_routes.admin_users"))


@admin_bp.route("/<user_id>/reset-password", methods=["POST"])
@login_required
def reset_user_password(user_id: str):
    err = _check_admin_permission()
    if err:
        return err

    wants_json = _expects_json()
    user = db.get_user_by_id(user_id)
    if not user:
        if wants_json:
            return jsonify({"status": "error", "message": "User not found."}), 404
        flash("User not found.", "error")
        return redirect(url_for("admin_routes.admin_users"))

    token = db.create_password_setup_token(user_id, expires_hours=24)
    setup_url = f"/setup-password/{token}" if token else ""

    if wants_json:
        return jsonify({
            "status": "success",
            "message": "Password reset link generated.",
            "user_id": user_id,
            "username": user.get("username"),
            "setup_url": setup_url,
        }), 200

    flash("Password reset token generated.", "success")
    return redirect(url_for("admin_routes.admin_users"))


@admin_bp.route("/<user_id>/reset-2fa", methods=["POST"])
@login_required
def reset_user_2fa(user_id: str):
    err = _check_admin_permission()
    if err:
        return err

    wants_json = _expects_json()
    if db.reset_user_2fa(user_id):
        if wants_json:
            return jsonify({"status": "success", "message": "2FA reset successfully."}), 200
        flash("2FA reset successfully.", "success")
    else:
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to reset 2FA."}), 500
        flash("Failed to reset 2FA.", "error")

    return redirect(url_for("admin_routes.admin_users"))


@admin_bp.route("/<user_id>/regen-api-key", methods=["POST"])
@login_required
def regen_api_key(user_id: str):
    err = _check_admin_permission()
    if err:
        return err

    wants_json = _expects_json()
    user = db.get_user_by_id(user_id)
    if not user:
        if wants_json:
            return jsonify({"status": "error", "message": "User not found."}), 404
        flash("User not found.", "error")
        return redirect(url_for("admin_routes.admin_users"))

    db.revoke_api_key(user_id)
    new_key = db.generate_api_key(user_id)
    if new_key:
        if wants_json:
            return jsonify({
                "status": "success",
                "message": f"API key regenerated for {user.get('username')}.",
                "user_id": user_id,
                "username": user.get("username"),
                "api_key": new_key,
            }), 200
        flash("API key regenerated successfully.", "success")
    else:
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to regenerate API key."}), 500
        flash("Failed to regenerate API key.", "error")

    return redirect(url_for("admin_routes.admin_routes.admin_users"))


@admin_bp.route("/<user_id>/delete", methods=["POST", "DELETE"])
@login_required
def delete_user(user_id: str):
    err = _check_admin_permission()
    if err:
        return err

    wants_json = _expects_json()
    current_uid = str(getattr(current_user, "id", "") or "").strip()
    if str(user_id).strip() == current_uid:
        if wants_json:
            return jsonify({"status": "error", "message": "Cannot delete currently logged-in user."}), 400
        flash("Cannot delete currently logged-in user.", "error")
        return redirect(url_for("admin_routes.admin_users"))

    deleted_count = db.bulk_delete_users([user_id])
    if deleted_count > 0:
        if wants_json:
            return jsonify({"status": "success", "message": "User deleted successfully.", "user_id": user_id}), 200
        flash("User deleted successfully.", "success")
    else:
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to delete user or user not found."}), 404
        flash("Failed to delete user.", "error")

    return redirect(url_for("admin_routes.admin_users"))


@admin_bp.route("/bulk", methods=["POST"])
@login_required
def bulk_users():
    err = _check_admin_permission()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "").strip().lower()
    raw_user_ids = data.get("user_ids")

    if not isinstance(raw_user_ids, list):
        return jsonify({"status": "error", "message": "'user_ids' must be an array."}), 400

    user_ids = [str(uid).strip() for uid in raw_user_ids if str(uid).strip()]
    if not user_ids:
        return jsonify({"status": "error", "message": "Select at least one user."}), 400

    current_uid = str(getattr(current_user, "id", "") or "").strip()
    protected_ids = [uid for uid in user_ids if uid == current_uid]

    if action == "update_role":
        role = db.normalize_role(data.get("role") or "Viewer")
        updated_count = db.bulk_update_user_role(user_ids, role=role)
        return jsonify({
            "status": "success",
            "message": f"Updated role for {updated_count} user(s).",
            "updated_count": int(updated_count),
            "role": role,
        }), 200

    if action == "delete":
        deletable_ids = [uid for uid in user_ids if uid != current_uid]
        if not deletable_ids:
            return jsonify({
                "status": "error",
                "message": "No deletable users selected. Currently logged-in user cannot be deleted.",
                "protected_ids": protected_ids,
            }), 400
        deleted_count = db.bulk_delete_users(deletable_ids)
        if deleted_count == 0:
            return jsonify({
                "status": "error",
                "message": "Failed to delete selected users.",
                "protected_ids": protected_ids,
            }), 500
        return jsonify({
            "status": "success",
            "message": f"Deleted {deleted_count} user(s).",
            "deleted_count": int(deleted_count),
            "protected_ids": protected_ids,
        }), 200

    return jsonify({"status": "error", "message": "Invalid bulk action."}), 400
