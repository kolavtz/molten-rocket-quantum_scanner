import json
from unittest.mock import patch
from uuid import uuid4

from werkzeug.security import generate_password_hash

from src import database as db


def test_admin_update_user_json(app_client):
    db.init_db()
    username = f"int-user-{uuid4().hex[:8]}"
    email = f"{username}@example.com"
    user_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=username,
        email=email,
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Test123!"),
    )

    with patch("web.app.current_user") as route_user:
        route_user.role = "Admin"
        route_user.id = 900
        route_user.username = "admin"
        resp = app_client.post(
            f"/admin/users/{user_id}/update",
            data=json.dumps({"role": "Manager", "is_active": False}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"


def test_admin_regen_api_key_json(app_client):
    db.init_db()
    username = f"int-key-{uuid4().hex[:8]}"
    email = f"{username}@example.com"
    user_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=username,
        email=email,
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Test123!"),
    )

    with patch("web.app.current_user") as route_user:
        route_user.role = "Admin"
        route_user.id = 901
        route_user.username = "admin"
        resp = app_client.post(
            f"/admin/users/{user_id}/regen-api-key",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert payload["api_key"].startswith("qss_")


def test_admin_bulk_update_user_role_json(app_client):
    db.init_db()
    username_a = f"int-bulk-a-{uuid4().hex[:6]}"
    username_b = f"int-bulk-b-{uuid4().hex[:6]}"
    email_a = f"{username_a}@example.com"
    email_b = f"{username_b}@example.com"

    user_id_a = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=username_a,
        email=email_a,
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Test123!"),
    )
    user_id_b = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=username_b,
        email=email_b,
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Test123!"),
    )

    with patch("web.app.current_user") as route_user:
        route_user.role = "Admin"
        route_user.id = "admin-bulk-role"
        route_user.username = "admin"
        resp = app_client.post(
            "/admin/users/bulk",
            data=json.dumps({"action": "update_role", "user_ids": [user_id_a, user_id_b], "role": "Manager"}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert int(payload.get("updated_count", 0)) >= 2


def test_admin_bulk_delete_protects_logged_in_user_json(app_client):
    db.init_db()
    username = f"int-bulk-del-{uuid4().hex[:6]}"
    email = f"{username}@example.com"
    user_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=username,
        email=email,
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Test123!"),
    )

    with patch("web.app.current_user") as route_user:
        route_user.role = "Admin"
        route_user.id = user_id
        route_user.username = username
        resp = app_client.post(
            "/admin/users/bulk",
            data=json.dumps({"action": "delete", "user_ids": [user_id]}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert int(payload.get("deleted_count", 0)) == 0
    assert user_id in payload.get("protected_ids", [])
