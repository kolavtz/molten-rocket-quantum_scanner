"""
Integration tests for admin single deletion, bulk deletion, 2FA reset, and rate limit exemptions.
"""

import json
from uuid import uuid4
from unittest.mock import patch
from werkzeug.security import generate_password_hash

import pytest
from src import database as db


@pytest.fixture
def app_client():
    from web.app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


def test_admin_single_delete_user_post_and_delete(app_client):
    db.init_db()
    
    # 1. Create target user for POST deletion
    u1 = f"del-post-{uuid4().hex[:6]}"
    u1_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=u1,
        email=f"{u1}@example.com",
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Pass123!"),
    )

    with patch("web.app.current_user") as admin_user:
        admin_user.role = "Admin"
        admin_user.id = "admin-1"
        admin_user.username = "admin"
        
        resp = app_client.post(
            f"/admin/users/{u1_id}/delete",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert payload["user_id"] == u1_id
    assert db.get_user_by_id(u1_id) is None

    # 2. Create target user for DELETE HTTP method deletion
    u2 = f"del-http-{uuid4().hex[:6]}"
    u2_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=u2,
        email=f"{u2}@example.com",
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Pass123!"),
    )

    with patch("web.app.current_user") as admin_user:
        admin_user.role = "Admin"
        admin_user.id = "admin-1"
        admin_user.username = "admin"
        
        resp = app_client.delete(
            f"/admin/users/{u2_id}/delete",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert payload["user_id"] == u2_id
    assert db.get_user_by_id(u2_id) is None


def test_admin_bulk_delete_users(app_client):
    db.init_db()
    
    u1 = f"bulk-del-1-{uuid4().hex[:6]}"
    u2 = f"bulk-del-2-{uuid4().hex[:6]}"
    
    u1_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=u1,
        email=f"{u1}@example.com",
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Pass123!"),
    )
    u2_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=u2,
        email=f"{u2}@example.com",
        role="SingleScan",
        created_by=None,
        password_hash=generate_password_hash("Pass123!"),
    )

    with patch("web.app.current_user") as admin_user:
        admin_user.role = "Admin"
        admin_user.id = "admin-bulk-deleter"
        admin_user.username = "admin"
        
        resp = app_client.post(
            "/admin/users/bulk",
            data=json.dumps({"action": "delete", "user_ids": [u1_id, u2_id]}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"
    assert int(payload["deleted_count"]) == 2
    assert db.get_user_by_id(u1_id) is None
    assert db.get_user_by_id(u2_id) is None


def test_admin_reset_user_2fa(app_client):
    db.init_db()
    
    u1 = f"reset2fa-{uuid4().hex[:6]}"
    u1_id = db.create_invited_user(
        employee_id=f"EMP-{uuid4().hex[:8]}",
        username=u1,
        email=f"{u1}@example.com",
        role="Viewer",
        created_by=None,
        password_hash=generate_password_hash("Pass123!"),
    )

    with patch("web.app.current_user") as admin_user:
        admin_user.role = "Admin"
        admin_user.id = "admin-2fa-resetter"
        admin_user.username = "admin"
        
        resp = app_client.post(
            f"/admin/users/{u1_id}/reset-2fa",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["status"] == "success"


def test_admin_delete_user_rate_limit_exemption(app_client):
    db.init_db()

    with patch("web.app.current_user") as admin_user:
        admin_user.role = "Admin"
        admin_user.id = "admin-limiter-test"
        admin_user.username = "admin"
        
        # Fire multiple requests to single delete endpoint - should NOT hit 429
        for _ in range(15):
            u_id = db.create_invited_user(
                employee_id=f"EMP-{uuid4().hex[:8]}",
                username=f"limiter-{uuid4().hex[:6]}",
                email=f"limiter-{uuid4().hex[:6]}@example.com",
                role="Viewer",
                created_by=None,
                password_hash=generate_password_hash("Pass123!"),
            )
            resp = app_client.post(
                f"/admin/users/{u_id}/delete",
                data=json.dumps({}),
                content_type="application/json",
                headers={"Accept": "application/json"},
            )
            assert resp.status_code != 429
