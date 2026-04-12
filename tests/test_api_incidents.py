"""Tests for /api/incidents endpoints."""

from __future__ import annotations

import json
from unittest.mock import patch


def _sample_incident_payload() -> dict:
    return {
        "incident_id": "incident-placeholder-id",
        "title": "some_string_value",
        "category": "some_string_value",
        "severity": "high",
        "source_system": "some_string_value",
        "status": "New",
        "owner": "some_string_value",
        "created_at": "some_string_value",
        "last_updated_at": "some_string_value",
        "description": "some_string_value",
        "tags": ["some_string_value"],
        "notes": [],
        "timeline": [
            {
                "event": "created",
                "actor": "some_string_value",
                "at": "some_string_value",
            }
        ],
        "linked_entities": {
            "asset_id": "some_integer_value",
            "scan_id": "some_integer_value",
            "certificate_id": None,
            "cbom_entry_id": None,
        },
    }


def test_incidents_list_success_envelope(app_client):
    payload = {
        "items": [_sample_incident_payload()],
        "total": 1,
        "page": 1,
        "page_size": 25,
        "total_pages": 1,
        "kpis": {
            "total_incidents": 1,
            "critical_incidents": 0,
        },
    }

    with patch("web.blueprints.api_incidents.IncidentService.list_incidents", return_value=(payload, 200)):
        resp = app_client.get("/api/incidents")
        if resp.status_code == 404:
            resp = app_client.get("/api/v1/incidents")

    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True
    assert "data" in body
    assert "filters" in body
    assert isinstance(body["data"].get("items"), list)


def test_incident_get_detail_success(app_client):
    with patch(
        "web.blueprints.api_incidents.IncidentService.get_incident",
        return_value=(_sample_incident_payload(), 200),
    ):
        resp = app_client.get("/api/incidents/incident-placeholder-id")
        if resp.status_code == 404:
            resp = app_client.get("/api/v1/incidents/incident-placeholder-id")

    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True
    assert body["data"]["incident_id"] == "incident-placeholder-id"


def test_incident_create_success(app_client):
    with patch(
        "web.blueprints.api_incidents.IncidentService.create_incident",
        return_value=(_sample_incident_payload(), 201),
    ):
        resp = app_client.post(
            "/api/incidents",
            json={
                "title": "some_string_value",
                "severity": "high",
                "category": "some_string_value",
                "description": "some_string_value",
            },
        )
        if resp.status_code == 404:
            resp = app_client.post(
                "/api/v1/incidents",
                json={
                    "title": "some_string_value",
                    "severity": "high",
                    "category": "some_string_value",
                    "description": "some_string_value",
                },
            )

    assert resp.status_code == 201
    body = json.loads(resp.data)
    assert body["success"] is True
    assert body["data"]["title"] == "some_string_value"


def test_incident_update_success(app_client):
    updated = _sample_incident_payload()
    updated["status"] = "In Progress"

    with patch(
        "web.blueprints.api_incidents.IncidentService.update_incident",
        return_value=(updated, 200),
    ):
        resp = app_client.patch(
            "/api/incidents/incident-placeholder-id",
            json={"status": "In Progress"},
        )
        if resp.status_code == 404:
            resp = app_client.patch(
                "/api/v1/incidents/incident-placeholder-id",
                json={"status": "In Progress"},
            )

    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True
    assert body["data"]["status"] == "In Progress"


def test_incident_events_envelope(app_client):
    incident = _sample_incident_payload()
    with patch(
        "web.blueprints.api_incidents.IncidentService.get_incident",
        return_value=(incident, 200),
    ):
        resp = app_client.get("/api/incidents/incident-placeholder-id/events")
        if resp.status_code == 404:
            resp = app_client.get("/api/v1/incidents/incident-placeholder-id/events")

    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True
    assert isinstance(body["data"]["items"], list)
    assert "kpis" in body["data"]


def test_incident_not_found_returns_error_envelope(app_client):
    with patch(
        "web.blueprints.api_incidents.IncidentService.get_incident",
        return_value=(None, 404),
    ):
        resp = app_client.get("/api/incidents/missing-incident")
        if resp.status_code == 404:
            resp = app_client.get("/api/v1/incidents/missing-incident")

    assert resp.status_code == 404
    body = json.loads(resp.data)
    assert body["success"] is False
    assert "error" in body
    assert body["error"]["status"] == 404
