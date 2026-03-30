"""API Incidents - /api/incidents endpoints.

Provides list/detail/create/update incident workflows using the universal
envelope contract.
"""

from __future__ import annotations

from flask import Blueprint, request
from flask_login import current_user, login_required

from src.services.incident_service import IncidentService
from utils.api_helper import error_response, parse_paging_args, success_response


api_incidents = Blueprint("api_incidents", __name__, url_prefix="/api/incidents")


@api_incidents.route("", methods=["GET"])
@login_required
def list_incidents():
    params = parse_paging_args(default_sort="created_at")
    if not params.get("search"):
        params["search"] = request.args.get("q", "", type=str)

    severity = request.args.get("severity", "", type=str)
    status = request.args.get("status", "", type=str)
    category = request.args.get("category", "", type=str)

    data, code = IncidentService.list_incidents(
        page=params["page"],
        page_size=params["page_size"],
        sort=params["sort"],
        order=params["order"],
        search=params["search"],
        severity=severity,
        status=status,
        category=category,
    )
    if code != 200:
        return error_response(data.get("message") or "Failed to list incidents", status_code=code)

    return success_response(
        data=data,
        filters={
            "sort": params["sort"],
            "order": params["order"],
            "search": params["search"],
            "severity": severity,
            "status": status,
            "category": category,
        },
        status_code=200,
    )


@api_incidents.route("", methods=["POST"])
@login_required
def create_incident():
    payload = request.get_json(silent=True) or {}
    actor = getattr(current_user, "username", "system")
    incident, code = IncidentService.create_incident(payload, actor=actor)

    if code >= 400:
        return error_response(
            message=incident.get("message") or "Failed to create incident",
            status_code=code,
            hint=str(incident.get("hint") or ""),
        )

    return success_response(data=incident, status_code=code)


@api_incidents.route("/<incident_id>", methods=["GET"])
@login_required
def get_incident_detail(incident_id: str):
    incident, code = IncidentService.get_incident(incident_id)
    if code != 200 or not incident:
        return error_response("Incident not found", status_code=404)
    return success_response(data=incident, status_code=200)


@api_incidents.route("/<incident_id>", methods=["PATCH"])
@login_required
def update_incident(incident_id: str):
    payload = request.get_json(silent=True) or {}
    actor = getattr(current_user, "username", "system")
    incident, code = IncidentService.update_incident(incident_id, payload, actor=actor)
    if code == 404:
        return error_response("Incident not found", status_code=404)
    if code >= 400 or incident is None:
        return error_response("Failed to update incident", status_code=code)
    return success_response(data=incident, status_code=200)


@api_incidents.route("/<incident_id>/events", methods=["GET"])
@login_required
def get_incident_events(incident_id: str):
    incident, code = IncidentService.get_incident(incident_id)
    if code != 200 or not incident:
        return error_response("Incident not found", status_code=404)

    timeline = incident.get("timeline")
    if not isinstance(timeline, list):
        timeline = []

    return success_response(
        data={
            "items": timeline,
            "total": len(timeline),
            "page": 1,
            "page_size": len(timeline) if timeline else 0,
            "total_pages": 1,
            "kpis": {
                "event_count": len(timeline),
            },
        },
        filters={},
        status_code=200,
    )
