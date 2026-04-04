"""
API AI Assistant - /api/ai/* endpoints
Provides session-first API access (login or X-API-Key) to a small local LLM
that can answer questions about CBOM data using live context from CbomService.
"""
from flask import Blueprint, request, jsonify, current_app
from middleware.api_auth import api_guard
from flask_login import current_user
from src.services.cbom_service import CbomService
from src import database as db

# Local ai services (small, server-side wrappers)
from src.services.ai.llm_client import LLMClient
from src.services.ai.retriever import build_cbom_context
from src.services.ai.prompt_templates import build_prompt_for_query

api_ai = Blueprint("api_ai", __name__, url_prefix="/api/ai")


@api_ai.route("/cbom-context", methods=["GET"])
@api_guard
def get_cbom_context():
    """Return compact CBOM context (KPIs + sample entries) for the UI."""
    try:
        asset_id = request.args.get("asset_id", type=int)
        limit = int(request.args.get("limit", 5))
        ctx = build_cbom_context(asset_id=asset_id, limit=limit)
        return jsonify({"success": True, "data": {"kpis": ctx.get("kpis", {}), "sample_entries": ctx.get("samples", [])}}), 200
    except Exception as e:
        current_app.logger.exception("Failed to build CBOM context")
        return jsonify({"success": False, "message": str(e)}), 500


@api_ai.route("/cbom-query", methods=["POST"])
@api_guard
def post_cbom_query():
    """
    POST /api/ai/cbom-query
    Body: { "query": "...", "asset_id": 1?, "scan_id": 123?, "limit": 5?, "max_tokens": 256?, "temperature": 0.2? }
    Returns structured answer and the sources used (kpis + sample entries).
    """
    try:
        payload = (request.get_json(silent=True) or {})
        query = str(payload.get("query") or "").strip()
        if not query:
            return jsonify({"success": False, "message": "Query required."}), 400

        asset_id = payload.get("asset_id")
        scan_id = payload.get("scan_id")
        limit = int(payload.get("limit", 5))

        # Build context (small textual summary + structured sources)
        ctx = build_cbom_context(asset_id=asset_id, scan_id=scan_id, limit=limit)
        context_text = ctx.get("text", "")
        sources = {"kpis": ctx.get("kpis", {}), "sample_entries": ctx.get("samples", [])}

        # Build prompt and call LLM
        prompt = build_prompt_for_query(query=query, context=context_text)

        client = LLMClient()
        try:
            answer = client.generate(
                prompt=prompt,
                max_tokens=int(payload.get("max_tokens", 256)),
                temperature=float(payload.get("temperature", 0.2)),
            )
        except Exception as e:
            current_app.logger.exception("LLM generation failed")
            return jsonify({"success": False, "message": "LLM backend error", "error": str(e)}), 503

        # Audit the request (tamper-evident audit chain)
        try:
            db.append_audit_log(
                event_category="ai",
                event_type="assistant_query",
                status="success",
                actor_user_id=getattr(current_user, "id", None),
                actor_username=getattr(current_user, "username", None),
                request_method=request.method,
                request_path=request.path,
                details={"query": query, "asset_id": asset_id, "scan_id": scan_id},
            )
        except Exception:
            # Best-effort auditing; never fail the request because of audit errors
            current_app.logger.debug("AI audit log failed (non-fatal)")

        return jsonify({"success": True, "answer": answer, "sources": sources}), 200

    except Exception as e:
        current_app.logger.exception("Unhandled error in AI cbom-query")
        return jsonify({"success": False, "message": "Internal server error", "error": str(e)}), 500
