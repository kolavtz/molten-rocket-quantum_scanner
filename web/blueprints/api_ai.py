"""
API AI Assistant - /api/ai/* endpoints
Provides session-first API access (login or X-API-Key) to a small local LLM
that can answer questions about CBOM data using live context from CbomService.
"""
from flask import Blueprint, request, jsonify, current_app, Response
from middleware.api_auth import api_guard
from flask_login import current_user
from src.services.cbom_service import CbomService
from src import database as db

# Local ai services (small, server-side wrappers)
from src.services.ai.llm_client import LLMClient
from src.services.ai.retriever import build_cbom_context
from src.services.ai.prompt_templates import build_prompt_for_query
from src.services.ai.rag import search as rag_search, reindex_from_cbom
from flask import stream_with_context
import os

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

        # Optionally augment with RAG documents
        use_rag = payload.get("use_rag")
        if use_rag is None:
            use_rag = os.environ.get("QSS_AI_USE_RAG", "false").lower() in ("1", "true", "yes")
        rag_docs = []
        if use_rag:
            try:
                rag_docs = rag_search(query, limit=5)
                if rag_docs:
                    # Append compact RAG findings to the context text so the LLM can cite them
                    rag_lines = ["RAG Documents:"]
                    for i, d in enumerate(rag_docs, 1):
                        src = d.get("source") or d.get("id")
                        snip = d.get("snippet") or (d.get("content") or "")[:300]
                        rag_lines.append(f"{i}. [{src}] {snip}")
                    context_text = context_text + "\n\n" + "\n".join(rag_lines)
                    sources["rag"] = rag_docs
            except Exception:
                current_app.logger.exception("RAG search failed (non-fatal)")

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



@api_ai.route("/cbom-query/stream", methods=["GET"])
@api_guard
def stream_cbom_query():
    """SSE streaming endpoint for incremental LLM output.
    Query parameters: query, asset_id, scan_id, limit, max_tokens, temperature, use_rag
    """
    try:
        query = str(request.args.get("query") or "").strip()
        if not query:
            return jsonify({"success": False, "message": "Query required."}), 400

        asset_id = request.args.get("asset_id")
        scan_id = request.args.get("scan_id")
        limit = int(request.args.get("limit") or 5)
        max_tokens = int(request.args.get("max_tokens") or os.environ.get("QSS_AI_MAX_TOKENS", 512))
        temperature = float(request.args.get("temperature") or os.environ.get("QSS_AI_TEMPERATURE", 0.2))

        # Build context
        ctx = build_cbom_context(asset_id=asset_id, scan_id=scan_id, limit=limit)
        context_text = ctx.get("text", "")
        sources = {"kpis": ctx.get("kpis", {}), "sample_entries": ctx.get("samples", [])}

        use_rag = request.args.get("use_rag")
        if use_rag is None:
            use_rag = os.environ.get("QSS_AI_USE_RAG", "false").lower() in ("1", "true", "yes")
        if use_rag:
            try:
                rag_docs = rag_search(query, limit=5)
                if rag_docs:
                    rag_lines = ["RAG Documents:"]
                    for i, d in enumerate(rag_docs, 1):
                        src = d.get("source") or d.get("id")
                        snip = d.get("snippet") or (d.get("content") or "")[:300]
                        rag_lines.append(f"{i}. [{src}] {snip}")
                    context_text = context_text + "\n\n" + "\n".join(rag_lines)
                    sources["rag"] = rag_docs
            except Exception:
                current_app.logger.exception("RAG search failed (non-fatal)")

        prompt = build_prompt_for_query(query=query, context=context_text)
        client = LLMClient()

        @stream_with_context
        def event_stream():
            try:
                for chunk in client.stream_generate(prompt=prompt, max_tokens=max_tokens, temperature=temperature):
                    # Each yielded chunk becomes an SSE data event
                    try:
                        data = chunk if isinstance(chunk, str) else str(chunk)
                    except Exception:
                        data = ''
                    yield f"data: {data}\n\n"
                # Signal completion
                yield "event: done\ndata: {}\n\n"
            except Exception as e:
                current_app.logger.exception("Error while streaming LLM output")
                yield f"event: error\ndata: {str(e)}\n\n"

        # Fire-and-forget audit (best-effort)
        try:
            db.append_audit_log(
                event_category="ai",
                event_type="assistant_query_stream",
                status="started",
                actor_user_id=getattr(current_user, "id", None),
                actor_username=getattr(current_user, "username", None),
                request_method=request.method,
                request_path=request.path,
                details={"query": query, "asset_id": asset_id, "scan_id": scan_id},
            )
        except Exception:
            current_app.logger.debug("AI streaming audit failed (non-fatal)")

        return Response(event_stream(), mimetype="text/event-stream")

    except Exception as e:
        current_app.logger.exception("Unhandled error in AI streaming endpoint")
        return jsonify({"success": False, "message": "Internal server error", "error": str(e)}), 500



@api_ai.route("/cbom-reindex", methods=["POST"])
@api_guard
def cbom_reindex():
    """Trigger a RAG reindex from CBOM data. Restricted to admin users (session or API key)."""
    try:
        # Simple admin check: session user role or API key owner role
        def _is_admin():
            try:
                if getattr(current_user, "is_authenticated", False):
                    return getattr(current_user, "role", "").lower() == "admin"
            except Exception:
                pass
            # Check X-API-Key
            raw_key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if raw_key:
                user = db.get_user_by_api_key(raw_key)
                if user and user.get("role", "").lower() == "admin":
                    return True
            return False

        if not _is_admin():
            return jsonify({"success": False, "message": "Admin privileges required."}), 403

        count = reindex_from_cbom()
        return jsonify({"success": True, "indexed": count}), 200
    except Exception as e:
        current_app.logger.exception("RAG reindex failed")
        return jsonify({"success": False, "message": str(e)}), 500


@api_ai.route("/config", methods=["GET"])
@api_guard
def get_ai_config():
    """Return runtime AI/agent configuration (admin-only in production).

    For safety, secret values are masked unless the app is running in TESTING mode
    or the caller is an admin. This endpoint is useful for debugging deployments.
    """
    try:
        # Allow in TESTING or for admin users/API keys that map to admin users
        is_testing = current_app.config.get("TESTING", False)

        def _is_admin_user():
            try:
                if getattr(current_user, "is_authenticated", False):
                    return getattr(current_user, "role", "").lower() == "admin"
            except Exception:
                pass
            # Also allow API key admin owners (api_guard may have set g.api_user)
            try:
                from flask import g as _g

                api_user = getattr(_g, "api_user", None)
                if api_user and api_user.get("role", "").lower() == "admin":
                    return True
            except Exception:
                pass
            return False

        if not (is_testing or _is_admin_user()):
            # Deny access if not testing and not admin
            return jsonify({"success": False, "message": "Admin privileges required."}), 403

        cfg = {
            "ai_server_url": os.environ.get("AI_SERVER_URL", ""),
            "ai_server_api_key_present": bool(os.environ.get("AI_SERVER_API_KEY") or os.environ.get("QSS_AI_SERVER_API_KEY")),
            "qss_ai_use_rag": os.environ.get("QSS_AI_USE_RAG", "false").lower() in ("1", "true", "yes"),
            "qss_ai_max_tokens": int(os.environ.get("QSS_AI_MAX_TOKENS", "512")),
            "qss_ai_temperature": float(os.environ.get("QSS_AI_TEMPERATURE", "0.2")),
            "qss_ai_model_backend": os.environ.get("QSS_AI_MODEL_BACKEND", ""),
            # Mask sensitive fields unless testing
            "qss_ai_system_prompt": os.environ.get("QSS_AI_SYSTEM_PROMPT") if is_testing or _is_admin_user() else (os.environ.get("QSS_AI_SYSTEM_PROMPT") and "<hidden>"),
            "qss_ai_model_path": os.environ.get("QSS_AI_MODEL_PATH") if is_testing else (os.environ.get("QSS_AI_MODEL_PATH") and "<masked>"),
            "agent_enabled": os.environ.get("QSS_AGENT_ENABLED", "false").lower() in ("1", "true", "yes"),
            "agent_backend_url": os.environ.get("QSS_AGENT_BACKEND_URL", ""),
            "agent_port": os.environ.get("QSS_AGENT_PORT", ""),
        }

        return jsonify({"success": True, "config": cfg}), 200
    except Exception as e:
        current_app.logger.exception("Failed to return AI config")
        return jsonify({"success": False, "message": str(e)}), 500
