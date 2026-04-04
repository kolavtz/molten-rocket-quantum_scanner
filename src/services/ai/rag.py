"""
Lightweight RAG index implementation using SQLite FTS5.

This module provides a simple reindexer that pulls CBOM entries via
CbomService and stores compact textual documents in a local SQLite FTS5
database. It exposes a search() function to retrieve the most relevant
documents for a free-text query.

Environment variables:
  QSS_RAG_DB_PATH - path to the sqlite DB file (default: data/ai_rag.db)
"""
from __future__ import annotations
import os
import sqlite3
import logging
from typing import List, Dict, Any, Optional

from src.services.cbom_service import CbomService

logger = logging.getLogger(__name__)


def _db_path() -> str:
    return os.environ.get("QSS_RAG_DB_PATH", "data/ai_rag.db")


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _get_conn():
    path = _db_path()
    _ensure_dir(path)
    conn = sqlite3.connect(path, check_same_thread=False)
    return conn


def init_db() -> None:
    conn = _get_conn()
    cur = conn.cursor()
    # Simple standalone FTS5 table for documents. Keep schema small.
    cur.execute("CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, title TEXT, content TEXT, source TEXT)")
    # FTS5 virtual table for full-text search; we keep it simple and rebuild on reindex.
    try:
        cur.execute("CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(content, source)")
    except sqlite3.OperationalError as e:
        # If FTS5 is unavailable, log an error and raise
        logger.error("SQLite FTS5 not available: %s", e)
        conn.close()
        raise
    conn.commit()
    conn.close()


def reindex_from_cbom(limit: int = 10000) -> int:
    """Rebuild the RAG index from CBOM data. Returns the number of documents indexed."""
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    # Clear existing FTS rows
    cur.execute("DELETE FROM documents_fts")
    conn.commit()

    indexed = 0
    try:
        # Pull a large snapshot of CBOM applications
        data = CbomService.get_cbom_dashboard_data(limit=limit)
        apps = data.get("applications") or data.get("items") or []
        docs = []
        for app in apps:
            doc_id = str(app.get("row_key") or f"{app.get('source')}:{app.get('record_id') or ''}")
            title = f"{app.get('asset_name') or ''} - {app.get('endpoint') or ''}".strip()
            # Build a compact content string
            parts = [f"asset: {app.get('asset_name')}", f"endpoint: {app.get('endpoint')}"]
            if app.get('subject_cn'):
                parts.append(f"subject_cn: {app.get('subject_cn')}")
            if app.get('issuer_o'):
                parts.append(f"issuer: {app.get('issuer_o')}")
            if app.get('cipher_suite') or app.get('cipher'):
                parts.append(f"cipher: {app.get('cipher_suite') or app.get('cipher')}")
            if app.get('key_length'):
                parts.append(f"key_length: {app.get('key_length')}")
            content = "\n".join(p for p in parts if p)
            docs.append((doc_id, title, content, str(app.get('source') or 'cbom')))

        # Insert into FTS table
        for doc_id, title, content, source in docs:
            try:
                # Keep a lightweight canonical document table as well (for future updates)
                cur.execute("INSERT OR REPLACE INTO documents (id, title, content, source) VALUES (?, ?, ?, ?)", (doc_id, title, content, source))
                # FTS table independent insert
                cur.execute("INSERT INTO documents_fts (content, source) VALUES (?, ?)", (content, source))
                indexed += 1
            except Exception:
                logger.exception("Failed to index doc %s", doc_id)
        conn.commit()
    finally:
        conn.close()

    logger.info("RAG reindex complete: indexed %d documents", indexed)
    return indexed


def search(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Search the RAG index for *query* and return a list of documents with snippets.
    If the index or FTS is unavailable, returns an empty list.
    """
    path = _db_path()
    if not os.path.exists(path):
        return []
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Use simple MATCH search; snippet() may not be available in all builds, so fall back safely.
        try:
            q = query.replace('"', ' ')
            cur.execute(
                "SELECT rowid, content, source, snippet(documents_fts, -1, '<b>', '</b>', '...', 64) as snippet FROM documents_fts WHERE documents_fts MATCH ? LIMIT ?",
                (q, int(limit)),
            )
            rows = cur.fetchall()
            results = []
            for row in rows:
                rowid, content, source, snippet = row
                results.append({"id": rowid, "content": content, "source": source, "snippet": snippet or content[:200]})
            return results
        except sqlite3.OperationalError:
            # Fallback simple LIKE scan against documents table
            cur.execute("SELECT id, title, content, source FROM documents WHERE content LIKE ? LIMIT ?", (f"%{query}%", int(limit)))
            rows = cur.fetchall()
            return [{"id": r[0], "title": r[1], "content": r[2], "source": r[3]} for r in rows]
    finally:
        conn.close()
