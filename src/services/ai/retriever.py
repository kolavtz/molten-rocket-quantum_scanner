"""
Simple live-API retriever to build a compact textual context for the LLM.
Uses CbomService to fetch KPIs and sample application rows.
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional
from src.services.cbom_service import CbomService


def _format_sample_entry(row: Dict[str, Any]) -> str:
    # Row may be a dict or object mapping depending on caller; keep it defensive.
    try:
        asset = row.get("asset_name") or row.get("asset") or row.get("target") or ""
    except Exception:
        asset = ""
    parts = [
        f"asset={asset}",
        f"subject_cn={row.get('subject_cn') or row.get('subject_name') or ''}",
        f"issuer={row.get('issuer') or row.get('ca') or ''}",
        f"cipher={row.get('cipher_suite') or row.get('cipher') or ''}",
        f"key_length={row.get('key_length') or ''}",
        f"valid_until={row.get('valid_until') or row.get('valid_to') or ''}",
    ]
    return "; ".join(p for p in parts if p)


def build_cbom_context(asset_id: Optional[int] = None, scan_id: Optional[int] = None, limit: int = 5) -> Dict[str, Any]:
    """
    Returns a small payload:
      { 'text': '...', 'kpis': {...}, 'samples': [ {...}, ... ] }
    """
    data = CbomService.get_cbom_dashboard_data(asset_id=asset_id, start_date=None, end_date=None, limit=limit)
    kpis = data.get("kpis", {})
    applications = data.get("applications") or data.get("items") or []
    samples = []
    for idx, app in enumerate(applications[:limit]):
        if isinstance(app, dict):
            samples.append(app)
        else:
            # Best-effort convert SQLAlchemy object to dict if needed
            try:
                samples.append({k: getattr(app, k) for k in getattr(app, "__dict__", {}) if not k.startswith("_")})
            except Exception:
                samples.append({})
    # Build short text context
    lines: List[str] = []
    lines.append("CBOM KPIs:")
    for k, v in kpis.items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append(f"Top {len(samples)} CBOM entries (compact):")
    for i, s in enumerate(samples, 1):
        lines.append(f"{i}. {_format_sample_entry(s)}")
    context_text = "\n".join(lines)
    return {"text": context_text, "kpis": kpis, "samples": samples}
