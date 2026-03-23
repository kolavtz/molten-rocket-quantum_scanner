"""
Report Generator Module

Creates executive summaries and exportable reports from scan results,
CBOM data, and validation outcomes.

Classes:
    ReportGenerator — assembles and exports scan reports.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from typing import Any, Dict, List

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import APP_NAME, APP_VERSION


def _json_default(value: Any):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


class ReportGenerator:
    """Assembles executive-summary reports from scan pipeline output.

    Usage::

        gen = ReportGenerator()
        report = gen.generate_summary(cbom_dict, validations, labels)
    """

    def generate_summary(
        self,
        cbom_dict: Dict[str, Any],
        validations: List[Dict[str, Any]],
        labels: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build an executive-summary report dict."""
        summary = cbom_dict.get("summary", {})
        total = summary.get("total_assets", 0)
        safe = summary.get("quantum_safe", 0)
        vuln = summary.get("quantum_vulnerable", 0)

        # Aggregate findings
        all_findings: List[Dict[str, Any]] = []
        all_recommendations: List[str] = []
        for v in validations:
            all_findings.extend(v.get("findings", []))
            all_recommendations.extend(v.get("recommendations", []))

        # Deduplicate recommendations
        unique_recs = list(dict.fromkeys(all_recommendations))

        # Severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Compliance distribution
        scores = [v.get("compliance_score", 0) for v in validations]
        avg_score = round(sum(scores) / len(scores)) if scores else 0

        # Risk distribution
        risk_dist = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in validations:
            rl = v.get("hndl_risk_level", "HIGH")
            risk_dist[rl] = risk_dist.get(rl, 0) + 1

        # Label distribution
        label_dist = {"PQC Ready": 0, "Partial": 0, "Non-Compliant": 0}
        for lb in labels:
            lt = lb.get("label", "Non-Compliant")
            label_dist[lt] = label_dist.get(lt, 0) + 1

        return {
            "report_id": cbom_dict.get("serial_number", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": {"name": APP_NAME, "version": APP_VERSION},
            "overview": {
                "total_assets": total,
                "quantum_safe": safe,
                "quantum_vulnerable": vuln,
                "average_compliance_score": avg_score,
            },
            "severity_breakdown": severity_counts,
            "risk_distribution": risk_dist,
            "label_distribution": label_dist,
            "top_recommendations": unique_recs[:10],
            "findings": all_findings,
            "labels": labels,
            "assets": cbom_dict.get("assets", []),
        }

    def export_json(self, report: Dict[str, Any], path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=_json_default)
