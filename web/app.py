"""
Quantum-Safe TLS Scanner — Flask Web Application

Routes:
    GET  /            → Scanner dashboard
    POST /scan        → Run scan pipeline
    GET  /results/<id>→ View scan results
    GET  /cbom/<id>   → Download CBOM JSON
    GET  /api/scan    → REST API endpoint
"""

from __future__ import annotations

import json
import os
import uuid
import traceback
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    redirect,
    url_for,
)

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config import SECRET_KEY, DEBUG, FLASK_HOST, FLASK_PORT, RESULTS_DIR, AUTODISCOVERY_PORTS
from src.scanner.network_discovery import NetworkScanner, sanitize_target
from src.scanner.tls_analyzer import TLSAnalyzer
from src.scanner.pqc_detector import PQCDetector
from src.cbom.builder import CBOMBuilder
from src.cbom.cyclonedx_generator import CycloneDXGenerator
from src.validator.quantum_safe_checker import QuantumSafeChecker
from src.validator.certificate_issuer import CertificateIssuer
from src.reporting.report_generator import ReportGenerator
from src.reporting.recommendation_engine import RecommendationEngine
from src import database as db

# ── Flask App ────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.secret_key = SECRET_KEY

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# In-memory store — hydrated from MySQL on cold start
scan_store: dict = {}

# Initialise MySQL (if available) and hydrate scan_store
_db_available = db.init_db()
if _db_available:
    for _report in db.list_scans(limit=100):
        _sid = _report.get("scan_id")
        if _sid:
            scan_store[_sid] = _report
    print(f"  💾 MySQL connected — loaded {len(scan_store)} scans from database")
else:
    # Fallback: load from JSON files on disk
    for _fname in os.listdir(RESULTS_DIR):
        if _fname.endswith("_report.json"):
            try:
                with open(os.path.join(RESULTS_DIR, _fname), "r", encoding="utf-8") as _fh:
                    _report = json.load(_fh)
                    _sid = _report.get("scan_id")
                    if _sid:
                        scan_store[_sid] = _report
            except Exception:
                pass
    print(f"  📂 JSON-only mode — loaded {len(scan_store)} scans from disk")

# ── Pipeline ─────────────────────────────────────────────────────────


def run_scan_pipeline(target: str, ports: list[int] | None = None) -> dict:
    """Execute the full scan pipeline and return a report dict."""
    scan_id = str(uuid.uuid4())[:8]

    # 1. Service Discovery (broad port sweep)
    scanner = NetworkScanner()
    all_services = scanner.discover_services(target, ports)
    discovered_services = [
        {
            "host": ep.host,
            "port": ep.port,
            "service": ep.service,
            "is_tls": ep.is_tls,
            "banner": ep.banner,
        }
        for ep in all_services
    ]

    # 2. Filter to TLS-capable endpoints only
    tls_endpoints = [ep for ep in all_services if ep.is_tls]

    # Fallback: if no TLS endpoints from broad sweep, try port 443 directly
    if not tls_endpoints:
        endpoints = scanner.discover_targets(target, ports)

        if not tls_endpoints:
            # Last resort: direct TLS analysis on port 443
            analyzer = TLSAnalyzer()
            tls_result = analyzer.analyze_endpoint(target, 443)
            if tls_result.is_successful:
                tls_results = [tls_result.to_dict()]
            else:
                return {
                    "scan_id": scan_id,
                    "target": target,
                    "status": "no_endpoints",
                    "message": f"No TLS endpoints found on {target}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "discovered_services": discovered_services,
                }
    else:
        # 3. TLS Analysis for each TLS endpoint
        analyzer = TLSAnalyzer()
        tls_results = []
        for ep in tls_endpoints:
            result = analyzer.analyze_endpoint(ep.host, ep.port)
            if result.is_successful:
                tls_results.append(result.to_dict())

    if not tls_results:
        return {
            "scan_id": scan_id,
            "target": target,
            "status": "analysis_failed",
            "message": "TLS analysis failed for all endpoints.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # 3. PQC Assessment
    detector = PQCDetector()
    pqc_assessments = [detector.assess_endpoint(tr) for tr in tls_results]
    pqc_dicts = [a.to_dict() for a in pqc_assessments]

    # 4. Build CBOM
    builder = CBOMBuilder()
    cbom = builder.build(tls_results, pqc_dicts)
    cbom_dict = cbom.to_dict()

    # 5. Validation
    checker = QuantumSafeChecker()
    validations = [
        checker.validate(tr, pd).to_dict()
        for tr, pd in zip(tls_results, pqc_dicts)
    ]

    # 6. Issue Labels
    issuer = CertificateIssuer()
    labels = [lb.to_dict() for lb in issuer.issue_labels(validations)]

    # 7. Recommendations
    rec_engine = RecommendationEngine()
    recommendations = []
    for v in validations:
        recommendations.extend(rec_engine.get_recommendations(v))

    # 8. Generate report
    reporter = ReportGenerator()
    report = reporter.generate_summary(cbom_dict, validations, labels)
    report["scan_id"] = scan_id
    report["target"] = target
    report["status"] = "complete"
    report["tls_results"] = tls_results
    report["pqc_assessments"] = pqc_dicts
    report["recommendations_detailed"] = recommendations
    report["discovered_services"] = discovered_services

    # 9. Export CBOM JSON
    cdx_gen = CycloneDXGenerator()
    cbom_path = os.path.join(RESULTS_DIR, f"{scan_id}_cbom.json")
    cdx_gen.export_json(cbom_dict, cbom_path)
    report["cbom_path"] = cbom_path

    # 10. Save report (JSON file — primary)
    report_path = os.path.join(RESULTS_DIR, f"{scan_id}_report.json")
    reporter.export_json(report, report_path)

    # 11. Save to MySQL (redundant copy)
    db.save_scan(report)
    db.save_cbom(scan_id, cbom_dict)

    # Store in memory
    scan_store[scan_id] = report

    return report


# ── Routes ───────────────────────────────────────────────────────────


@app.route("/")
def index():
    """Scanner dashboard with enterprise metrics, scan form, and recent results."""
    recent_scans = sorted(
        scan_store.values(),
        key=lambda s: s.get("generated_at", ""),
        reverse=True,
    )[:10]

    # Calculate Enterprise Aggregate Metrics
    enterprise_metrics = {
        "total_assets": 0,
        "quantum_safe": 0,
        "quantum_vulnerable": 0,
        "total_score": 0,
        "scan_count": 0,
        "avg_score": 0,
        "critical_findings": 0,
    }

    for scan in scan_store.values():
        if scan.get("status") != "complete" or not scan.get("overview"):
            continue
        
        overview = scan["overview"]
        enterprise_metrics["scan_count"] += 1
        enterprise_metrics["total_assets"] += overview.get("total_assets", 0)
        enterprise_metrics["quantum_safe"] += overview.get("quantum_safe", 0)
        enterprise_metrics["quantum_vulnerable"] += overview.get("quantum_vulnerable", 0)
        enterprise_metrics["total_score"] += overview.get("average_compliance_score", 0)
        
        # Count critical findings
        for finding in scan.get("findings", []):
            if finding.get("severity", "").upper() == "CRITICAL":
                enterprise_metrics["critical_findings"] += 1

    if enterprise_metrics["scan_count"] > 0:
        enterprise_metrics["avg_score"] = round(
            enterprise_metrics["total_score"] / enterprise_metrics["scan_count"]
        )

    return render_template(
        "index.html", 
        recent_scans=recent_scans, 
        enterprise_metrics=enterprise_metrics
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Run a scan on one or multiple targets (text input + CSV upload)."""
    import re
    import csv
    import io

    target_input = request.form.get("target", "").strip()
    ports_str = request.form.get("ports", "").strip()
    autodiscovery = request.form.get("autodiscovery") == "on"

    # Parse global custom ports
    custom_ports = None
    if ports_str:
        try:
            custom_ports = [
                int(p.strip()) for p in ports_str.replace(" ", ",").split(",")
                if p.strip().isdigit()
            ]
        except ValueError:
            pass

    # Autodiscovery mode: use the exhaustive port list
    if autodiscovery and not custom_ports:
        custom_ports = list(AUTODISCOVERY_PORTS)

    # ── Collect targets from text input ──
    targets = []  # list of (host, per_target_ports_or_None)
    if target_input:
        raw_targets = re.split(r'[,\n]+', target_input)
        for t in raw_targets:
            t = t.strip()
            if t:
                targets.append((t, custom_ports))

    # ── Collect targets from CSV upload ──
    csv_file = request.files.get("csv_file")
    if csv_file and csv_file.filename:
        try:
            stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"))
            reader = csv.DictReader(stream)
            # Normalize column headers to lowercase
            if reader.fieldnames:
                reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]
            for row in reader:
                host = (
                    row.get("ip", "")
                    or row.get("host", "")
                    or row.get("target", "")
                    or row.get("domain", "")
                ).strip()
                if not host:
                    continue
                port_val = row.get("port", "").strip()
                if port_val and port_val.isdigit():
                    row_ports = [int(port_val)]
                else:
                    row_ports = custom_ports
                targets.append((host, row_ports))
        except Exception:
            pass  # silently skip malformed CSV

    if not targets:
        return redirect(url_for("index"))

    try:
        if len(targets) == 1:
            # Single scan: redirect directly to results page
            host, ports = targets[0]
            clean_target, _ = sanitize_target(host)
            report = run_scan_pipeline(clean_target, ports)
            return redirect(url_for("results", scan_id=report.get("scan_id", "")))
        else:
            # Bulk scan: run all and redirect to dashboard
            for host, ports in targets:
                try:
                    clean_target, _ = sanitize_target(host)
                    run_scan_pipeline(clean_target, ports)
                except Exception:
                    continue  # skip invalid targets in bulk mode

            return redirect(url_for("index"))

    except Exception as exc:
        error_id = str(uuid.uuid4())[:8]
        return render_template(
            "error.html",
            error_id=error_id,
            error_message=str(exc),
            traceback_info=traceback.format_exc(),
        )


@app.route("/results/<scan_id>")
def results(scan_id: str):
    """Display scan results (memory → disk → MySQL fallback)."""
    report = scan_store.get(scan_id)
    if not report:
        # Try loading from disk
        report_path = os.path.join(RESULTS_DIR, f"{scan_id}_report.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
                scan_store[scan_id] = report
        else:
            # Try loading from MySQL
            report = db.get_scan(scan_id)
            if report:
                scan_store[scan_id] = report
            else:
                return render_template("error.html", error_message="Scan not found."), 404

    return render_template("results.html", report=report, scan_id=scan_id)


@app.route("/cbom/<scan_id>")
def download_cbom(scan_id: str):
    """Download CBOM JSON file (disk → MySQL fallback)."""
    cbom_path = os.path.join(RESULTS_DIR, f"{scan_id}_cbom.json")
    if os.path.exists(cbom_path):
        return send_file(
            cbom_path,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"cbom_{scan_id}.json",
        )
    # Fallback: try MySQL
    cbom_data = db.get_cbom(scan_id)
    if cbom_data:
        return jsonify(cbom_data)
    return jsonify({"error": "CBOM not found"}), 404


@app.route("/api/scan", methods=["GET", "POST"])
def api_scan():
    """REST API endpoint for CI/CD integration."""
    if request.method == "GET":
        target = request.args.get("target", "")
    else:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "") or request.form.get("target", "")

    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400

    try:
        clean_target, _ = sanitize_target(target)
        report = run_scan_pipeline(clean_target)
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/scans")
def api_list_scans():
    """List all stored scan results."""
    scans = [
        {
            "scan_id": r.get("scan_id"),
            "target": r.get("target"),
            "status": r.get("status"),
            "generated_at": r.get("generated_at"),
            "overview": r.get("overview"),
        }
        for r in scan_store.values()
    ]
    return jsonify(scans)


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  🔒 {app.import_name} — Quantum-Safe TLS Scanner")
    print(f"  📡 Running on http://{FLASK_HOST}:{FLASK_PORT}")
    print(f"{'='*60}\n")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=DEBUG)
