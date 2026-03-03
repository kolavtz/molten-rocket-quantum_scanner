#!/usr/bin/env python3
"""
QuantumShield — CLI Scanner

Run a full scan from the command line and print results to stdout
or export as JSON.

Usage:
    python scan.py google.com
    python scan.py 192.168.1.1 --json --output report.json
    python scan.py cloudflare.com --cbom --output cbom.json
"""

from __future__ import annotations

import argparse
import json
import sys
import os

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from src.scanner.network_discovery import NetworkScanner
from src.scanner.tls_analyzer import TLSAnalyzer
from src.scanner.pqc_detector import PQCDetector
from src.cbom.builder import CBOMBuilder
from src.cbom.cyclonedx_generator import CycloneDXGenerator
from src.validator.quantum_safe_checker import QuantumSafeChecker
from src.validator.certificate_issuer import CertificateIssuer
from src.reporting.report_generator import ReportGenerator
from src.reporting.recommendation_engine import RecommendationEngine


# ── ANSI colors ──
class C:
    BOLD  = "\033[1m"
    RED   = "\033[31m"
    GREEN = "\033[32m"
    YELLOW= "\033[33m"
    CYAN  = "\033[36m"
    RESET = "\033[0m"
    DIM   = "\033[2m"


def banner():
    print(f"""
{C.CYAN}+======================================================+
|  [*] QuantumShield - Quantum-Safe TLS Scanner        |
|      PNB Cybersecurity Hackathon 2026                |
+======================================================+{C.RESET}
""")


def print_section(title: str):
    print(f"\n{C.BOLD}{C.CYAN}── {title} ──{C.RESET}")


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": C.RED,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.CYAN,
        "INFO": C.DIM,
    }.get(sev, "")


def run_scan(target: str, ports: list[int] | None = None) -> dict:
    """Execute the full scan pipeline."""
    # 1. Network Discovery
    print(f"{C.DIM}[1/7] Discovering TLS endpoints...{C.RESET}")
    scanner = NetworkScanner()
    endpoints = scanner.discover_targets(target, ports)

    if not endpoints:
        # Fallback — direct TLS analysis on port 443
        analyzer = TLSAnalyzer()
        tls_result = analyzer.analyze_endpoint(target, 443)
        if tls_result.is_successful:
            tls_results = [tls_result.to_dict()]
        else:
            print(f"{C.RED}✗ No TLS endpoints found on {target}{C.RESET}")
            return {}
    else:
        # 2. TLS Analysis
        print(f"{C.DIM}[2/7] Analyzing TLS handshakes ({len(endpoints)} endpoints)...{C.RESET}")
        analyzer = TLSAnalyzer()
        tls_results = []
        for ep in endpoints:
            result = analyzer.analyze_endpoint(ep.host, ep.port)
            if result.is_successful:
                tls_results.append(result.to_dict())

    if not tls_results:
        print(f"{C.RED}✗ TLS analysis failed for all endpoints{C.RESET}")
        return {}

    # 3. PQC Assessment
    print(f"{C.DIM}[3/7] Classifying PQC readiness...{C.RESET}")
    detector = PQCDetector()
    pqc_assessments = [detector.assess_endpoint(tr) for tr in tls_results]
    pqc_dicts = [a.to_dict() for a in pqc_assessments]

    # 4. Build CBOM
    print(f"{C.DIM}[4/7] Building CBOM...{C.RESET}")
    builder = CBOMBuilder()
    cbom = builder.build(tls_results, pqc_dicts)
    cbom_dict = cbom.to_dict()

    # 5. Validation
    print(f"{C.DIM}[5/7] Validating NIST PQC compliance...{C.RESET}")
    checker = QuantumSafeChecker()
    validations = [
        checker.validate(tr, pd).to_dict()
        for tr, pd in zip(tls_results, pqc_dicts)
    ]

    # 6. Issue Labels
    print(f"{C.DIM}[6/7] Issuing Quantum-Safe labels...{C.RESET}")
    issuer = CertificateIssuer()
    labels = [lb.to_dict() for lb in issuer.issue_labels(validations)]

    # 7. Generate report
    print(f"{C.DIM}[7/7] Generating report...{C.RESET}")
    rec_engine = RecommendationEngine()
    recommendations = []
    for v in validations:
        recommendations.extend(rec_engine.get_recommendations(v))

    reporter = ReportGenerator()
    report = reporter.generate_summary(cbom_dict, validations, labels)
    report["target"] = target
    report["tls_results"] = tls_results
    report["pqc_assessments"] = pqc_dicts
    report["recommendations_detailed"] = recommendations

    return report


def print_results(report: dict):
    """Print a human-readable summary to stdout."""
    overview = report.get("overview", {})
    labels = report.get("labels", [])
    findings = report.get("findings", [])
    recs = report.get("recommendations_detailed", [])
    tls = report.get("tls_results", [])

    # ── Overview ──
    print_section("SCAN OVERVIEW")
    score = overview.get("average_compliance_score", 0)
    score_color = C.GREEN if score >= 80 else C.YELLOW if score >= 50 else C.RED
    print(f"  Target:             {C.BOLD}{report.get('target')}{C.RESET}")
    print(f"  Total Assets:       {overview.get('total_assets', 0)}")
    print(f"  Quantum Safe:       {C.GREEN}{overview.get('quantum_safe', 0)}{C.RESET}")
    print(f"  Quantum Vulnerable: {C.RED}{overview.get('quantum_vulnerable', 0)}{C.RESET}")
    print(f"  Compliance Score:   {score_color}{score}%{C.RESET}")

    # ── Labels ──
    print_section("QUANTUM-SAFE LABELS")
    for lb in labels:
        label_text = lb.get("label", "Unknown")
        if label_text == "PQC Ready":
            lc = C.GREEN
        elif label_text == "Partial":
            lc = C.YELLOW
        else:
            lc = C.RED
        tag = "[SAFE]" if label_text == "PQC Ready" else "[WARN]" if label_text == "Partial" else "[FAIL]"
        print(f"  {tag} {lc}{C.BOLD}{label_text}{C.RESET} -- {lb.get('host')}:{lb.get('port')} (Score: {lb.get('compliance_score')}%)")

    # ── Findings ──
    if findings:
        print_section("SECURITY FINDINGS")
        for f in findings:
            sev = f.get("severity", "INFO")
            sc = severity_color(sev)
            print(f"  {sc}[{sev:8s}]{C.RESET} {C.BOLD}{f.get('title')}{C.RESET}")
            print(f"             {C.DIM}{f.get('description', '')}{C.RESET}")
            if f.get("current_value"):
                print(f"             Current: {f['current_value']}  →  Recommended: {f.get('recommended_value', '—')}")

    # ── TLS Details ──
    if tls:
        print_section("TLS ENDPOINT DETAILS")
        for t in tls:
            print(f"  {C.BOLD}{t['host']}:{t['port']}{C.RESET}")
            print(f"    Protocol:    {t.get('protocol_version', '—')}")
            print(f"    Cipher:      {t.get('cipher_suite', '—')}")
            print(f"    Key Exchange:{t.get('key_exchange', '—')}")
            cert = t.get("certificate", {})
            if cert:
                print(f"    Cert Subject:{cert.get('subject', {}).get('commonName', '—')}")
                print(f"    Cert Issuer: {cert.get('issuer', {}).get('commonName', '—')}")
                print(f"    PubKey:      {cert.get('public_key_type', '—')} ({cert.get('public_key_bits', 0)} bit)")
                print(f"    Sig Algo:    {cert.get('signature_algorithm', '—')}")

    # ── Top Recommendations ──
    if recs:
        print_section("TOP RECOMMENDATIONS")
        for r in recs[:5]:
            print(f"  {C.BOLD}P{r.get('priority', '?')}: {r.get('title')}{C.RESET}")
            print(f"     {C.DIM}{r.get('description', '')[:120]}...{C.RESET}")
            print(f"     Impact: {r.get('impact')} | Effort: {r.get('effort')} | Timeline: {r.get('timeline')}")

    print(f"\n{C.GREEN}{'='*56}{C.RESET}")
    print(f"  Scan complete. Use {C.CYAN}--json{C.RESET} or {C.CYAN}--cbom{C.RESET} for machine-readable output.")
    print(f"{C.GREEN}{'='*56}{C.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="QuantumShield — Quantum-Safe TLS Scanner (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python scan.py google.com\n  python scan.py 10.0.0.0/28 --json --output report.json\n  python scan.py example.com --cbom --output cbom.json",
    )
    parser.add_argument("target", help="Hostname, IP, or CIDR range to scan")
    parser.add_argument("--ports", nargs="+", type=int, help="Override default TLS ports")
    parser.add_argument("--json", action="store_true", help="Output full report as JSON")
    parser.add_argument("--cbom", action="store_true", help="Output CBOM as CycloneDX JSON")
    parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    args = parser.parse_args()

    banner()

    report = run_scan(args.target, args.ports)
    if not report:
        sys.exit(1)

    if args.json:
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"{C.GREEN}✓ Report saved to {args.output}{C.RESET}")
        else:
            print(output)
    elif args.cbom:
        builder = CBOMBuilder()
        cbom = builder.build(report["tls_results"], report["pqc_assessments"])
        gen = CycloneDXGenerator()
        cdx_json = gen._generate_manual(cbom.to_dict())
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(cdx_json)
            print(f"{C.GREEN}✓ CBOM saved to {args.output}{C.RESET}")
        else:
            print(cdx_json)
    else:
        print_results(report)


if __name__ == "__main__":
    main()
