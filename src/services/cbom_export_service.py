"""
CBOM Export Service
Generates CycloneDX standard JSON and Visual PDF reports for Cryptographic Bill of Materials.
"""

import io
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class CbomExportService:

    @staticmethod
    def generate_cyclonedx_json(cbom_dashboard_data: Dict[str, Any]) -> str:
        """
        Generates standard CycloneDX JSON representation ("bomFormat": "CycloneDX").
        Conforms to CycloneDX v1.4 / v1.5 specification for Cryptographic Assets.
        """
        applications = cbom_dashboard_data.get("applications", [])
        minimum_elements = cbom_dashboard_data.get("minimum_elements", {}).get("items", [])
        kpis = cbom_dashboard_data.get("kpis", {})

        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        components = []

        # 1. Map Consolidated Domain / Application Components
        for app in applications:
            domain_name = app.get("asset_name") or app.get("subject_cn") or "Unknown-Domain"
            key_len = app.get("key_length") or 2048
            key_type = app.get("public_key_type") or "RSA"
            cipher = app.get("cipher_suite") or "AES-GCM"
            tls_ver = app.get("tls_version") or "TLS 1.2"
            ca = app.get("ca") or "Unknown CA"

            component_bom_ref = f"crypto-component-{app.get('asset_id') or uuid.uuid4()}"

            components.append({
                "type": "cryptographic-asset",
                "bom-ref": component_bom_ref,
                "name": domain_name,
                "version": tls_ver,
                "description": f"Domain cryptographic profile for {domain_name} using {key_type}-{key_len} and {cipher}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "algorithmProperties": {
                        "primitive": "key-exchange",
                        "parameterSetIdentifier": str(key_len),
                        "executionEnvironment": "tls-stack",
                        "implementationPlatform": "web-server",
                        "certificationLevel": ["FIPS 140-2"],
                        "cryptoFunctions": ["key-exchange", "encryption", "digital-signature"],
                        "classicalSecurityLevel": int(key_len) if isinstance(key_len, int) else 128,
                        "nistQuantumSecurityLevel": 1 if key_len >= 2048 else 0
                    },
                    "protocolProperties": {
                        "type": "tls",
                        "version": tls_ver,
                        "cipherSuites": [
                            {
                                "name": cipher,
                                "algorithms": [key_type, cipher]
                            }
                        ]
                    },
                    "certificateProperties": {
                        "subjectName": app.get("subject_cn") or domain_name,
                        "issuerName": ca,
                        "notValidBefore": app.get("valid_from"),
                        "notValidAfter": app.get("valid_until"),
                        "signatureAlgorithmRef": app.get("fingerprint_sha256") or ""
                    }
                }
            })

        # 2. Add granular CBOM entries if present
        for entry in minimum_elements:
            elem_name = entry.get("element_name") or entry.get("primitive") or "Crypto-Primitive"
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"entry-{entry.get('id') or uuid.uuid4()}",
                "name": elem_name,
                "description": f"Primitive: {entry.get('primitive')}, Key Size: {entry.get('key_size')}, Classical Security: {entry.get('classical_security_level')}",
                "cryptoProperties": {
                    "assetType": entry.get("asset_type") or "algorithm",
                    "algorithmProperties": {
                        "primitive": entry.get("primitive") or "cipher",
                        "classicalSecurityLevel": entry.get("classical_security_level") or 128
                    }
                }
            })

        cyclonedx_payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "QuantumShield",
                        "name": "CBOM Intelligence Scanner",
                        "version": "2.4.0"
                    }
                ],
                "properties": [
                    {"name": "total_applications", "value": str(kpis.get("total_applications", len(applications)))},
                    {"name": "active_certificates", "value": str(kpis.get("active_certificates", 0))},
                    {"name": "weak_crypto_count", "value": str(kpis.get("weak_crypto_count", 0))}
                ]
            },
            "components": components
        }

        return json.dumps(cyclonedx_payload, indent=2)

    @staticmethod
    def generate_visual_pdf(cbom_dashboard_data: Dict[str, Any]) -> io.BytesIO:
        """
        Generates a clean visual PDF report summarizing CBOM findings, subdomains,
        certificates, and deduplicated mitigations using ReportLab.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Title'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
            fontName="Helvetica-Bold"
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            fontName="Helvetica"
        )
        h2_style = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['BodyText'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155")
        )
        table_hdr_style = ParagraphStyle(
            'TableHdr',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            textColor=colors.white,
            fontName="Helvetica-Bold"
        )
        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#1e293b")
        )

        story = []

        # Title Block
        story.append(Paragraph("CRYPTOGRAPHIC BILL OF MATERIALS (CBOM) REPORT", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | QuantumShield Security Suite", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=15))

        # KPI Summary
        kpis = cbom_dashboard_data.get("kpis", {})
        applications = cbom_dashboard_data.get("applications", [])

        kpi_data = [
            [
                Paragraph(f"<b>Total Domains:</b> {kpis.get('total_applications', len(applications))}", body_style),
                Paragraph(f"<b>Sites Surveyed:</b> {kpis.get('sites_surveyed', 0)}", body_style),
                Paragraph(f"<b>Active Certs:</b> {kpis.get('active_certificates', 0)}", body_style),
                Paragraph(f"<b>Weak Crypto:</b> {kpis.get('weak_crypto_count', 0)}", body_style),
            ]
        ]
        t_kpi = Table(kpi_data, colWidths=[130, 130, 130, 130])
        t_kpi.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t_kpi)
        story.append(Spacer(1, 15))

        # Consolidated Domain Table
        story.append(Paragraph("Consolidated Domain Cryptographic Inventory", h2_style))

        headers = [
            Paragraph("Domain / Target", table_hdr_style),
            Paragraph("TLS Version", table_hdr_style),
            Paragraph("Key Length", table_hdr_style),
            Paragraph("Status", table_hdr_style),
            Paragraph("Endpoints", table_hdr_style),
            Paragraph("Subdomains", table_hdr_style)
        ]
        
        table_rows = [headers]
        for app in applications[:50]:  # Up to top 50 consolidated rows for PDF
            target = str(app.get("asset_name") or app.get("subject_cn") or "Unknown")
            tls_ver = str(app.get("tls_version") or "TLS 1.2")
            key_len = str(app.get("key_length") or "2048")
            status = str(app.get("cert_status") or "Valid")
            endpoints_cnt = str(app.get("total_endpoints") or len(app.get("all_endpoints", [1])))
            subdomains_cnt = str(app.get("total_subdomains") or len(app.get("all_subdomains", [])))

            table_rows.append([
                Paragraph(target, table_cell_style),
                Paragraph(tls_ver, table_cell_style),
                Paragraph(key_len, table_cell_style),
                Paragraph(status, table_cell_style),
                Paragraph(endpoints_cnt, table_cell_style),
                Paragraph(subdomains_cnt, table_cell_style)
            ])

        if len(table_rows) == 1:
            table_rows.append([Paragraph("No CBOM entries found", table_cell_style)] + [Paragraph("-", table_cell_style)]*5)

        t_inventory = Table(table_rows, colWidths=[150, 70, 70, 70, 75, 85])
        t_inventory.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t_inventory)
        story.append(Spacer(1, 15))

        # Deduplicated Mitigations Section
        story.append(Paragraph("Recommended Quantum-Safe Mitigation Steps (Deduplicated)", h2_style))

        mitigation_set = set()
        for app in applications:
            for m in app.get("mitigations", []):
                mitigation_set.add(m)

        if not mitigation_set:
            mitigation_set = {
                "Migrate legacy RSA (key length < 2048) and ECDSA (P-256) to NIST Post-Quantum Standards (ML-KEM-768, ML-DSA-65).",
                "Enforce TLS 1.3 across all perimeter and internal endpoints; deprecate TLS 1.0 and 1.1.",
                "Ensure all certificates are issued by trusted, non-expired Certificate Authorities with active CRL/OCSP checking."
            }

        mit_data = []
        for i, mit_text in enumerate(sorted(list(mitigation_set)), 1):
            mit_data.append([
                Paragraph(f"<b>{i}.</b>", table_cell_style),
                Paragraph(mit_text, table_cell_style)
            ])

        t_mit = Table(mit_data, colWidths=[25, 495])
        t_mit.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t_mit)

        doc.build(story)
        buffer.seek(0)
        return buffer
