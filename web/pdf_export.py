import io
import logging
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.utils import ImageReader

# Defer importing matplotlib until runtime so the app can start even when
# matplotlib is not installed. This avoids crashing the whole app on import
# (useful in environments where PDF/export dependencies are optional).
plt = None

logger = logging.getLogger(__name__)


def generate_report_pdf(report: dict, scan_id: str | None = None) -> io.BytesIO:
    """Generate a simple multi-page PDF for the given scan report.

    - Renders three charts via matplotlib (doughnut/pie, bar, doughnut)
    - Embeds them into a PDF using reportlab
    - Appends a simple list of discovered services

    Returns an io.BytesIO containing the PDF bytes.
    """
    images = []

    # Import matplotlib here so missing optional dependency does not break app import
    global plt
    if plt is None:
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as _plt
            plt = _plt
        except Exception as e:
            logger.exception('matplotlib not available; PDF charts will be skipped: %s', e)
            plt = None

    # Chart 1: PQC Readiness (SAFE vs VULN) as doughnut
    if plt is not None:
        try:
            safe = int(report.get('overview', {}).get('quantum_safe', 0) or 0)
            vuln = int(report.get('overview', {}).get('quantum_vulnerable', 0) or 0)
            fig1 = plt.figure(figsize=(6, 3.6), constrained_layout=True)
            ax1 = fig1.add_subplot(111)
            vals = [safe, vuln]
            labels = ['SAFE', 'VULN']
            colors = ['#22c55e', '#ef4444']
            wedges, texts = ax1.pie(vals, labels=labels, colors=colors, startangle=90, wedgeprops=dict(width=0.4))
            ax1.set_title('PQC Readiness Distribution')
            buf1 = io.BytesIO()
            fig1.savefig(buf1, format='png', dpi=150)
            plt.close(fig1)
            buf1.seek(0)
            images.append(buf1)
        except Exception as e:
            logger.exception('Failed to render asset chart: %s', e)

    # Chart 2: Severity bar chart
    if plt is not None:
        try:
            severity = report.get('severity_breakdown') or {}
            labels = [str(k).upper() for k in severity.keys()]
            values = [float(v) for v in severity.values()] if severity else []
            fig2 = plt.figure(figsize=(6, 3.6), constrained_layout=True)
            ax2 = fig2.add_subplot(111)
            if labels and values:
                ax2.bar(labels, values, color='#2563eb')
            ax2.set_title('Finding Severity Analysis')
            ax2.set_ylabel('Count')
            buf2 = io.BytesIO()
            fig2.savefig(buf2, format='png', dpi=150)
            plt.close(fig2)
            buf2.seek(0)
            images.append(buf2)
        except Exception as e:
            logger.exception('Failed to render severity chart: %s', e)

    # Chart 3: Risk distribution
    if plt is not None:
        try:
            risk = report.get('risk_distribution') or {}
            labels = [str(k).upper() for k in risk.keys()]
            values = [float(v) for v in risk.values()] if risk else []
            fig3 = plt.figure(figsize=(6, 3.6), constrained_layout=True)
            ax3 = fig3.add_subplot(111)
            if values:
                colors = ['#ef4444', '#f59e0b', '#22c55e']
                # Trim/pad colors to match values
                colors = colors[:len(values)] if len(values) <= len(colors) else (colors * ((len(values)//len(colors))+1))[:len(values)]
                ax3.pie(values, labels=labels, colors=colors, startangle=90)
            ax3.set_title('HNDL Risk Map')
            buf3 = io.BytesIO()
            fig3.savefig(buf3, format='png', dpi=150)
            plt.close(fig3)
            buf3.seek(0)
            images.append(buf3)
        except Exception as e:
            logger.exception('Failed to render risk chart: %s', e)

    # Build PDF
    pdf_buf = io.BytesIO()
    c = rl_canvas.Canvas(pdf_buf, pagesize=A4)
    width, height = A4

    # Header
    title = f"SCAN_RESULTS: {report.get('target', '')}"
    c.setFont('Helvetica-Bold', 14)
    c.drawString(40, height - 50, title)
    c.setFont('Helvetica', 9)
    c.drawString(40, height - 68, f"Scan ID: {scan_id or '-'}")
    c.drawString(40, height - 84, f"Generated: {report.get('generated_at', '-')}")

    y = height - 110

    for img_buf in images:
        try:
            img = ImageReader(img_buf)
            iw, ih = img.getSize()
            aspect = ih / float(iw)
            draw_w = width - 80
            draw_h = draw_w * aspect
            if y - draw_h < 60:  # not enough space, new page
                c.showPage()
                y = height - 60
            c.drawImage(img, 40, y - draw_h, width=draw_w, height=draw_h)
            y = y - draw_h - 18
        except Exception as e:
            logger.exception('Failed to embed chart image into PDF: %s', e)

    # Discovered services (simple text list)
    services = report.get('discovered_services') or []
    if services:
        if y < 120:
            c.showPage()
            y = height - 60
        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Discovered Services')
        y -= 18
        c.setFont('Helvetica', 9)
        for svc in services:
            line = f"{svc.get('host', '')}:{svc.get('port', '')} {svc.get('service', '')}"
            if y < 60:
                c.showPage(); y = height - 60
            c.drawString(40, y, line)
            y -= 12

    c.save()
    pdf_buf.seek(0)
    return pdf_buf
