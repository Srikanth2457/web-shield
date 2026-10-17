from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from datetime import datetime
import os

SEVERITY_COLORS = {
    "High": colors.HexColor("#ff3860"),
    "Medium": colors.HexColor("#ffb020"),
    "Low": colors.HexColor("#3b9eff"),
}

def generate_pdf_report(target, report, output_dir="reports/generated"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"webshield_report_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)

    c = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4
    y = height - 25 * mm

    # --- Header ---
    c.setFillColor(colors.HexColor("#0a0e17"))
    c.rect(0, height - 35 * mm, width, 35 * mm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(20 * mm, height - 20 * mm, "WEB-SHIELD")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, height - 28 * mm, "AI-Powered Web Application Security Scanner - Report")

    y = height - 45 * mm

    # --- Meta info ---
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y, f"Target: {target}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 12 * mm

    # --- Score summary ---
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20 * mm, y, f"Security Score: {report['score']} / 100")
    y -= 8 * mm
    c.setFont("Helvetica", 11)
    c.drawString(20 * mm, y, f"High: {report['counts']['High']}   Medium: {report['counts']['Medium']}   Low: {report['counts']['Low']}")
    y -= 12 * mm

    c.setStrokeColor(colors.HexColor("#dddddd"))
    c.line(20 * mm, y, width - 20 * mm, y)
    y -= 10 * mm

    # --- Findings ---
    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, "Findings")
    y -= 10 * mm

    for finding in report["findings"]:
        if y < 40 * mm:  # start a new page if running out of space
            c.showPage()
            y = height - 25 * mm

        sev_color = SEVERITY_COLORS.get(finding["severity"], colors.grey)
        c.setFillColor(sev_color)
        c.rect(20 * mm, y - 3 * mm, 3 * mm, 5 * mm, fill=1, stroke=0)

        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(26 * mm, y, f"[{finding['severity']}] {finding['check']}")
        y -= 6 * mm

        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#333333"))
        desc_lines = wrap_text(finding["description"], 95)
        for line in desc_lines:
            c.drawString(26 * mm, y, line)
            y -= 5 * mm

        if finding.get("evidence"):
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColor(colors.HexColor("#666666"))
            c.drawString(26 * mm, y, f"Evidence: {finding['evidence'][:90]}")
            y -= 5 * mm

        if finding.get("remediation"):
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#0a7a3d"))
            fix_lines = wrap_text(f"Fix: {finding['remediation']}", 95)
            for line in fix_lines:
                c.drawString(26 * mm, y, line)
                y -= 5 * mm

        y -= 6 * mm

    c.save()
    return filepath


def wrap_text(text, max_chars):
    """Simple word-wrap so long text doesn't run off the PDF page."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= max_chars:
            current += (" " if current else "") + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines