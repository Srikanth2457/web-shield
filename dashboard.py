from flask import Flask, render_template, request, send_file
from crawler.crawler import crawl
from scanner.scanner import scan_page
from scanner.active_checks import test_forms
from analyzer.analyzer import analyze
from ai_module.risk_analysis import enrich_findings
from reports.report_generator import generate_pdf_report

app = Flask(__name__)

# Temporary in-memory storage for the most recent scan (fine for a single-user demo)
last_scan = {"target": None, "report": None}


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')

    site_map = crawl(target_url)

    all_findings = []
    for page_url in site_map:
        all_findings.extend(scan_page(page_url))
    all_findings.extend(test_forms(site_map))

    report = analyze(all_findings)
    report["findings"] = enrich_findings(report["findings"])

    last_scan["target"] = target_url
    last_scan["report"] = report

    return render_template('results.html', target=target_url, report=report)


@app.route('/download-report')
def download_report():
    if not last_scan["report"]:
        return "No scan has been run yet.", 400

    filepath = generate_pdf_report(last_scan["target"], last_scan["report"])
    return send_file(filepath, as_attachment=True, download_name="WEB-SHIELD_Report.pdf")


if __name__ == '__main__':
    app.run(port=5000, debug=True)