from crawler.crawler import crawl
from scanner.scanner import scan_page
from scanner.active_checks import test_forms
from analyzer.analyzer import analyze, print_report


def run_full_scan(target_url):
    print("Starting scan on " + target_url + "...\n")

    site_map = crawl(target_url)

    all_findings = []

    for page_url in site_map:
        all_findings.extend(scan_page(page_url))

    all_findings.extend(test_forms(site_map))

    report = analyze(all_findings)
    print_report(target_url, report)

    return report


if __name__ == "__main__":
    run_full_scan("http://127.0.0.1:5001")