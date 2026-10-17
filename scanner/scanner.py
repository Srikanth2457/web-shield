import requests
from urllib.parse import urlparse

REQUIRED_HEADERS = {
    "Content-Security-Policy": "Missing CSP allows unrestricted script execution, weakening XSS defenses.",
    "X-Frame-Options": "Missing X-Frame-Options allows clickjacking via iframe embedding.",
    "X-Content-Type-Options": "Missing nosniff header allows MIME-type sniffing attacks.",
    "Strict-Transport-Security": "Missing HSTS allows downgrade to unencrypted HTTP."
}

def check_https(url):
    """Check if the site uses HTTPS."""
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append({
            "check": "HTTPS",
            "severity": "High",
            "description": "Site is not served over HTTPS. Traffic can be intercepted in plain text.",
            "evidence": f"URL scheme is '{parsed.scheme}'"
        })
    else:
        findings.append({
            "check": "HTTPS",
            "severity": "Pass",
            "description": "Site is served over HTTPS.",
            "evidence": ""
        })
    return findings

def check_security_headers(response):
    """Check for the presence of key security headers."""
    findings = []
    for header, explanation in REQUIRED_HEADERS.items():
        if header not in response.headers:
            findings.append({
                "check": f"Missing Header: {header}",
                "severity": "Medium",
                "description": explanation,
                "evidence": f"'{header}' not found in response headers"
            })
    return findings

def check_cookie_security(response):
    """Check Set-Cookie headers for Secure, HttpOnly, SameSite flags."""
    findings = []
    cookies = response.raw.headers.get_all('Set-Cookie') if hasattr(response.raw.headers, "get_all") else response.headers.get("Set-Cookie")

    # requests exposes cookies differently depending on version; this covers both cases
    set_cookie_headers = []
    if cookies:
        if isinstance(cookies, list):
            set_cookie_headers = cookies
        else:
            set_cookie_headers = [cookies]

    for cookie_str in set_cookie_headers:
        missing_flags = []
        if "Secure" not in cookie_str:
            missing_flags.append("Secure")
        if "HttpOnly" not in cookie_str:
            missing_flags.append("HttpOnly")
        if "SameSite" not in cookie_str:
            missing_flags.append("SameSite")

        if missing_flags:
            findings.append({
                "check": "Weak Cookie Configuration",
                "severity": "Medium",
                "description": f"Cookie is missing flags: {', '.join(missing_flags)}. This increases risk of theft via XSS or interception.",
                "evidence": cookie_str.split(";")[0]  # just show cookie name=value, not full string
            })
    return findings

def scan_page(url):
    """Run all passive checks (no payload injection) on a single page."""
    all_findings = []
    all_findings.extend(check_https(url))

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        all_findings.append({
            "check": "Connectivity",
            "severity": "High",
            "description": f"Could not connect to {url}: {e}",
            "evidence": ""
        })
        return all_findings

    all_findings.extend(check_security_headers(response))
    all_findings.extend(check_cookie_security(response))
    return all_findings


if __name__ == "__main__":
    target = "http://127.0.0.1:5001"
    results = scan_page(target)
    print(f"\n--- SCAN RESULTS for {target} ---\n")
    for finding in results:
        print(f"[{finding['severity']}] {finding['check']}")
        print(f"   {finding['description']}")
        if finding['evidence']:
            print(f"   Evidence: {finding['evidence']}")
        print()