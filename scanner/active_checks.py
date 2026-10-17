import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOAD = "<script>alert('WSXSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1' --"


def test_xss(form, base_url):
    findings = []
    data = {inp["name"]: XSS_PAYLOAD for inp in form["inputs"] if inp["name"]}

    try:
        if form["method"] == "post":
            response = requests.post(form["action"], data=data, timeout=5)
        else:
            response = requests.get(form["action"], params=data, timeout=5)
    except requests.RequestException as e:
        return [{"check": "XSS Test", "severity": "Info",
                  "description": f"Could not test form: {e}", "evidence": ""}]

    if XSS_PAYLOAD in response.text:
        findings.append({
            "check": "Reflected XSS",
            "severity": "High",
            "description": "Input is reflected in the page without escaping, allowing script execution.",
            "evidence": f"Payload found unescaped at {form['action']}"
        })
    return findings


def test_sqli(form, base_url):
    findings = []
    data = {}
    for inp in form["inputs"]:
        if not inp["name"]:
            continue
        if inp["type"] == "password":
            data[inp["name"]] = "anything"
        else:
            data[inp["name"]] = SQLI_PAYLOAD

    try:
        if form["method"] == "post":
            response = requests.post(form["action"], data=data, timeout=5)
        else:
            response = requests.get(form["action"], params=data, timeout=5)
    except requests.RequestException as e:
        return [{"check": "SQLi Test", "severity": "Info",
                  "description": f"Could not test form: {e}", "evidence": ""}]

    text_lower = response.text.lower()
    if "successful" in text_lower or "welcome" in text_lower:
        findings.append({
            "check": "SQL Injection (Auth Bypass)",
            "severity": "High",
            "description": "Login succeeded using an SQL injection payload instead of a real password.",
            "evidence": f"Payload '{SQLI_PAYLOAD}' bypassed authentication at {form['action']}"
        })
    elif "sql" in text_lower or "database error" in text_lower or "sqlite3" in text_lower:
        findings.append({
            "check": "SQL Injection (Error-Based)",
            "severity": "High",
            "description": "Database error message was exposed, revealing SQL injection vulnerability.",
            "evidence": f"Error text found in response at {form['action']}"
        })
    return findings


def test_xss_on_url(url):
    """
    Check if a URL with a query parameter (like ?q=test) reflects
    an XSS payload back unescaped.
    """
    findings = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return findings

    injected_params = {key: XSS_PAYLOAD for key in query_params}
    new_query = urlencode(injected_params)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        response = requests.get(test_url, timeout=5)
    except requests.RequestException as e:
        return [{"check": "XSS Test", "severity": "Info",
                  "description": f"Could not test URL: {e}", "evidence": ""}]

    if XSS_PAYLOAD in response.text:
        findings.append({
            "check": "Reflected XSS",
            "severity": "High",
            "description": "URL parameter is reflected in the page without escaping, allowing script execution.",
            "evidence": f"Payload found unescaped at {test_url}"
        })
    return findings


def test_forms(site_map):
    """Run XSS and SQLi tests on every form AND every URL with parameters found by the crawler."""
    all_findings = []
    for page_url, data in site_map.items():
        for form in data["forms"]:
            all_findings.extend(test_xss(form, page_url))
            all_findings.extend(test_sqli(form, page_url))
        all_findings.extend(test_xss_on_url(page_url))
    return all_findings


if __name__ == "__main__":
    fake_login_form = {
        "action": "http://127.0.0.1:5001/login",
        "method": "post",
        "inputs": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"}
        ]
    }
    results = test_sqli(fake_login_form, "http://127.0.0.1:5001")
    for r in results:
        print(f"[{r['severity']}] {r['check']}\n   {r['description']}\n   Evidence: {r['evidence']}\n")