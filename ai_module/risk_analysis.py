RISK_KNOWLEDGE_BASE = {
    "HTTPS": {
        "risk_explanation": "Without HTTPS, anyone on the same network as your users—like public WiFi—can potentially read everything sent between their browser and your site, including passwords and personal data.",
        "remediation": "Install an SSL/TLS certificate (e.g. via Let's Encrypt, which is free) and configure your server to redirect all HTTP traffic to HTTPS."
    },
    "Missing Header: Content-Security-Policy": {
        "risk_explanation": "Without a Content-Security-Policy, if an attacker manages to inject malicious code into your page, the browser has no rules stopping it from running.",
        "remediation": "Add a Content-Security-Policy header restricting scripts to trusted sources only, e.g. Content-Security-Policy: default-src 'self'"
    },
    "Missing Header: X-Frame-Options": {
        "risk_explanation": "Without this header, another website could load your page inside an invisible frame and trick users into clicking things they didn't mean to (called clickjacking).",
        "remediation": "Add the header X-Frame-Options: DENY or SAMEORIGIN to prevent your site from being embedded in another page's frame."
    },
    "Missing Header: X-Content-Type-Options": {
        "risk_explanation": "Without this header, browsers may misinterpret uploaded files, potentially allowing a disguised file to run as executable code.",
        "remediation": "Add the header X-Content-Type-Options: nosniff to stop browsers from guessing file types."
    },
    "Missing Header: Strict-Transport-Security": {
        "risk_explanation": "Without HSTS, an attacker on the same network could trick a user's browser into connecting over unencrypted HTTP instead of HTTPS, exposing their data.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS is properly configured."
    },
    "Weak Cookie Configuration": {
        "risk_explanation": "This cookie can be read by malicious scripts, sent over unencrypted connections, or sent from other websites—any of which could let an attacker hijack a user's session.",
        "remediation": "Set the cookie with Secure, HttpOnly, and SameSite=Strict (or Lax) attributes."
    },
    "Reflected XSS": {
        "risk_explanation": "An attacker can craft a malicious link that, when clicked by a victim, runs their own code in the victim's browser—potentially stealing session cookies, login credentials, or personal data.",
        "remediation": "Escape all user input before displaying it in HTML (e.g. use Flask's built-in Jinja2 auto-escaping, or a library like markupsafe), and validate input on the server side."
    },
    "SQL Injection (Auth Bypass)": {
        "risk_explanation": "An attacker can bypass your login entirely without knowing any real password, gaining full access to user accounts or the underlying database.",
        "remediation": "Always use parameterized queries (e.g. cursor.execute('...WHERE username=?', (username,))) instead of building SQL strings with string formatting or concatenation."
    },
    "SQL Injection (Error-Based)": {
        "risk_explanation": "Exposed database error messages can reveal your database structure, helping an attacker craft more damaging attacks.",
        "remediation": "Use parameterized queries, and configure your app to show generic error messages to users instead of raw database errors."
    },
}

DEFAULT_ADVICE = {
    "risk_explanation": "This finding may expose the application to security risks that should be reviewed by the development team.",
    "remediation": "Review this finding against OWASP guidelines for the relevant vulnerability category."
}


def enrich_findings(findings):
    """
    Add a plain-language risk explanation and remediation suggestion
    to each finding, based on its check type.
    """
    for finding in findings:
        check_name = finding.get("check", "")
        advice = RISK_KNOWLEDGE_BASE.get(check_name, DEFAULT_ADVICE)
        finding["risk_explanation"] = advice["risk_explanation"]
        finding["remediation"] = advice["remediation"]
    return findings