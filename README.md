# WEB-SHIELD: AI-Powered Web Application Security Scanner

A Python/Flask security scanner that crawls a web application, tests it for common
vulnerabilities, and returns a scored report with plain-language fixes.

## Features
- Automated crawler (pages, links, forms)
- HTTPS, security header and cookie checks
- Active testing for reflected XSS and SQL injection (forms and URL parameters)
- Weighted 0-100 security score and A-F grade, with duplicate findings removed
- Risk explanations and remediation advice for each finding
- Interactive dashboard and downloadable PDF report

## Tech Stack
Python 3.12, Flask, Requests, BeautifulSoup4, ReportLab, HTML/CSS/JS, Three.js

## How to Run
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
Terminal 1 (test target):
```bash
python vulnerable_test_app/vuln_app.py
```
Terminal 2 (scanner dashboard):
```bash
python dashboard.py
```
Open http://127.0.0.1:5000 and scan `http://127.0.0.1:5001`.

## Demo Results
| Stage | Score | Grade |
|---|---|---|
| Original vulnerable app | 20/100 | F |
| After headers and cookie fixes | 48/100 | D |
| After SQL injection fix | 63/100 | C |

## Ethics and Scope
WEB-SHIELD must only be used on applications you own or have written permission to test.
All testing in this project was done against the local app in `vulnerable_test_app/`,
which is intentionally insecure. Never deploy it to a public server.
The scanner covers selected OWASP Top 10 checks and does not claim full coverage.

## Author
srikanth
