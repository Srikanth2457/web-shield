SEVERITY_WEIGHTS = {
    "High": 15,
    "Medium": 7,
    "Low": 3,
    "Info": 0,
    "Pass": 0
}

def calculate_score(findings):
    score = 100
    for finding in findings:
        severity = finding.get("severity", "Info")
        score -= SEVERITY_WEIGHTS.get(severity, 0)
    return max(score, 0)


def count_by_severity(findings):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts


def deduplicate_findings(findings):
    seen = set()
    unique_findings = []
    for finding in findings:
        key = (finding.get("check"), finding.get("evidence"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return unique_findings


def analyze(all_findings):
    all_findings = deduplicate_findings(all_findings)
    score = calculate_score(all_findings)
    counts = count_by_severity(all_findings)

    report = {
        "score": score,
        "counts": counts,
        "findings": all_findings
    }
    return report


def print_report(target, report):
    print("\nWEB-SHIELD SCAN COMPLETE")
    print("Target: " + target)
    print("Security Score: " + str(report["score"]) + "/100")
    print("HIGH: " + str(report["counts"]["High"]) + "  MEDIUM: " + str(report["counts"]["Medium"]) + "  LOW: " + str(report["counts"]["Low"]))
    print()
    for finding in report["findings"]:
        print("[" + finding["severity"] + "] " + finding["check"])
        print("   " + finding["description"])
        if finding.get("evidence"):
            print("   Evidence: " + str(finding["evidence"]))
        print()