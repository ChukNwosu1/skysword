import json
from datetime import datetime


def export_findings(findings, score):
    report = {
        "tool": "SkySword",
        "scan_time_utc": datetime.utcnow().isoformat() + "Z",
        "security_score": score,
        "total_findings": len(findings),
        "findings": findings,
    }

    filename = f"output/skysword_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return filename


def print_results(findings, score, report_file):
    if not findings:
        print("✅ No security issues found.")
        print("Security Score: 100/100")
        print(f"Report saved to: {report_file}")
        return

    print("SkySword Findings")
    print("-" * 60)

    for index, finding in enumerate(findings, start=1):
        print(f"{index}. Service  : {finding['service']}")
        print(f"   Resource : {finding['resource']}")
        print(f"   Issue    : {finding['issue']}")
        print(f"   Severity : {finding['severity']}")
        print()

    print(f"Security Score: {score}/100")
    print(f"Report saved to: {report_file}")