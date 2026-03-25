from colorama import Fore, Style, init
import json
from datetime import datetime

init(autoreset=True)


def colorize_severity(severity):
    if severity == "Critical":
        return Fore.RED + severity + Style.RESET_ALL
    if severity == "High":
        return Fore.YELLOW + severity + Style.RESET_ALL
    if severity == "Medium":
        return Fore.BLUE + severity + Style.RESET_ALL
    return severity


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
        print(Fore.GREEN + "✅ No security issues found." + Style.RESET_ALL)
        print(Fore.GREEN + "Security Score: 100/100" + Style.RESET_ALL)
        print(f"Report saved to: {report_file}")
        return

    print(Fore.CYAN + "SkySword Findings" + Style.RESET_ALL)
    print("-" * 60)

    for index, finding in enumerate(findings, start=1):
        print(f"{index}. Service  : {finding['service']}")
        print(f"   Resource : {finding['resource']}")
        print(f"   Issue    : {finding['issue']}")
        print(f"   Severity : {colorize_severity(finding['severity'])}")
        print()

    score_color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 50 else Fore.RED
    print(score_color + f"Security Score: {score}/100" + Style.RESET_ALL)
    print(f"Report saved to: {report_file}")