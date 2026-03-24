from scanner.s3_checks import check_s3_public_access
from scanner.ec2_checks import check_open_security_groups
from core.scoring import calculate_score
from core.reporting import export_findings, print_results


def main():
    findings = []
    findings.extend(check_s3_public_access())
    findings.extend(check_open_security_groups())

    score = calculate_score(findings)
    report_file = export_findings(findings, score)
    print_results(findings, score, report_file)


if __name__ == "__main__":
    main()