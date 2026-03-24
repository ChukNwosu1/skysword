import argparse

from scanner.s3_checks import check_s3_public_access
from scanner.ec2_checks import check_open_security_groups
from scanner.iam_checks import check_iam_policies
from core.scoring import calculate_score
from core.reporting import export_findings, print_results


def run_selected_checks(service):
    findings = []

    if service in ["s3", "all"]:
        findings.extend(check_s3_public_access())

    if service in ["ec2", "all"]:
        findings.extend(check_open_security_groups())

    if service in ["iam", "all"]:
        findings.extend(check_iam_policies())

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="SkySword - AWS cloud security scanner"
    )
    parser.add_argument(
        "--service",
        choices=["s3", "ec2", "iam", "all"],
        default="all",
        help="Choose which service to scan",
    )

    args = parser.parse_args()

    findings = run_selected_checks(args.service)
    score = calculate_score(findings)
    report_file = export_findings(findings, score)
    print_results(findings, score, report_file)


if __name__ == "__main__":
    main()