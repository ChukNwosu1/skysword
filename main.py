import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def check_s3_public_access():
    s3 = boto3.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except NoCredentialsError:
        print("AWS credentials not found.")
        return findings
    except ClientError as e:
        print(f"Failed to list buckets: {e}")
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")

                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(
                        {
                            "resource": bucket_name,
                            "issue": "S3 bucket may be publicly accessible through ACL",
                            "severity": "High",
                            "service": "S3",
                        }
                    )
                    break
        except ClientError as e:
            findings.append(
                {
                    "resource": bucket_name,
                    "issue": f"Could not evaluate bucket ACL: {e}",
                    "severity": "Medium",
                    "service": "S3",
                }
            )

    return findings


def check_open_security_groups():
    ec2 = boto3.client("ec2")
    findings = []

    try:
        response = ec2.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
    except NoCredentialsError:
        print("AWS credentials not found.")
        return findings
    except ClientError as e:
        print(f"Failed to describe security groups: {e}")
        return findings

    for sg in security_groups:
        sg_name = sg.get("GroupName", "Unknown")
        sg_id = sg.get("GroupId", "Unknown")

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            ip_ranges = permission.get("IpRanges", [])

            for ip_range in ip_ranges:
                cidr = ip_range.get("CidrIp")
                if cidr == "0.0.0.0/0":
                    severity = "High"

                    if from_port in [22, 3389]:
                        severity = "Critical"

                    findings.append(
                        {
                            "resource": f"{sg_name} ({sg_id})",
                            "issue": f"Security group allows inbound access from 0.0.0.0/0 on ports {from_port}-{to_port}",
                            "severity": severity,
                            "service": "EC2",
                        }
                    )

    return findings


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding["severity"]

        if severity == "Critical":
            score -= 30
        elif severity == "High":
            score -= 20
        elif severity == "Medium":
            score -= 10

    return max(score, 0)


def print_results(findings):
    if not findings:
        print("✅ No security issues found.")
        print("Security Score: 100/100")
        return

    print("SkySword Findings")
    print("-" * 60)

    for index, finding in enumerate(findings, start=1):
        print(f"{index}. Service  : {finding['service']}")
        print(f"   Resource : {finding['resource']}")
        print(f"   Issue    : {finding['issue']}")
        print(f"   Severity : {finding['severity']}")
        print()

    score = calculate_score(findings)
    print(f"Security Score: {score}/100")


def main():
    findings = []
    findings.extend(check_s3_public_access())
    findings.extend(check_open_security_groups())
    print_results(findings)


if __name__ == "__main__":
    main()