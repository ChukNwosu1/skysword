import boto3
from botocore.exceptions import ClientError, NoCredentialsError


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
                            "service": "EC2",
                            "resource": f"{sg_name} ({sg_id})",
                            "issue": f"Security group allows inbound access from 0.0.0.0/0 on ports {from_port}-{to_port}",
                            "severity": severity,
                        }
                    )

    return findings