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
                            "service": "S3",
                            "resource": bucket_name,
                            "issue": "S3 bucket may be publicly accessible through ACL",
                            "severity": "High",
                        }
                    )
                    break
        except ClientError as e:
            findings.append(
                {
                    "service": "S3",
                    "resource": bucket_name,
                    "issue": f"Could not evaluate bucket ACL: {e}",
                    "severity": "Medium",
                }
            )

    return findings