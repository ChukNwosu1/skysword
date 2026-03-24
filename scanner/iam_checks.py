import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def check_iam_policies():
    iam = boto3.client("iam")
    findings = []

    try:
        policies = iam.list_policies(Scope="Local")["Policies"]
    except NoCredentialsError:
        print("AWS credentials not found.")
        return findings
    except ClientError as e:
        print(f"Failed to list IAM policies: {e}")
        return findings

    for policy in policies:
        policy_name = policy["PolicyName"]
        policy_arn = policy["Arn"]

        try:
            version = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            document = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )["PolicyVersion"]["Document"]
        except ClientError:
            continue

        statements = document.get("Statement", [])

        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            # Normalize to list
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard permissions
            if "*" in actions or "*" in resources:
                findings.append({
                    "service": "IAM",
                    "resource": policy_name,
                    "issue": "Policy allows wildcard '*' in Action or Resource",
                    "severity": "Critical"
                })

            # Check for admin policy
            if "AdministratorAccess" in policy_name:
                findings.append({
                    "service": "IAM",
                    "resource": policy_name,
                    "issue": "AdministratorAccess policy detected",
                    "severity": "Critical"
                })

    return findings