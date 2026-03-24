# SkySword

SkySword is a Python-based cloud security tool designed to identify AWS misconfigurations, classify findings by severity, and generate a simple security score.

## Current Features
- Scans AWS S3 buckets
- Detects potential public bucket exposure through ACLs
- Classifies findings as High or Medium
- Generates a security score out of 100
- Scans AWS EC2 security groups
- Detects public inbound exposure to 0.0.0.0/0
- Flags SSH (22) and RDP (3389) exposure as Critical
- Exports scan findings to a timestamped JSON report
- Scans IAM policies for overly permissive access
- Detects wildcard (*) permissions and admin-level policies

## Planned Features
- IAM misconfiguration checks
- EC2 security group exposure checks
- Critical / High / Medium risk mapping
- Exportable findings report
- Dashboard integration

## Tech Stack
- Python
- Boto3
- AWS

## Usage
Generated reports are saved in the `output/` directory.

```bash
pip install -r requirements.txt
python main.py