# NIMBUS

> Cloud Security Scanner — Multi-Cloud CSPM · CIS Benchmarks · Executive Dashboards

A modular CLI tool that scans AWS, Azure, and GCP for security misconfigurations, implements CIS benchmark compliance checking, and generates executive-grade HTML dashboards.

> **Educational tool** — Demonstrates cloud security assessment techniques used by enterprise CSPM platforms like Prisma Cloud and Dome9.

> **Legal disclaimer:** Only run this tool against cloud accounts you own or have explicit written permission to audit.

---

## Requirements

### Python dependencies
```bash
pip install -r requirements.txt
```

> **Note:** Cloud provider SDKs (boto3, azure-*, google-cloud-*) are only needed for live scanning. Demo mode works with just `colorama` and `pyyaml`.

---

## Quick Start

### Demo mode (no cloud credentials needed)
```bash
# Scan all providers in demo mode
python main.py --providers all --demo

# Demo mode with only AWS
python main.py --providers aws --demo

# Demo mode with severity filter
python main.py --providers all --demo --severity high
```

### Live scanning
```bash
# Scan AWS using default credentials
python main.py --providers aws

# Scan AWS with a named profile and multiple regions
python main.py --providers aws --aws-profile prod --aws-regions us-east-1,us-west-2

# Scan Azure
python main.py --providers azure --azure-subscription <subscription-id>

# Scan GCP
python main.py --providers gcp --gcp-project <project-id>

# Scan all providers
python main.py --providers all --aws-profile prod --azure-subscription <sub-id> --gcp-project <project-id>
```

### All options

| Flag | Default | Description |
|------|---------|-------------|
| `--providers` | *(required)* | Comma-separated: `aws`, `azure`, `gcp`, or `all` |
| `--demo` | off | Run in simulation mode with realistic sample data |
| `--aws-profile` | default | AWS CLI profile name |
| `--aws-regions` | `us-east-1` | Comma-separated AWS regions to scan |
| `--azure-subscription` | — | Azure subscription ID |
| `--gcp-project` | — | GCP project ID |
| `--severity` | all | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--output` | `cloud_security_report` | Output file base name |
| `--format` | `all` | `html`, `json`, or `all` |
| `--rules-dir` | `./rules` | Custom YAML rules directory |
| `--verbose` | off | Verbose output |

---

## Security Checks (18 total)

### AWS (8 checks)
| Check | CIS Benchmark | Severity |
|-------|---------------|----------|
| S3 bucket public access (ACLs + policies) | 2.1.1 | Critical |
| S3 bucket default encryption | 2.1.2 | High |
| IAM users without MFA | 1.10 | Critical |
| Overly permissive IAM policies (Action:*, Resource:*) | 1.16 | Critical |
| Unencrypted EBS volumes | 2.2.1 | High |
| Security groups with 0.0.0.0/0 on sensitive ports | 5.2 | High |
| Unencrypted RDS instances | 2.3.1 | High |
| CloudTrail logging disabled | 3.1 | Critical |

### Azure (5 checks)
| Check | CIS Benchmark | Severity |
|-------|---------------|----------|
| Storage account public blob access | 3.7 | Critical |
| Storage account encryption | 3.2 | High |
| NSG unrestricted inbound on sensitive ports | 6.1 | High |
| Key Vault overly broad access policies | 8.5 | High |
| SQL database without TDE | 4.1.2 | High |

### GCP (5 checks)
| Check | CIS Benchmark | Severity |
|-------|---------------|----------|
| Cloud Storage bucket public access | 5.1 | Critical |
| Cloud Storage bucket encryption (CMEK) | 5.3 | Medium |
| Firewall rules with 0.0.0.0/0 source | 3.6 | High |
| IAM primitive roles on projects | 1.6 | High |
| Cloud SQL without SSL enforcement | 6.4 | High |

---

## Output

### HTML Dashboard
The HTML report includes:
- **Overall compliance score** with doughnut chart
- **Summary cards** showing finding counts by severity
- **Per-provider breakdown** with compliance percentages per resource type
- **Severity distribution** bar chart
- **CIS benchmark compliance matrix** mapping each control to PASS/FAIL
- **Detailed findings table** with remediation guidance

### JSON Report
Machine-readable output containing all findings, compliance scores, and metadata.

---

## Adding Custom Rules

Rules are defined in YAML files in the `rules/` directory:

```yaml
rules:
  - id: "AWS-S3-003"
    title: "S3 Bucket Versioning"
    description: "S3 buckets should have versioning enabled"
    severity: "medium"
    provider: "aws"
    resource_type: "S3 Bucket"
    check_method: "check_s3_versioning"
    cis_benchmark: "CIS AWS Foundations 1.4.0 - 2.1.3"
    remediation: "Enable versioning on the S3 bucket."
    enabled: true
    tags: ["storage", "versioning", "s3"]
```

Then add the corresponding `check_s3_versioning()` method to `scanner/aws_scanner.py`.

---

## Architecture

```
cloud_security_scanner/
├── main.py                  # CLI entry point
├── scanner/
│   ├── base_scanner.py      # Finding dataclass + BaseScanner ABC
│   ├── aws_scanner.py       # AWS checks (boto3)
│   ├── azure_scanner.py     # Azure checks (azure-mgmt-*)
│   └── gcp_scanner.py       # GCP checks (google-cloud-*)
├── rules_engine/
│   ├── rule_loader.py       # YAML rule parser
│   └── evaluator.py         # Compliance scoring
├── rules/                   # CIS benchmark rule definitions
├── demo/
│   └── demo_provider.py     # Simulated findings for learning
└── reporter/
    └── report_generator.py  # HTML dashboard + JSON output
```

---

## Credential Setup

### AWS
```bash
aws configure                # or
export AWS_PROFILE=my-profile
```

### Azure
```bash
az login
az account set --subscription <subscription-id>
```

### GCP
```bash
gcloud auth application-default login
gcloud config set project <project-id>
```
