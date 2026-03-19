"""
Demo Provider
--------------
Generates realistic simulated cloud findings for demo/learning mode.
Produces a curated mix of PASS and FAIL results across all providers.
"""

from scanner.base_scanner import Finding


def generate_demo_findings(providers: list[str]) -> list[Finding]:
    """Generate demo findings for the specified providers."""
    findings: list[Finding] = []

    if "aws" in providers:
        findings.extend(_aws_demo_findings())
    if "azure" in providers:
        findings.extend(_azure_demo_findings())
    if "gcp" in providers:
        findings.extend(_gcp_demo_findings())

    return findings


def _aws_demo_findings() -> list[Finding]:
    return [
        # S3 Public Access — mixed results
        Finding(
            rule_id="AWS-S3-001", provider="aws", resource_type="S3 Bucket",
            resource_id="arn:aws:s3:::company-public-assets",
            region="us-east-1", severity="critical", status="FAIL",
            title="S3 Bucket Public Access",
            description="Bucket 'company-public-assets' has public ACL granting READ to AllUsers",
            remediation="Enable S3 Block Public Access at the account and bucket level.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
        ),
        Finding(
            rule_id="AWS-S3-001", provider="aws", resource_type="S3 Bucket",
            resource_id="arn:aws:s3:::company-logs-2024",
            region="us-east-1", severity="critical", status="PASS",
            title="S3 Bucket Public Access",
            description="Bucket 'company-logs-2024' has Block Public Access enabled",
            remediation="Enable S3 Block Public Access at the account and bucket level.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
        ),
        Finding(
            rule_id="AWS-S3-001", provider="aws", resource_type="S3 Bucket",
            resource_id="arn:aws:s3:::dev-temp-uploads",
            region="us-west-2", severity="critical", status="FAIL",
            title="S3 Bucket Public Access",
            description="Bucket 'dev-temp-uploads' has a bucket policy granting s3:GetObject to Principal '*'",
            remediation="Enable S3 Block Public Access at the account and bucket level.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
        ),

        # S3 Encryption
        Finding(
            rule_id="AWS-S3-002", provider="aws", resource_type="S3 Bucket",
            resource_id="arn:aws:s3:::company-public-assets",
            region="us-east-1", severity="high", status="FAIL",
            title="S3 Bucket Encryption",
            description="Bucket 'company-public-assets' does not have default encryption enabled",
            remediation="Enable default encryption on the S3 bucket using SSE-S3 or SSE-KMS.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.2",
        ),
        Finding(
            rule_id="AWS-S3-002", provider="aws", resource_type="S3 Bucket",
            resource_id="arn:aws:s3:::company-logs-2024",
            region="us-east-1", severity="high", status="PASS",
            title="S3 Bucket Encryption",
            description="Bucket 'company-logs-2024' has SSE-S3 (AES-256) encryption enabled",
            remediation="Enable default encryption on the S3 bucket using SSE-S3 or SSE-KMS.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.2",
        ),

        # IAM No MFA
        Finding(
            rule_id="AWS-IAM-001", provider="aws", resource_type="IAM User",
            resource_id="arn:aws:iam::123456789012:user/dev-intern",
            region="global", severity="critical", status="FAIL",
            title="IAM Users Without MFA",
            description="IAM user 'dev-intern' has console access but no MFA device configured",
            remediation="Enable MFA for all IAM users with console access.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 1.10",
        ),
        Finding(
            rule_id="AWS-IAM-001", provider="aws", resource_type="IAM User",
            resource_id="arn:aws:iam::123456789012:user/admin",
            region="global", severity="critical", status="PASS",
            title="IAM Users Without MFA",
            description="IAM user 'admin' has virtual MFA device configured",
            remediation="Enable MFA for all IAM users with console access.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 1.10",
        ),

        # IAM Overly Permissive
        Finding(
            rule_id="AWS-IAM-002", provider="aws", resource_type="IAM Policy",
            resource_id="arn:aws:iam::123456789012:policy/LegacyFullAccess",
            region="global", severity="critical", status="FAIL",
            title="Overly Permissive IAM Policies",
            description="Policy 'LegacyFullAccess' grants Action: '*' on Resource: '*'",
            remediation="Apply the principle of least privilege. Replace wildcard policies.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 1.16",
        ),

        # EBS Encryption
        Finding(
            rule_id="AWS-EC2-001", provider="aws", resource_type="EBS Volume",
            resource_id="vol-0abc123def456789a",
            region="us-east-1", severity="high", status="FAIL",
            title="Unencrypted EBS Volumes",
            description="EBS volume 'vol-0abc123def456789a' (200 GiB, gp3) is not encrypted",
            remediation="Enable EBS encryption by default or create encrypted copies.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.2.1",
        ),
        Finding(
            rule_id="AWS-EC2-001", provider="aws", resource_type="EBS Volume",
            resource_id="vol-0def789abc123456b",
            region="us-east-1", severity="high", status="PASS",
            title="Unencrypted EBS Volumes",
            description="EBS volume 'vol-0def789abc123456b' is encrypted with aws/ebs key",
            remediation="Enable EBS encryption by default or create encrypted copies.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.2.1",
        ),

        # Security Groups
        Finding(
            rule_id="AWS-EC2-002", provider="aws", resource_type="Security Group",
            resource_id="sg-0abc123def456789a",
            region="us-east-1", severity="high", status="FAIL",
            title="Unrestricted Security Group Ingress",
            description="Security group 'sg-0abc123def456789a' (web-sg) allows SSH (port 22) from 0.0.0.0/0",
            remediation="Restrict security group ingress to specific IP ranges.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 5.2",
        ),
        Finding(
            rule_id="AWS-EC2-002", provider="aws", resource_type="Security Group",
            resource_id="sg-0fed987cba654321b",
            region="us-east-1", severity="high", status="PASS",
            title="Unrestricted Security Group Ingress",
            description="Security group 'sg-0fed987cba654321b' (internal-sg) has no unrestricted ingress rules",
            remediation="Restrict security group ingress to specific IP ranges.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 5.2",
        ),

        # RDS Encryption
        Finding(
            rule_id="AWS-RDS-001", provider="aws", resource_type="RDS Instance",
            resource_id="arn:aws:rds:us-east-1:123456789012:db:prod-mysql",
            region="us-east-1", severity="high", status="FAIL",
            title="Unencrypted RDS Instances",
            description="RDS instance 'prod-mysql' (MySQL 8.0) does not have storage encryption enabled",
            remediation="Enable encryption when creating RDS instances.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.3.1",
        ),

        # CloudTrail
        Finding(
            rule_id="AWS-LOG-001", provider="aws", resource_type="CloudTrail",
            resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            region="us-east-1", severity="critical", status="PASS",
            title="CloudTrail Logging Disabled",
            description="CloudTrail trail 'management-trail' is active and logging in all regions",
            remediation="Enable CloudTrail with a multi-region trail.",
            cis_benchmark="CIS AWS Foundations 1.4.0 - 3.1",
        ),
    ]


def _azure_demo_findings() -> list[Finding]:
    return [
        # Storage Public Access
        Finding(
            rule_id="AZURE-STORAGE-001", provider="azure", resource_type="Storage Account",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddata01",
            region="eastus", severity="critical", status="FAIL",
            title="Storage Account Public Blob Access",
            description="Storage account 'proddata01' allows public blob access",
            remediation="Disable public blob access on the storage account.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 3.7",
        ),
        Finding(
            rule_id="AZURE-STORAGE-001", provider="azure", resource_type="Storage Account",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/securelogs",
            region="eastus", severity="critical", status="PASS",
            title="Storage Account Public Blob Access",
            description="Storage account 'securelogs' has public blob access disabled",
            remediation="Disable public blob access on the storage account.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 3.7",
        ),

        # Storage Encryption
        Finding(
            rule_id="AZURE-STORAGE-002", provider="azure", resource_type="Storage Account",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddata01",
            region="eastus", severity="high", status="PASS",
            title="Storage Account Encryption",
            description="Storage account 'proddata01' has encryption enabled for all services",
            remediation="Enable encryption for all storage services.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 3.2",
        ),

        # NSG Unrestricted
        Finding(
            rule_id="AZURE-NET-001", provider="azure", resource_type="Network Security Group",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
            region="eastus", severity="high", status="FAIL",
            title="NSG Unrestricted Inbound Access",
            description="NSG 'nsg-web' has rule allowing RDP (3389) from source '*'",
            remediation="Restrict NSG inbound rules to specific IP ranges.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 6.1",
        ),
        Finding(
            rule_id="AZURE-NET-001", provider="azure", resource_type="Network Security Group",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-internal",
            region="eastus", severity="high", status="PASS",
            title="NSG Unrestricted Inbound Access",
            description="NSG 'nsg-internal' has no unrestricted inbound rules",
            remediation="Restrict NSG inbound rules to specific IP ranges.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 6.1",
        ),

        # Key Vault
        Finding(
            rule_id="AZURE-KV-001", provider="azure", resource_type="Key Vault",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod-secrets",
            region="eastus", severity="high", status="FAIL",
            title="Key Vault Overly Broad Access",
            description="Key Vault 'kv-prod-secrets' has access policy granting all key, secret, and certificate permissions",
            remediation="Review Key Vault access policies and remove unnecessary permissions.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 8.5",
        ),

        # SQL TDE
        Finding(
            rule_id="AZURE-SQL-001", provider="azure", resource_type="SQL Database",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod/databases/appdb",
            region="eastus", severity="high", status="PASS",
            title="SQL Database Without TDE",
            description="SQL database 'appdb' has Transparent Data Encryption enabled",
            remediation="Enable TDE on all Azure SQL databases.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 4.1.2",
        ),
        Finding(
            rule_id="AZURE-SQL-001", provider="azure", resource_type="SQL Database",
            resource_id="/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-dev/databases/testdb",
            region="westus", severity="high", status="FAIL",
            title="SQL Database Without TDE",
            description="SQL database 'testdb' does not have Transparent Data Encryption enabled",
            remediation="Enable TDE on all Azure SQL databases.",
            cis_benchmark="CIS Azure Foundations 2.0.0 - 4.1.2",
        ),
    ]


def _gcp_demo_findings() -> list[Finding]:
    return [
        # Storage Public Access
        Finding(
            rule_id="GCP-STORAGE-001", provider="gcp", resource_type="Cloud Storage Bucket",
            resource_id="projects/my-project/buckets/public-website-assets",
            region="us-central1", severity="critical", status="FAIL",
            title="Cloud Storage Bucket Public Access",
            description="Bucket 'public-website-assets' has IAM binding granting 'allUsers' the Storage Object Viewer role",
            remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM bindings.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 5.1",
        ),
        Finding(
            rule_id="GCP-STORAGE-001", provider="gcp", resource_type="Cloud Storage Bucket",
            resource_id="projects/my-project/buckets/internal-backups",
            region="us-central1", severity="critical", status="PASS",
            title="Cloud Storage Bucket Public Access",
            description="Bucket 'internal-backups' has no public IAM bindings",
            remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM bindings.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 5.1",
        ),

        # Storage Encryption
        Finding(
            rule_id="GCP-STORAGE-002", provider="gcp", resource_type="Cloud Storage Bucket",
            resource_id="projects/my-project/buckets/public-website-assets",
            region="us-central1", severity="medium", status="FAIL",
            title="Cloud Storage Bucket Encryption",
            description="Bucket 'public-website-assets' uses Google-managed encryption (no CMEK configured)",
            remediation="Configure CMEK via Cloud KMS for sensitive buckets.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 5.3",
        ),

        # Firewall Rules
        Finding(
            rule_id="GCP-NET-001", provider="gcp", resource_type="Firewall Rule",
            resource_id="projects/my-project/global/firewalls/allow-ssh-all",
            region="global", severity="high", status="FAIL",
            title="Firewall Rule Allows Unrestricted Ingress",
            description="Firewall rule 'allow-ssh-all' allows TCP:22 from 0.0.0.0/0",
            remediation="Restrict source ranges to specific IP addresses.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 3.6",
        ),
        Finding(
            rule_id="GCP-NET-001", provider="gcp", resource_type="Firewall Rule",
            resource_id="projects/my-project/global/firewalls/allow-internal",
            region="global", severity="high", status="PASS",
            title="Firewall Rule Allows Unrestricted Ingress",
            description="Firewall rule 'allow-internal' is restricted to 10.0.0.0/8 source range",
            remediation="Restrict source ranges to specific IP addresses.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 3.6",
        ),

        # IAM Primitive Roles
        Finding(
            rule_id="GCP-IAM-001", provider="gcp", resource_type="IAM Binding",
            resource_id="projects/my-project",
            region="global", severity="high", status="FAIL",
            title="IAM Primitive Roles on Project",
            description="Service account 'ci-bot@my-project.iam.gserviceaccount.com' has 'roles/editor' on project",
            remediation="Replace primitive roles with predefined or custom IAM roles.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 1.6",
        ),
        Finding(
            rule_id="GCP-IAM-001", provider="gcp", resource_type="IAM Binding",
            resource_id="projects/my-project",
            region="global", severity="high", status="PASS",
            title="IAM Primitive Roles on Project",
            description="Service account 'app-sa@my-project.iam.gserviceaccount.com' uses predefined role 'roles/storage.objectViewer'",
            remediation="Replace primitive roles with predefined or custom IAM roles.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 1.6",
        ),

        # Cloud SQL SSL
        Finding(
            rule_id="GCP-SQL-001", provider="gcp", resource_type="Cloud SQL Instance",
            resource_id="projects/my-project/instances/prod-postgres",
            region="us-central1", severity="high", status="FAIL",
            title="Cloud SQL Instance Without SSL",
            description="Cloud SQL instance 'prod-postgres' does not require SSL connections",
            remediation="Enable SSL enforcement on Cloud SQL instances.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 6.4",
        ),
        Finding(
            rule_id="GCP-SQL-001", provider="gcp", resource_type="Cloud SQL Instance",
            resource_id="projects/my-project/instances/prod-mysql",
            region="us-central1", severity="high", status="PASS",
            title="Cloud SQL Instance Without SSL",
            description="Cloud SQL instance 'prod-mysql' requires SSL connections",
            remediation="Enable SSL enforcement on Cloud SQL instances.",
            cis_benchmark="CIS GCP Foundations 2.0.0 - 6.4",
        ),
    ]
