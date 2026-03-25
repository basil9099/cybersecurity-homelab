"""
AWS Scanner
-----------
Scans AWS resources for security misconfigurations using boto3.
Checks: S3 buckets, IAM, EBS, Security Groups, RDS, CloudTrail.
"""

import json

from .base_scanner import BaseScanner, Finding

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}


class AWSScanner(BaseScanner):
    PROVIDER = "aws"

    def __init__(
        self,
        regions: list[str] | None = None,
        profile: str | None = None,
        demo_mode: bool = False,
    ):
        super().__init__(regions=regions, demo_mode=demo_mode)
        self.profile = profile
        self._session = None

    def default_regions(self) -> list[str]:
        return ["us-east-1"]

    def authenticate(self) -> bool:
        try:
            import boto3

            kwargs = {}
            if self.profile:
                kwargs["profile_name"] = self.profile

            self._session = boto3.Session(**kwargs)
            sts = self._session.client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
            return True
        except Exception:
            return False

    def _client(self, service: str, region: str | None = None):
        return self._session.client(service, region_name=region or self.regions[0])

    # ------------------------------------------------------------------
    # S3 Checks
    # ------------------------------------------------------------------

    def check_s3_public_access(self) -> None:
        """Check S3 buckets for public access via ACLs and bucket policies."""
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])

            for bucket in buckets:
                name = bucket["Name"]
                resource_id = f"arn:aws:s3:::{name}"

                try:
                    region = s3.get_bucket_location(Bucket=name).get(
                        "LocationConstraint"
                    ) or "us-east-1"
                except Exception:
                    region = "unknown"

                is_public = False
                details = []

                # Check Block Public Access
                try:
                    bpa = s3.get_public_access_block(Bucket=name)
                    config = bpa["PublicAccessBlockConfiguration"]
                    if not all([
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False),
                    ]):
                        # BPA not fully enabled — check ACLs
                        try:
                            acl = s3.get_bucket_acl(Bucket=name)
                            for grant in acl.get("Grants", []):
                                grantee = grant.get("Grantee", {})
                                uri = grantee.get("URI", "")
                                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                                    is_public = True
                                    details.append(f"ACL grants access to {uri.split('/')[-1]}")
                        except Exception:
                            pass
                except Exception:
                    # No BPA configured — check ACLs and policy
                    try:
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            uri = grantee.get("URI", "")
                            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                                is_public = True
                                details.append(f"ACL grants access to {uri.split('/')[-1]}")
                    except Exception:
                        pass

                # Check bucket policy for Principal: *
                try:
                    policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
                    policy = json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
                            if stmt.get("Effect") == "Allow":
                                is_public = True
                                details.append("Bucket policy grants access to Principal '*'")
                except Exception:
                    pass

                detail_str = "; ".join(details) if details else "Block Public Access is enabled"
                self.add_finding(
                    rule_id="AWS-S3-001",
                    resource_type="S3 Bucket",
                    resource_id=resource_id,
                    region=region,
                    severity="critical",
                    status="FAIL" if is_public else "PASS",
                    title="S3 Bucket Public Access",
                    description=f"Bucket '{name}': {detail_str}",
                    remediation="Enable S3 Block Public Access at the account and bucket level.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AWS-S3-001",
                resource_type="S3 Bucket",
                resource_id="N/A",
                region=self.regions[0],
                severity="critical",
                status="ERROR",
                title="S3 Bucket Public Access",
                description=f"Error checking S3 public access: {e}",
                remediation="Ensure IAM permissions allow s3:ListBuckets and s3:GetBucketAcl.",
                cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
            )

    def check_s3_encryption(self) -> None:
        """Check S3 buckets for default encryption configuration."""
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])

            for bucket in buckets:
                name = bucket["Name"]
                resource_id = f"arn:aws:s3:::{name}"

                try:
                    region = s3.get_bucket_location(Bucket=name).get(
                        "LocationConstraint"
                    ) or "us-east-1"
                except Exception:
                    region = "unknown"

                encrypted = False
                detail = "No default encryption configured"

                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                        encrypted = True
                        detail = f"Default encryption enabled ({algo})"
                except s3.exceptions.ClientError:
                    pass
                except Exception:
                    pass

                self.add_finding(
                    rule_id="AWS-S3-002",
                    resource_type="S3 Bucket",
                    resource_id=resource_id,
                    region=region,
                    severity="high",
                    status="PASS" if encrypted else "FAIL",
                    title="S3 Bucket Encryption",
                    description=f"Bucket '{name}': {detail}",
                    remediation="Enable default encryption using SSE-S3 or SSE-KMS.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.2",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AWS-S3-002",
                resource_type="S3 Bucket",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="S3 Bucket Encryption",
                description=f"Error checking S3 encryption: {e}",
                remediation="Ensure IAM permissions allow s3:GetEncryptionConfiguration.",
                cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.2",
            )

    # ------------------------------------------------------------------
    # IAM Checks
    # ------------------------------------------------------------------

    def check_iam_no_mfa(self) -> None:
        """Check for IAM users without MFA enabled."""
        try:
            iam = self._client("iam")
            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    arn = user["Arn"]

                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                    except iam.exceptions.NoSuchEntityException:
                        continue  # No console access
                    except Exception:
                        continue

                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    has_mfa = len(mfa_devices) > 0

                    self.add_finding(
                        rule_id="AWS-IAM-001",
                        resource_type="IAM User",
                        resource_id=arn,
                        region="global",
                        severity="critical",
                        status="PASS" if has_mfa else "FAIL",
                        title="IAM Users Without MFA",
                        description=f"IAM user '{username}' {'has' if has_mfa else 'does not have'} MFA enabled",
                        remediation="Enable MFA for all IAM users with console access.",
                        cis_benchmark="CIS AWS Foundations 1.4.0 - 1.10",
                    )
        except Exception as e:
            self.add_finding(
                rule_id="AWS-IAM-001",
                resource_type="IAM User",
                resource_id="N/A",
                region="global",
                severity="critical",
                status="ERROR",
                title="IAM Users Without MFA",
                description=f"Error checking IAM MFA: {e}",
                remediation="Ensure IAM permissions allow iam:ListUsers and iam:ListMFADevices.",
                cis_benchmark="CIS AWS Foundations 1.4.0 - 1.10",
            )

    def check_iam_overly_permissive(self) -> None:
        """Check for IAM policies with overly permissive actions."""
        try:
            iam = self._client("iam")
            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for policy in page["Policies"]:
                    arn = policy["Arn"]
                    name = policy["PolicyName"]
                    version_id = policy["DefaultVersionId"]

                    version = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version_id
                    )
                    document = version["PolicyVersion"]["Document"]

                    is_overly_permissive = False
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") != "Allow":
                            continue
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources:
                            is_overly_permissive = True
                            break

                    self.add_finding(
                        rule_id="AWS-IAM-002",
                        resource_type="IAM Policy",
                        resource_id=arn,
                        region="global",
                        severity="critical",
                        status="FAIL" if is_overly_permissive else "PASS",
                        title="Overly Permissive IAM Policies",
                        description=f"Policy '{name}' {'grants' if is_overly_permissive else 'does not grant'} Action:* on Resource:*",
                        remediation="Apply the principle of least privilege. Replace wildcard policies.",
                        cis_benchmark="CIS AWS Foundations 1.4.0 - 1.16",
                    )
        except Exception as e:
            self.add_finding(
                rule_id="AWS-IAM-002",
                resource_type="IAM Policy",
                resource_id="N/A",
                region="global",
                severity="critical",
                status="ERROR",
                title="Overly Permissive IAM Policies",
                description=f"Error checking IAM policies: {e}",
                remediation="Ensure IAM permissions allow iam:ListPolicies and iam:GetPolicyVersion.",
                cis_benchmark="CIS AWS Foundations 1.4.0 - 1.16",
            )

    # ------------------------------------------------------------------
    # EC2 Checks
    # ------------------------------------------------------------------

    def check_ebs_encryption(self) -> None:
        """Check for unencrypted EBS volumes."""
        for region in self.regions:
            try:
                ec2 = self._client("ec2", region)
                paginator = ec2.get_paginator("describe_volumes")

                for page in paginator.paginate():
                    for volume in page["Volumes"]:
                        vol_id = volume["VolumeId"]
                        encrypted = volume.get("Encrypted", False)
                        size = volume.get("Size", "?")
                        vol_type = volume.get("VolumeType", "?")

                        self.add_finding(
                            rule_id="AWS-EC2-001",
                            resource_type="EBS Volume",
                            resource_id=vol_id,
                            region=region,
                            severity="high",
                            status="PASS" if encrypted else "FAIL",
                            title="Unencrypted EBS Volumes",
                            description=f"EBS volume '{vol_id}' ({size} GiB, {vol_type}) is {'encrypted' if encrypted else 'not encrypted'}",
                            remediation="Enable EBS encryption by default or create encrypted copies.",
                            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.2.1",
                        )
            except Exception as e:
                self.add_finding(
                    rule_id="AWS-EC2-001",
                    resource_type="EBS Volume",
                    resource_id="N/A",
                    region=region,
                    severity="high",
                    status="ERROR",
                    title="Unencrypted EBS Volumes",
                    description=f"Error checking EBS volumes in {region}: {e}",
                    remediation="Ensure IAM permissions allow ec2:DescribeVolumes.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 2.2.1",
                )

    def check_security_groups(self) -> None:
        """Check security groups for unrestricted ingress on sensitive ports."""
        for region in self.regions:
            try:
                ec2 = self._client("ec2", region)
                paginator = ec2.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    for sg in page["SecurityGroups"]:
                        sg_id = sg["GroupId"]
                        sg_name = sg.get("GroupName", "unnamed")
                        open_ports = []

                        for perm in sg.get("IpPermissions", []):
                            from_port = perm.get("FromPort", 0)
                            to_port = perm.get("ToPort", 65535)

                            for ip_range in perm.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    for port in SENSITIVE_PORTS:
                                        if from_port <= port <= to_port:
                                            open_ports.append(port)

                            for ip_range in perm.get("Ipv6Ranges", []):
                                if ip_range.get("CidrIpv6") == "::/0":
                                    for port in SENSITIVE_PORTS:
                                        if from_port <= port <= to_port:
                                            open_ports.append(port)

                        has_issue = len(open_ports) > 0
                        ports_str = ", ".join(str(p) for p in sorted(set(open_ports)))

                        self.add_finding(
                            rule_id="AWS-EC2-002",
                            resource_type="Security Group",
                            resource_id=sg_id,
                            region=region,
                            severity="high",
                            status="FAIL" if has_issue else "PASS",
                            title="Unrestricted Security Group Ingress",
                            description=f"Security group '{sg_id}' ({sg_name}) {'allows 0.0.0.0/0 on ports: ' + ports_str if has_issue else 'has no unrestricted ingress on sensitive ports'}",
                            remediation="Restrict security group ingress to specific IP ranges.",
                            cis_benchmark="CIS AWS Foundations 1.4.0 - 5.2",
                        )
            except Exception as e:
                self.add_finding(
                    rule_id="AWS-EC2-002",
                    resource_type="Security Group",
                    resource_id="N/A",
                    region=region,
                    severity="high",
                    status="ERROR",
                    title="Unrestricted Security Group Ingress",
                    description=f"Error checking security groups in {region}: {e}",
                    remediation="Ensure IAM permissions allow ec2:DescribeSecurityGroups.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 5.2",
                )

    # ------------------------------------------------------------------
    # RDS Checks
    # ------------------------------------------------------------------

    def check_rds_encryption(self) -> None:
        """Check RDS instances for storage encryption."""
        for region in self.regions:
            try:
                rds = self._client("rds", region)
                paginator = rds.get_paginator("describe_db_instances")

                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        db_id = db["DBInstanceIdentifier"]
                        arn = db["DBInstanceArn"]
                        encrypted = db.get("StorageEncrypted", False)
                        engine = db.get("Engine", "unknown")

                        self.add_finding(
                            rule_id="AWS-RDS-001",
                            resource_type="RDS Instance",
                            resource_id=arn,
                            region=region,
                            severity="high",
                            status="PASS" if encrypted else "FAIL",
                            title="Unencrypted RDS Instances",
                            description=f"RDS instance '{db_id}' ({engine}) {'has' if encrypted else 'does not have'} storage encryption enabled",
                            remediation="Enable encryption when creating RDS instances.",
                            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.3.1",
                        )
            except Exception as e:
                self.add_finding(
                    rule_id="AWS-RDS-001",
                    resource_type="RDS Instance",
                    resource_id="N/A",
                    region=region,
                    severity="high",
                    status="ERROR",
                    title="Unencrypted RDS Instances",
                    description=f"Error checking RDS in {region}: {e}",
                    remediation="Ensure IAM permissions allow rds:DescribeDBInstances.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 2.3.1",
                )

    # ------------------------------------------------------------------
    # CloudTrail Checks
    # ------------------------------------------------------------------

    def check_cloudtrail(self) -> None:
        """Check if CloudTrail is enabled and logging."""
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])

            if not trails:
                self.add_finding(
                    rule_id="AWS-LOG-001",
                    resource_type="CloudTrail",
                    resource_id="N/A",
                    region=self.regions[0],
                    severity="critical",
                    status="FAIL",
                    title="CloudTrail Logging Disabled",
                    description="No CloudTrail trails configured in this account",
                    remediation="Enable CloudTrail with a multi-region trail.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 3.1",
                )
                return

            for trail in trails:
                name = trail.get("Name", "unnamed")
                arn = trail.get("TrailARN", "N/A")
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                home_region = trail.get("HomeRegion", self.regions[0])

                try:
                    status = ct.get_trail_status(Name=arn)
                    is_logging = status.get("IsLogging", False)
                except Exception:
                    is_logging = False

                active = is_logging and is_multi_region

                self.add_finding(
                    rule_id="AWS-LOG-001",
                    resource_type="CloudTrail",
                    resource_id=arn,
                    region=home_region,
                    severity="critical",
                    status="PASS" if active else "FAIL",
                    title="CloudTrail Logging Disabled",
                    description=f"Trail '{name}': logging={'yes' if is_logging else 'no'}, multi-region={'yes' if is_multi_region else 'no'}",
                    remediation="Enable CloudTrail with a multi-region trail.",
                    cis_benchmark="CIS AWS Foundations 1.4.0 - 3.1",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AWS-LOG-001",
                resource_type="CloudTrail",
                resource_id="N/A",
                region=self.regions[0],
                severity="critical",
                status="ERROR",
                title="CloudTrail Logging Disabled",
                description=f"Error checking CloudTrail: {e}",
                remediation="Ensure IAM permissions allow cloudtrail:DescribeTrails.",
                cis_benchmark="CIS AWS Foundations 1.4.0 - 3.1",
            )
