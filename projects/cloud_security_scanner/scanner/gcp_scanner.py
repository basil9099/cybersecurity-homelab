"""
GCP Scanner
-----------
Scans Google Cloud Platform resources for security misconfigurations.
Checks: Cloud Storage, Firewall Rules, IAM Bindings, Cloud SQL.
"""

from .base_scanner import BaseScanner, Finding

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}


class GCPScanner(BaseScanner):
    PROVIDER = "gcp"

    def __init__(
        self,
        project_id: str | None = None,
        regions: list[str] | None = None,
        demo_mode: bool = False,
    ):
        super().__init__(regions=regions, demo_mode=demo_mode)
        self.project_id = project_id
        self._credentials = None

    def default_regions(self) -> list[str]:
        return ["us-central1"]

    def authenticate(self) -> bool:
        try:
            import google.auth

            self._credentials, project = google.auth.default()
            if not self.project_id:
                self.project_id = project
            if not self.project_id:
                return False

            # Test connectivity by listing buckets
            from google.cloud import storage

            client = storage.Client(
                project=self.project_id, credentials=self._credentials
            )
            next(client.list_buckets(max_results=1), None)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Cloud Storage Checks
    # ------------------------------------------------------------------

    def check_storage_public_access(self) -> None:
        """Check Cloud Storage buckets for public access via IAM bindings."""
        try:
            from google.cloud import storage

            client = storage.Client(
                project=self.project_id, credentials=self._credentials
            )
            buckets = list(client.list_buckets())

            for bucket in buckets:
                name = bucket.name
                resource_id = f"projects/{self.project_id}/buckets/{name}"
                location = bucket.location or "unknown"
                is_public = False
                public_members = []

                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        for member in binding.get("members", []):
                            if member in ("allUsers", "allAuthenticatedUsers"):
                                is_public = True
                                public_members.append(f"{member} ({binding['role']})")
                except Exception:
                    pass

                detail = "; ".join(public_members) if public_members else "No public IAM bindings"

                self.add_finding(
                    rule_id="GCP-STORAGE-001",
                    resource_type="Cloud Storage Bucket",
                    resource_id=resource_id,
                    region=location.lower(),
                    severity="critical",
                    status="FAIL" if is_public else "PASS",
                    title="Cloud Storage Bucket Public Access",
                    description=f"Bucket '{name}': {detail}",
                    remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM bindings.",
                    cis_benchmark="CIS GCP Foundations 2.0.0 - 5.1",
                )
        except Exception as e:
            self.add_finding(
                rule_id="GCP-STORAGE-001",
                resource_type="Cloud Storage Bucket",
                resource_id="N/A",
                region=self.regions[0],
                severity="critical",
                status="ERROR",
                title="Cloud Storage Bucket Public Access",
                description=f"Error checking Cloud Storage public access: {e}",
                remediation="Ensure service account has storage.buckets.list and storage.buckets.getIamPolicy.",
                cis_benchmark="CIS GCP Foundations 2.0.0 - 5.1",
            )

    def check_storage_encryption(self) -> None:
        """Check Cloud Storage buckets for customer-managed encryption keys."""
        try:
            from google.cloud import storage

            client = storage.Client(
                project=self.project_id, credentials=self._credentials
            )
            buckets = list(client.list_buckets())

            for bucket in buckets:
                name = bucket.name
                resource_id = f"projects/{self.project_id}/buckets/{name}"
                location = bucket.location or "unknown"

                has_cmek = bucket.default_kms_key_name is not None

                self.add_finding(
                    rule_id="GCP-STORAGE-002",
                    resource_type="Cloud Storage Bucket",
                    resource_id=resource_id,
                    region=location.lower(),
                    severity="medium",
                    status="PASS" if has_cmek else "FAIL",
                    title="Cloud Storage Bucket Encryption",
                    description=f"Bucket '{name}' {'uses CMEK' if has_cmek else 'uses Google-managed encryption (no CMEK)'}",
                    remediation="Configure CMEK via Cloud KMS for sensitive buckets.",
                    cis_benchmark="CIS GCP Foundations 2.0.0 - 5.3",
                )
        except Exception as e:
            self.add_finding(
                rule_id="GCP-STORAGE-002",
                resource_type="Cloud Storage Bucket",
                resource_id="N/A",
                region=self.regions[0],
                severity="medium",
                status="ERROR",
                title="Cloud Storage Bucket Encryption",
                description=f"Error checking Cloud Storage encryption: {e}",
                remediation="Ensure service account has storage.buckets.list.",
                cis_benchmark="CIS GCP Foundations 2.0.0 - 5.3",
            )

    # ------------------------------------------------------------------
    # Network Checks
    # ------------------------------------------------------------------

    def check_firewall_rules(self) -> None:
        """Check VPC firewall rules for unrestricted ingress."""
        try:
            from googleapiclient.discovery import build

            compute = build(
                "compute", "v1", credentials=self._credentials
            )
            result = compute.firewalls().list(project=self.project_id).execute()
            firewalls = result.get("items", [])

            for fw in firewalls:
                name = fw.get("name", "unnamed")
                resource_id = f"projects/{self.project_id}/global/firewalls/{name}"
                direction = fw.get("direction", "INGRESS")

                if direction != "INGRESS":
                    continue

                source_ranges = fw.get("sourceRanges", [])
                has_open_source = "0.0.0.0/0" in source_ranges

                if not has_open_source:
                    self.add_finding(
                        rule_id="GCP-NET-001",
                        resource_type="Firewall Rule",
                        resource_id=resource_id,
                        region="global",
                        severity="high",
                        status="PASS",
                        title="Firewall Rule Allows Unrestricted Ingress",
                        description=f"Firewall rule '{name}' does not allow 0.0.0.0/0 source",
                        remediation="Restrict source ranges to specific IP addresses.",
                        cis_benchmark="CIS GCP Foundations 2.0.0 - 3.6",
                    )
                    continue

                # Check if allowed rules include sensitive ports
                open_ports = []
                for allowed in fw.get("allowed", []):
                    protocol = allowed.get("IPProtocol", "")
                    if protocol not in ("tcp", "all"):
                        continue

                    ports = allowed.get("ports", [])
                    if not ports and protocol == "all":
                        open_ports.extend(SENSITIVE_PORTS)
                        continue

                    for port_spec in ports:
                        if "-" in str(port_spec):
                            try:
                                low, high = str(port_spec).split("-")
                                for port in SENSITIVE_PORTS:
                                    if int(low) <= port <= int(high):
                                        open_ports.append(port)
                            except ValueError:
                                pass
                        else:
                            try:
                                if int(port_spec) in SENSITIVE_PORTS:
                                    open_ports.append(int(port_spec))
                            except ValueError:
                                pass

                has_sensitive = len(open_ports) > 0
                ports_str = ", ".join(str(p) for p in sorted(set(open_ports)))

                self.add_finding(
                    rule_id="GCP-NET-001",
                    resource_type="Firewall Rule",
                    resource_id=resource_id,
                    region="global",
                    severity="high",
                    status="FAIL" if has_sensitive else "PASS",
                    title="Firewall Rule Allows Unrestricted Ingress",
                    description=f"Firewall rule '{name}' {'allows 0.0.0.0/0 on ports: ' + ports_str if has_sensitive else 'allows 0.0.0.0/0 but not on sensitive ports'}",
                    remediation="Restrict source ranges to specific IP addresses.",
                    cis_benchmark="CIS GCP Foundations 2.0.0 - 3.6",
                )
        except Exception as e:
            self.add_finding(
                rule_id="GCP-NET-001",
                resource_type="Firewall Rule",
                resource_id="N/A",
                region="global",
                severity="high",
                status="ERROR",
                title="Firewall Rule Allows Unrestricted Ingress",
                description=f"Error checking firewall rules: {e}",
                remediation="Ensure service account has compute.firewalls.list.",
                cis_benchmark="CIS GCP Foundations 2.0.0 - 3.6",
            )

    # ------------------------------------------------------------------
    # IAM Checks
    # ------------------------------------------------------------------

    def check_iam_primitive_roles(self) -> None:
        """Check for IAM bindings using primitive roles on the project."""
        try:
            from googleapiclient.discovery import build

            crm = build(
                "cloudresourcemanager", "v1", credentials=self._credentials
            )
            policy = crm.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()

            bindings = policy.get("bindings", [])

            for binding in bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])

                if role not in PRIMITIVE_ROLES:
                    continue

                for member in members:
                    # Flag service accounts with primitive roles
                    is_sa = member.startswith("serviceAccount:")

                    self.add_finding(
                        rule_id="GCP-IAM-001",
                        resource_type="IAM Binding",
                        resource_id=f"projects/{self.project_id}",
                        region="global",
                        severity="high",
                        status="FAIL" if is_sa else "PASS",
                        title="IAM Primitive Roles on Project",
                        description=f"Member '{member}' has primitive role '{role}' on project"
                            + (" (service account with primitive role)" if is_sa else ""),
                        remediation="Replace primitive roles with predefined or custom IAM roles.",
                        cis_benchmark="CIS GCP Foundations 2.0.0 - 1.6",
                    )
        except Exception as e:
            self.add_finding(
                rule_id="GCP-IAM-001",
                resource_type="IAM Binding",
                resource_id=f"projects/{self.project_id}",
                region="global",
                severity="high",
                status="ERROR",
                title="IAM Primitive Roles on Project",
                description=f"Error checking IAM bindings: {e}",
                remediation="Ensure service account has resourcemanager.projects.getIamPolicy.",
                cis_benchmark="CIS GCP Foundations 2.0.0 - 1.6",
            )

    # ------------------------------------------------------------------
    # Cloud SQL Checks
    # ------------------------------------------------------------------

    def check_cloudsql_ssl(self) -> None:
        """Check Cloud SQL instances for SSL enforcement."""
        try:
            from googleapiclient.discovery import build

            sqladmin = build(
                "sqladmin", "v1beta4", credentials=self._credentials
            )
            result = sqladmin.instances().list(
                project=self.project_id
            ).execute()
            instances = result.get("items", [])

            for instance in instances:
                name = instance.get("name", "unnamed")
                resource_id = f"projects/{self.project_id}/instances/{name}"
                region = instance.get("region", "unknown")

                settings = instance.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                require_ssl = ip_config.get("requireSsl", False)

                self.add_finding(
                    rule_id="GCP-SQL-001",
                    resource_type="Cloud SQL Instance",
                    resource_id=resource_id,
                    region=region,
                    severity="high",
                    status="PASS" if require_ssl else "FAIL",
                    title="Cloud SQL Instance Without SSL",
                    description=f"Cloud SQL instance '{name}' {'requires' if require_ssl else 'does not require'} SSL connections",
                    remediation="Enable SSL enforcement on Cloud SQL instances.",
                    cis_benchmark="CIS GCP Foundations 2.0.0 - 6.4",
                )
        except Exception as e:
            self.add_finding(
                rule_id="GCP-SQL-001",
                resource_type="Cloud SQL Instance",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="Cloud SQL Instance Without SSL",
                description=f"Error checking Cloud SQL: {e}",
                remediation="Ensure service account has cloudsql.instances.list.",
                cis_benchmark="CIS GCP Foundations 2.0.0 - 6.4",
            )
