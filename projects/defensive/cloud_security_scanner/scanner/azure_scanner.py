"""
Azure Scanner
--------------
Scans Azure resources for security misconfigurations.
Checks: Storage Accounts, NSGs, Key Vaults, SQL Databases.
"""

from .base_scanner import BaseScanner, Finding

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}


class AzureScanner(BaseScanner):
    PROVIDER = "azure"

    def __init__(
        self,
        subscription_id: str | None = None,
        regions: list[str] | None = None,
        demo_mode: bool = False,
    ):
        super().__init__(regions=regions, demo_mode=demo_mode)
        self.subscription_id = subscription_id
        self._credential = None

    def default_regions(self) -> list[str]:
        return ["eastus"]

    def authenticate(self) -> bool:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient

            self._credential = DefaultAzureCredential()
            client = ResourceManagementClient(self._credential, self.subscription_id)
            # Test connectivity by listing resource groups
            next(client.resource_groups.list(), None)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Storage Checks
    # ------------------------------------------------------------------

    def check_storage_public_access(self) -> None:
        """Check storage accounts for public blob access."""
        try:
            from azure.mgmt.storage import StorageManagementClient

            client = StorageManagementClient(self._credential, self.subscription_id)
            accounts = list(client.storage_accounts.list())

            for account in accounts:
                name = account.name
                resource_id = account.id
                location = account.location or "unknown"
                allow_public = getattr(account, "allow_blob_public_access", None)

                # Default is True if property is None (pre-2019 accounts)
                is_public = allow_public is not False

                self.add_finding(
                    rule_id="AZURE-STORAGE-001",
                    resource_type="Storage Account",
                    resource_id=resource_id,
                    region=location,
                    severity="critical",
                    status="FAIL" if is_public else "PASS",
                    title="Storage Account Public Blob Access",
                    description=f"Storage account '{name}' {'allows' if is_public else 'does not allow'} public blob access",
                    remediation="Disable public blob access on the storage account.",
                    cis_benchmark="CIS Azure Foundations 2.0.0 - 3.7",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AZURE-STORAGE-001",
                resource_type="Storage Account",
                resource_id="N/A",
                region=self.regions[0],
                severity="critical",
                status="ERROR",
                title="Storage Account Public Blob Access",
                description=f"Error checking storage public access: {e}",
                remediation="Ensure permissions allow Microsoft.Storage/storageAccounts/read.",
                cis_benchmark="CIS Azure Foundations 2.0.0 - 3.7",
            )

    def check_storage_encryption(self) -> None:
        """Check storage accounts for encryption configuration."""
        try:
            from azure.mgmt.storage import StorageManagementClient

            client = StorageManagementClient(self._credential, self.subscription_id)
            accounts = list(client.storage_accounts.list())

            for account in accounts:
                name = account.name
                resource_id = account.id
                location = account.location or "unknown"

                encrypted = False
                if account.encryption and account.encryption.services:
                    blob_enc = account.encryption.services.blob
                    if blob_enc and blob_enc.enabled:
                        encrypted = True

                self.add_finding(
                    rule_id="AZURE-STORAGE-002",
                    resource_type="Storage Account",
                    resource_id=resource_id,
                    region=location,
                    severity="high",
                    status="PASS" if encrypted else "FAIL",
                    title="Storage Account Encryption",
                    description=f"Storage account '{name}' {'has' if encrypted else 'does not have'} blob encryption enabled",
                    remediation="Enable encryption for all storage services.",
                    cis_benchmark="CIS Azure Foundations 2.0.0 - 3.2",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AZURE-STORAGE-002",
                resource_type="Storage Account",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="Storage Account Encryption",
                description=f"Error checking storage encryption: {e}",
                remediation="Ensure permissions allow Microsoft.Storage/storageAccounts/read.",
                cis_benchmark="CIS Azure Foundations 2.0.0 - 3.2",
            )

    # ------------------------------------------------------------------
    # Network Checks
    # ------------------------------------------------------------------

    def check_nsg_unrestricted(self) -> None:
        """Check NSGs for unrestricted inbound rules on sensitive ports."""
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self.subscription_id)
            nsgs = list(client.network_security_groups.list_all())

            for nsg in nsgs:
                name = nsg.name
                resource_id = nsg.id
                location = nsg.location or "unknown"
                open_ports = []

                for rule in (nsg.security_rules or []):
                    if rule.direction != "Inbound" or rule.access != "Allow":
                        continue

                    src = rule.source_address_prefix or ""
                    if src not in ("*", "0.0.0.0/0", "Internet", "Any"):
                        # Also check source_address_prefixes list
                        prefixes = rule.source_address_prefixes or []
                        if not any(p in ("*", "0.0.0.0/0", "Internet", "Any") for p in prefixes):
                            continue

                    # Check port ranges
                    port_range = rule.destination_port_range or ""
                    port_ranges = rule.destination_port_ranges or []

                    all_ranges = [port_range] + list(port_ranges)
                    for pr in all_ranges:
                        if pr == "*":
                            open_ports.extend(SENSITIVE_PORTS)
                        elif "-" in pr:
                            try:
                                low, high = pr.split("-")
                                for port in SENSITIVE_PORTS:
                                    if int(low) <= port <= int(high):
                                        open_ports.append(port)
                            except ValueError:
                                pass
                        else:
                            try:
                                if int(pr) in SENSITIVE_PORTS:
                                    open_ports.append(int(pr))
                            except ValueError:
                                pass

                has_issue = len(open_ports) > 0
                ports_str = ", ".join(str(p) for p in sorted(set(open_ports)))

                self.add_finding(
                    rule_id="AZURE-NET-001",
                    resource_type="Network Security Group",
                    resource_id=resource_id,
                    region=location,
                    severity="high",
                    status="FAIL" if has_issue else "PASS",
                    title="NSG Unrestricted Inbound Access",
                    description=f"NSG '{name}' {'allows unrestricted inbound on ports: ' + ports_str if has_issue else 'has no unrestricted inbound rules on sensitive ports'}",
                    remediation="Restrict NSG inbound rules to specific IP ranges.",
                    cis_benchmark="CIS Azure Foundations 2.0.0 - 6.1",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AZURE-NET-001",
                resource_type="Network Security Group",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="NSG Unrestricted Inbound Access",
                description=f"Error checking NSGs: {e}",
                remediation="Ensure permissions allow Microsoft.Network/networkSecurityGroups/read.",
                cis_benchmark="CIS Azure Foundations 2.0.0 - 6.1",
            )

    # ------------------------------------------------------------------
    # Key Vault Checks
    # ------------------------------------------------------------------

    def check_keyvault_access(self) -> None:
        """Check Key Vaults for overly broad access policies."""
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient

            client = KeyVaultManagementClient(self._credential, self.subscription_id)
            vaults = list(client.vaults.list())

            for vault_item in vaults:
                # list() returns a minimal object; need to get full vault
                # Parse resource group from the vault ID
                parts = vault_item.id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                rg_name = parts[rg_idx]
                vault_name = vault_item.name

                try:
                    vault = client.vaults.get(rg_name, vault_name)
                except Exception:
                    continue

                resource_id = vault.id
                location = vault.location or "unknown"
                overly_broad = False

                all_key_perms = {"get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "decrypt", "encrypt", "unwrapKey", "wrapKey", "verify", "sign", "purge"}
                all_secret_perms = {"get", "list", "set", "delete", "recover", "backup", "restore", "purge"}

                for policy in (vault.properties.access_policies or []):
                    key_perms = set(p.value if hasattr(p, "value") else p for p in (policy.permissions.keys or []))
                    secret_perms = set(p.value if hasattr(p, "value") else p for p in (policy.permissions.secrets or []))

                    if "all" in key_perms or "all" in secret_perms:
                        overly_broad = True
                        break
                    if key_perms >= all_key_perms or secret_perms >= all_secret_perms:
                        overly_broad = True
                        break

                self.add_finding(
                    rule_id="AZURE-KV-001",
                    resource_type="Key Vault",
                    resource_id=resource_id,
                    region=location,
                    severity="high",
                    status="FAIL" if overly_broad else "PASS",
                    title="Key Vault Overly Broad Access",
                    description=f"Key Vault '{vault_name}' {'has' if overly_broad else 'does not have'} overly broad access policies",
                    remediation="Review Key Vault access policies and remove unnecessary permissions.",
                    cis_benchmark="CIS Azure Foundations 2.0.0 - 8.5",
                )
        except Exception as e:
            self.add_finding(
                rule_id="AZURE-KV-001",
                resource_type="Key Vault",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="Key Vault Overly Broad Access",
                description=f"Error checking Key Vaults: {e}",
                remediation="Ensure permissions allow Microsoft.KeyVault/vaults/read.",
                cis_benchmark="CIS Azure Foundations 2.0.0 - 8.5",
            )

    # ------------------------------------------------------------------
    # SQL Checks
    # ------------------------------------------------------------------

    def check_sql_tde(self) -> None:
        """Check Azure SQL databases for Transparent Data Encryption."""
        try:
            from azure.mgmt.sql import SqlManagementClient

            client = SqlManagementClient(self._credential, self.subscription_id)

            # List all SQL servers across resource groups
            servers = list(client.servers.list())

            for server in servers:
                server_name = server.name
                parts = server.id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                rg_name = parts[rg_idx]
                location = server.location or "unknown"

                databases = list(client.databases.list_by_server(rg_name, server_name))

                for db in databases:
                    if db.name == "master":
                        continue

                    resource_id = db.id
                    db_name = db.name

                    try:
                        tde_configs = list(client.transparent_data_encryptions.list_by_database(
                            rg_name, server_name, db_name
                        ))
                        tde_enabled = any(
                            t.state and str(t.state).lower() == "enabled"
                            for t in tde_configs
                        )
                    except Exception:
                        tde_enabled = False

                    self.add_finding(
                        rule_id="AZURE-SQL-001",
                        resource_type="SQL Database",
                        resource_id=resource_id,
                        region=location,
                        severity="high",
                        status="PASS" if tde_enabled else "FAIL",
                        title="SQL Database Without TDE",
                        description=f"SQL database '{db_name}' on server '{server_name}' {'has' if tde_enabled else 'does not have'} TDE enabled",
                        remediation="Enable TDE on all Azure SQL databases.",
                        cis_benchmark="CIS Azure Foundations 2.0.0 - 4.1.2",
                    )
        except Exception as e:
            self.add_finding(
                rule_id="AZURE-SQL-001",
                resource_type="SQL Database",
                resource_id="N/A",
                region=self.regions[0],
                severity="high",
                status="ERROR",
                title="SQL Database Without TDE",
                description=f"Error checking SQL TDE: {e}",
                remediation="Ensure permissions allow Microsoft.Sql/servers/databases/read.",
                cis_benchmark="CIS Azure Foundations 2.0.0 - 4.1.2",
            )
