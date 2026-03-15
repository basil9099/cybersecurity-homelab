#!/usr/bin/env python3
"""
Active Directory Enumeration Tool
----------------------------------
Enumerates AD users, groups, computers, and permission structures via LDAP.
Identifies privileged accounts, stale accounts, SPNs, and misconfigurations.

Usage:
  python ad_enum.py -d DOMAIN -u USER -p PASSWORD -H DC_IP [options]
  python ad_enum.py -d corp.local -u john -p Pass123 -H 192.168.1.10 --all
  python ad_enum.py -d corp.local -H 192.168.1.10 --anonymous --users

For educational/authorized penetration testing use only.
"""

import argparse
import json
import csv
import sys
import os
import re
import socket
from datetime import datetime, timezone, timedelta
from getpass import getpass

try:
    from ldap3 import (
        Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS,
        ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, SUBTREE, BASE
    )
    from ldap3.core.exceptions import (
        LDAPException, LDAPBindError, LDAPSocketOpenError,
        LDAPOperationResult
    )
except ImportError:
    print("[!] ldap3 not installed. Run: pip install ldap3")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

# ─── Colour helpers ────────────────────────────────────────────────────────────

def cprint(msg, color="reset"):
    if not COLORS:
        print(msg)
        return
    palette = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "blue":   Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "reset":  Style.RESET_ALL,
    }
    print(palette.get(color, "") + msg + Style.RESET_ALL)

def banner():
    art = r"""
  ___  ____     _____
 / _ \|  _ \   | ____|_ __  _   _ _ __ ___
| | | | | | |  |  _| | '_ \| | | | '_ ` _ \
| |_| | |_| |  | |___| | | | |_| | | | | | |
 \___/|____/   |_____|_| |_|\__,_|_| |_| |_|

  Active Directory Enumeration Tool  v1.0
  For authorized penetration testing only.
"""
    cprint(art, "cyan")


# ─── Windows FILETIME helpers ──────────────────────────────────────────────────

EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10_000_000
STALE_DAYS = 90  # accounts inactive longer than this are flagged stale


def filetime_to_dt(ft: int) -> datetime | None:
    """Convert Windows FILETIME integer to UTC datetime."""
    if ft in (0, 9223372036854775807):  # 0 = never, max int64 = never
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def is_stale(last_logon_ft: int | None, threshold_days: int = STALE_DAYS) -> bool:
    if last_logon_ft is None:
        return True
    dt = filetime_to_dt(last_logon_ft)
    if dt is None:
        return True
    return (datetime.now(timezone.utc) - dt).days > threshold_days


def format_dt(dt: datetime | None) -> str:
    if dt is None:
        return "Never"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


# ─── UAC flag decoder ──────────────────────────────────────────────────────────

UAC_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}


def decode_uac(uac: int) -> list[str]:
    return [name for bit, name in UAC_FLAGS.items() if uac & bit]


# ─── LDAP connection wrapper ───────────────────────────────────────────────────

class ADEnumerator:
    """Wraps an ldap3 connection and provides AD-specific query methods."""

    PRIVILEGED_GROUPS = {
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "Group Policy Creator Owners",
        "DNSAdmins",
        "Remote Management Users",
        "Exchange Organization Administrators",
    }

    def __init__(self, dc_ip: str, domain: str, username: str = "",
                 password: str = "", use_ssl: bool = False,
                 use_ntlm: bool = False, anonymous: bool = False,
                 timeout: int = 15):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.use_ntlm = use_ntlm
        self.anonymous = anonymous
        self.timeout = timeout
        self.conn: Connection | None = None
        self.base_dn = self._domain_to_dn(domain)
        self.results: dict = {
            "meta": {
                "target_dc": dc_ip,
                "domain": domain,
                "base_dn": self.base_dn,
                "scan_time": datetime.now(timezone.utc).isoformat(),
            },
            "domain_info": {},
            "password_policy": {},
            "users": [],
            "groups": [],
            "computers": [],
            "kerberoastable": [],
            "asreproastable": [],
            "privileged_users": [],
            "stale_users": [],
            "stale_computers": [],
            "trusts": [],
            "gpos": [],
            "findings": [],
        }

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split("."))

    def connect(self) -> bool:
        port = 636 if self.use_ssl else 389
        cprint(f"[*] Connecting to {self.dc_ip}:{port} ...", "cyan")
        try:
            server = Server(
                self.dc_ip,
                port=port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                connect_timeout=self.timeout,
            )
            if self.anonymous:
                self.conn = Connection(server, auto_bind=True)
                cprint("[+] Bound anonymously.", "yellow")
            elif self.use_ntlm:
                ntlm_user = f"{self.domain}\\{self.username}"
                self.conn = Connection(
                    server, user=ntlm_user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )
                cprint(f"[+] Bound via NTLM as {ntlm_user}", "green")
            else:
                upn = (
                    self.username if "@" in self.username
                    else f"{self.username}@{self.domain}"
                )
                self.conn = Connection(
                    server, user=upn, password=self.password,
                    authentication=SIMPLE, auto_bind=True
                )
                cprint(f"[+] Bound via Simple as {upn}", "green")
            return True
        except LDAPBindError as e:
            cprint(f"[!] Bind failed: {e}", "red")
        except LDAPSocketOpenError as e:
            cprint(f"[!] Cannot reach {self.dc_ip}:{port} — {e}", "red")
        except LDAPException as e:
            cprint(f"[!] LDAP error: {e}", "red")
        return False

    def disconnect(self):
        if self.conn:
            self.conn.unbind()

    # ── Internal query helper ──────────────────────────────────────────────────

    def _search(self, search_filter: str, attributes: list,
                base: str = None, scope=SUBTREE) -> list:
        base = base or self.base_dn
        entries = []
        try:
            self.conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                paged_size=500,
            )
            for entry in self.conn.entries:
                entries.append(entry)
            # Handle paged results (cookie)
            cookie = self.conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")
            while cookie:
                self.conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    paged_size=500,
                    paged_cookie=cookie,
                )
                for entry in self.conn.entries:
                    entries.append(entry)
                cookie = self.conn.result.get("controls", {}).get(
                    "1.2.840.113556.1.4.319", {}
                ).get("value", {}).get("cookie")
        except LDAPException as e:
            cprint(f"  [!] Query error ({search_filter[:60]}...): {e}", "yellow")
        return entries

    @staticmethod
    def _attr(entry, name: str, default=None):
        """Safely extract a single-value attribute."""
        try:
            val = getattr(entry, name).value
            return val if val is not None else default
        except Exception:
            return default

    @staticmethod
    def _attrs(entry, name: str) -> list:
        """Safely extract a multi-value attribute as list."""
        try:
            val = getattr(entry, name).values
            return list(val) if val else []
        except Exception:
            return []

    # ── Domain Info ───────────────────────────────────────────────────────────

    def enum_domain_info(self):
        cprint("\n[*] Enumerating domain info ...", "cyan")
        entries = self._search(
            "(objectClass=domain)",
            ["distinguishedName", "name", "whenCreated",
             "objectSid", "ms-DS-MachineAccountQuota",
             "minPwdLength", "maxPwdAge", "lockoutThreshold"],
            base=self.base_dn,
            scope=BASE,
        )
        if entries:
            e = entries[0]
            info = {
                "name": self._attr(e, "name"),
                "distinguished_name": self._attr(e, "distinguishedName"),
                "created": str(self._attr(e, "whenCreated", "Unknown")),
                "sid": str(self._attr(e, "objectSid", "Unknown")),
                "machine_account_quota": self._attr(e, "ms-DS-MachineAccountQuota"),
            }
            self.results["domain_info"] = info
            cprint(f"  Domain Name : {info['name']}", "green")
            cprint(f"  Domain SID  : {info['sid']}", "green")
            cprint(f"  Created     : {info['created']}", "green")
            if info["machine_account_quota"] and int(str(info["machine_account_quota"])) > 0:
                self._add_finding(
                    "MEDIUM",
                    "ms-DS-MachineAccountQuota > 0",
                    f"Any authenticated user can add {info['machine_account_quota']} "
                    "machine accounts to the domain (useful for resource-based constrained delegation attacks).",
                )

    # ── Password Policy ───────────────────────────────────────────────────────

    def enum_password_policy(self):
        cprint("\n[*] Enumerating default password policy ...", "cyan")
        entries = self._search(
            "(objectClass=domain)",
            ["minPwdLength", "maxPwdAge", "minPwdAge",
             "pwdHistoryLength", "lockoutThreshold",
             "lockoutDuration", "pwdProperties"],
            base=self.base_dn,
            scope=BASE,
        )
        if not entries:
            return
        e = entries[0]

        def age_to_days(raw) -> str:
            try:
                ns = abs(int(str(raw)))
                if ns == 0:
                    return "Never"
                return f"{ns // 864000000000} days"
            except Exception:
                return str(raw)

        policy = {
            "min_password_length": self._attr(e, "minPwdLength", 0),
            "max_password_age": age_to_days(self._attr(e, "maxPwdAge", 0)),
            "min_password_age": age_to_days(self._attr(e, "minPwdAge", 0)),
            "password_history_length": self._attr(e, "pwdHistoryLength", 0),
            "lockout_threshold": self._attr(e, "lockoutThreshold", 0),
            "lockout_duration": age_to_days(self._attr(e, "lockoutDuration", 0)),
        }
        self.results["password_policy"] = policy

        cprint(f"  Min Password Length  : {policy['min_password_length']}", "green")
        cprint(f"  Max Password Age     : {policy['max_password_age']}", "green")
        cprint(f"  Password History     : {policy['password_history_length']}", "green")
        cprint(f"  Lockout Threshold    : {policy['lockout_threshold']}", "green")
        cprint(f"  Lockout Duration     : {policy['lockout_duration']}", "green")

        # Findings
        min_len = int(str(policy["min_password_length"])) if policy["min_password_length"] else 0
        lockout = int(str(policy["lockout_threshold"])) if policy["lockout_threshold"] else 0

        if min_len < 8:
            self._add_finding("HIGH", "Weak minimum password length",
                              f"Minimum password length is {min_len} (recommended: 12+).")
        if lockout == 0:
            self._add_finding("HIGH", "No account lockout policy",
                              "Lockout threshold is 0 — brute-force attacks possible.")

    # ── Users ─────────────────────────────────────────────────────────────────

    def enum_users(self):
        cprint("\n[*] Enumerating users ...", "cyan")
        entries = self._search(
            "(&(objectClass=user)(objectCategory=person))",
            [
                "sAMAccountName", "displayName", "distinguishedName",
                "memberOf", "userAccountControl", "lastLogon",
                "lastLogonTimestamp", "pwdLastSet", "whenCreated",
                "description", "mail", "servicePrincipalName",
                "adminCount", "objectSid",
            ],
        )
        cprint(f"  Found {len(entries)} user accounts.", "green")

        for e in entries:
            sam = self._attr(e, "sAMAccountName", "")
            uac = int(str(self._attr(e, "userAccountControl", 0) or 0))
            last_logon = self._attr(e, "lastLogonTimestamp")
            pwd_last_set = self._attr(e, "pwdLastSet")
            spns = self._attrs(e, "servicePrincipalName")
            admin_count = self._attr(e, "adminCount", 0)
            description = self._attr(e, "description", "")
            uac_flags = decode_uac(uac)

            last_logon_ft = None
            if last_logon:
                try:
                    last_logon_ft = int(str(last_logon))
                except Exception:
                    pass

            pwd_last_set_ft = None
            if pwd_last_set:
                try:
                    pwd_last_set_ft = int(str(pwd_last_set))
                except Exception:
                    pass

            user = {
                "sam_account_name": sam,
                "display_name": self._attr(e, "displayName", ""),
                "distinguished_name": self._attr(e, "distinguishedName", ""),
                "email": self._attr(e, "mail", ""),
                "description": description,
                "uac": uac,
                "uac_flags": uac_flags,
                "last_logon": format_dt(filetime_to_dt(last_logon_ft)) if last_logon_ft else "Never",
                "pwd_last_set": format_dt(filetime_to_dt(pwd_last_set_ft)) if pwd_last_set_ft else "Never",
                "when_created": str(self._attr(e, "whenCreated", "")),
                "spns": spns,
                "admin_count": admin_count,
                "groups": self._attrs(e, "memberOf"),
                "disabled": "ACCOUNTDISABLE" in uac_flags,
                "password_never_expires": "DONT_EXPIRE_PASSWORD" in uac_flags,
                "no_preauth": "DONT_REQ_PREAUTH" in uac_flags,
                "stale": is_stale(last_logon_ft),
            }
            self.results["users"].append(user)

            # Kerberoastable
            if spns and not ("ACCOUNTDISABLE" in uac_flags):
                kerb = {
                    "sam_account_name": sam,
                    "spns": spns,
                    "admin_count": admin_count,
                    "password_never_expires": user["password_never_expires"],
                }
                self.results["kerberoastable"].append(kerb)

            # AS-REP Roastable
            if "DONT_REQ_PREAUTH" in uac_flags and "ACCOUNTDISABLE" not in uac_flags:
                self.results["asreproastable"].append({
                    "sam_account_name": sam,
                    "distinguished_name": self._attr(e, "distinguishedName", ""),
                })

            # Stale users
            if user["stale"] and not user["disabled"]:
                self.results["stale_users"].append({
                    "sam_account_name": sam,
                    "last_logon": user["last_logon"],
                    "disabled": user["disabled"],
                })

            # Password in description (quick check for common keywords)
            desc_lower = str(description).lower()
            if any(kw in desc_lower for kw in ["pass", "pwd", "password", "cred", "temp"]):
                self._add_finding(
                    "HIGH",
                    f"Possible password in description for {sam}",
                    f"Description field contains suspicious keyword: '{description}'",
                )

        # Findings summary
        if self.results["kerberoastable"]:
            self._add_finding(
                "HIGH",
                f"{len(self.results['kerberoastable'])} Kerberoastable account(s) found",
                "Accounts with SPNs can have their TGS tickets cracked offline.",
            )
        if self.results["asreproastable"]:
            self._add_finding(
                "HIGH",
                f"{len(self.results['asreproastable'])} AS-REP Roastable account(s) found",
                "Accounts with 'Do not require Kerberos preauthentication' set — "
                "hash can be captured and cracked offline without credentials.",
            )
        stale_count = len(self.results["stale_users"])
        if stale_count:
            self._add_finding(
                "MEDIUM",
                f"{stale_count} stale user account(s) (inactive >{STALE_DAYS} days)",
                "Stale enabled accounts are attack surface and indicate poor hygiene.",
            )

    # ── Groups ────────────────────────────────────────────────────────────────

    def enum_groups(self):
        cprint("\n[*] Enumerating groups ...", "cyan")
        entries = self._search(
            "(objectClass=group)",
            ["sAMAccountName", "distinguishedName", "member",
             "description", "adminCount", "groupType"],
        )
        cprint(f"  Found {len(entries)} groups.", "green")

        for e in entries:
            sam = self._attr(e, "sAMAccountName", "")
            members = self._attrs(e, "member")
            group = {
                "sam_account_name": sam,
                "distinguished_name": self._attr(e, "distinguishedName", ""),
                "description": self._attr(e, "description", ""),
                "admin_count": self._attr(e, "adminCount", 0),
                "member_count": len(members),
                "members": members,
                "is_privileged": sam in self.PRIVILEGED_GROUPS,
            }
            self.results["groups"].append(group)

            if group["is_privileged"]:
                for dn in members:
                    cn = dn.split(",")[0].replace("CN=", "")
                    entry = {"group": sam, "member_dn": dn, "member_cn": cn}
                    self.results["privileged_users"].append(entry)

        priv_groups_found = [g["sam_account_name"] for g in self.results["groups"] if g["is_privileged"]]
        if priv_groups_found:
            cprint(f"  Privileged groups: {', '.join(priv_groups_found)}", "yellow")

    # ── Computers ────────────────────────────────────────────────────────────

    def enum_computers(self):
        cprint("\n[*] Enumerating computers ...", "cyan")
        entries = self._search(
            "(objectClass=computer)",
            [
                "name", "dNSHostName", "distinguishedName",
                "operatingSystem", "operatingSystemVersion",
                "lastLogonTimestamp", "userAccountControl",
                "servicePrincipalName", "whenCreated",
            ],
        )
        cprint(f"  Found {len(entries)} computer accounts.", "green")

        dc_count = 0
        for e in entries:
            uac = int(str(self._attr(e, "userAccountControl", 0) or 0))
            uac_flags = decode_uac(uac)
            last_logon = self._attr(e, "lastLogonTimestamp")
            last_logon_ft = None
            if last_logon:
                try:
                    last_logon_ft = int(str(last_logon))
                except Exception:
                    pass

            is_dc = "SERVER_TRUST_ACCOUNT" in uac_flags
            if is_dc:
                dc_count += 1

            comp = {
                "name": self._attr(e, "name", ""),
                "dns_hostname": self._attr(e, "dNSHostName", ""),
                "distinguished_name": self._attr(e, "distinguishedName", ""),
                "os": self._attr(e, "operatingSystem", "Unknown"),
                "os_version": self._attr(e, "operatingSystemVersion", ""),
                "last_logon": format_dt(filetime_to_dt(last_logon_ft)) if last_logon_ft else "Never",
                "is_dc": is_dc,
                "uac_flags": uac_flags,
                "spns": self._attrs(e, "servicePrincipalName"),
                "stale": is_stale(last_logon_ft),
                "unconstrained_delegation": "TRUSTED_FOR_DELEGATION" in uac_flags and not is_dc,
            }
            self.results["computers"].append(comp)

            if comp["stale"] and "ACCOUNTDISABLE" not in uac_flags:
                self.results["stale_computers"].append({
                    "name": comp["name"],
                    "last_logon": comp["last_logon"],
                    "os": comp["os"],
                })
            if comp["unconstrained_delegation"]:
                self._add_finding(
                    "HIGH",
                    f"Unconstrained delegation on non-DC: {comp['name']}",
                    "Any TGT sent to this machine can be captured and reused "
                    "(printer bug / SpoolSample / Petitpotam).",
                )

        cprint(f"  Domain Controllers detected: {dc_count}", "yellow")
        if self.results["stale_computers"]:
            self._add_finding(
                "MEDIUM",
                f"{len(self.results['stale_computers'])} stale computer account(s)",
                "Stale computer accounts may represent decommissioned machines "
                "still accessible on the network.",
            )

    # ── Domain Trusts ─────────────────────────────────────────────────────────

    def enum_trusts(self):
        cprint("\n[*] Enumerating domain trusts ...", "cyan")
        entries = self._search(
            "(objectClass=trustedDomain)",
            ["name", "trustDirection", "trustType",
             "trustAttributes", "flatName"],
        )
        if not entries:
            cprint("  No trusts found.", "yellow")
            return

        direction_map = {1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}
        type_map = {1: "DOWNLEVEL", 2: "UPLEVEL (AD)", 3: "MIT Kerberos", 4: "DCE"}

        for e in entries:
            td = int(str(self._attr(e, "trustDirection", 0) or 0))
            tt = int(str(self._attr(e, "trustType", 0) or 0))
            ta = int(str(self._attr(e, "trustAttributes", 0) or 0))
            trust = {
                "name": self._attr(e, "name", ""),
                "flat_name": self._attr(e, "flatName", ""),
                "direction": direction_map.get(td, str(td)),
                "type": type_map.get(tt, str(tt)),
                "transitive": bool(ta & 0x1),
                "within_forest": bool(ta & 0x8),
                "sid_filtering": not bool(ta & 0x4),
            }
            self.results["trusts"].append(trust)
            cprint(f"  Trust: {trust['name']} [{trust['direction']}] transitive={trust['transitive']}", "yellow")

            if not trust["sid_filtering"] and trust["direction"] in ("OUTBOUND", "BIDIRECTIONAL"):
                self._add_finding(
                    "HIGH",
                    f"SID filtering disabled on trust to {trust['name']}",
                    "SID history attacks may be possible across this trust boundary.",
                )

    # ── GPOs ──────────────────────────────────────────────────────────────────

    def enum_gpos(self):
        cprint("\n[*] Enumerating Group Policy Objects ...", "cyan")
        entries = self._search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "distinguishedName", "gPCFileSysPath",
             "whenCreated", "whenChanged", "versionNumber"],
        )
        cprint(f"  Found {len(entries)} GPOs.", "green")
        for e in entries:
            gpo = {
                "name": self._attr(e, "displayName", ""),
                "distinguished_name": self._attr(e, "distinguishedName", ""),
                "file_path": self._attr(e, "gPCFileSysPath", ""),
                "created": str(self._attr(e, "whenCreated", "")),
                "modified": str(self._attr(e, "whenChanged", "")),
                "version": self._attr(e, "versionNumber", ""),
            }
            self.results["gpos"].append(gpo)

    # ── Findings helper ───────────────────────────────────────────────────────

    def _add_finding(self, severity: str, title: str, detail: str):
        self.results["findings"].append({
            "severity": severity,
            "title": title,
            "detail": detail,
        })

    # ── Print summary ─────────────────────────────────────────────────────────

    def print_summary(self):
        cprint("\n" + "=" * 60, "cyan")
        cprint("  ENUMERATION SUMMARY", "cyan")
        cprint("=" * 60, "cyan")

        r = self.results
        cprint(f"  Domain            : {r['meta']['domain']}", "green")
        cprint(f"  Base DN           : {r['meta']['base_dn']}", "green")
        cprint(f"  Users             : {len(r['users'])}", "green")
        cprint(f"  Groups            : {len(r['groups'])}", "green")
        cprint(f"  Computers         : {len(r['computers'])}", "green")
        cprint(f"  GPOs              : {len(r['gpos'])}", "green")
        cprint(f"  Trusts            : {len(r['trusts'])}", "green")
        cprint(f"  Kerberoastable    : {len(r['kerberoastable'])}", "yellow")
        cprint(f"  AS-REP Roastable  : {len(r['asreproastable'])}", "yellow")
        cprint(f"  Stale Users       : {len(r['stale_users'])}", "yellow")
        cprint(f"  Stale Computers   : {len(r['stale_computers'])}", "yellow")
        cprint(f"  Privileged Members: {len(r['privileged_users'])}", "yellow")

        if r["findings"]:
            cprint("\n  FINDINGS", "magenta")
            cprint("  " + "-" * 56, "magenta")
            sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}
            for f in sorted(r["findings"], key=lambda x: ("LOW","MEDIUM","HIGH").index(x["severity"]) if x["severity"] in ("LOW","MEDIUM","HIGH") else -1, reverse=True):
                c = sev_color.get(f["severity"], "reset")
                cprint(f"  [{f['severity']}] {f['title']}", c)
                cprint(f"       {f['detail']}", "reset")

        if r["kerberoastable"]:
            cprint("\n  KERBEROASTABLE ACCOUNTS", "yellow")
            for u in r["kerberoastable"]:
                cprint(f"  - {u['sam_account_name']}  SPNs: {', '.join(u['spns'])}", "yellow")

        if r["asreproastable"]:
            cprint("\n  AS-REP ROASTABLE ACCOUNTS", "yellow")
            for u in r["asreproastable"]:
                cprint(f"  - {u['sam_account_name']}", "yellow")

        cprint("=" * 60 + "\n", "cyan")

    # ── Exporters ─────────────────────────────────────────────────────────────

    def export_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        cprint(f"[+] JSON report saved: {path}", "green")

    def export_csv(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        tables = {
            "users": ["sam_account_name", "display_name", "email", "disabled",
                      "password_never_expires", "no_preauth", "stale", "last_logon",
                      "pwd_last_set", "description"],
            "groups": ["sam_account_name", "is_privileged", "member_count", "description"],
            "computers": ["name", "dns_hostname", "os", "is_dc", "stale",
                         "unconstrained_delegation", "last_logon"],
            "kerberoastable": ["sam_account_name", "admin_count", "password_never_expires"],
            "asreproastable": ["sam_account_name", "distinguished_name"],
            "findings": ["severity", "title", "detail"],
        }
        for name, fields in tables.items():
            rows = self.results.get(name, [])
            if not rows:
                continue
            path = os.path.join(output_dir, f"{name}.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
        cprint(f"[+] CSV reports saved to: {output_dir}/", "green")

    def export_html(self, path: str):
        """Generate a self-contained HTML report."""
        r = self.results

        def table(headers: list, rows: list) -> str:
            if not rows:
                return "<p><em>None</em></p>"
            cols = headers
            th = "".join(f"<th>{h}</th>" for h in cols)
            trs = ""
            for row in rows:
                tds = "".join(
                    f"<td>{row.get(c, '') if isinstance(row, dict) else ''}</td>"
                    for c in cols
                )
                trs += f"<tr>{tds}</tr>\n"
            return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"

        sev_class = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
        findings_html = ""
        for f in sorted(r["findings"], key=lambda x: ["INFO","LOW","MEDIUM","HIGH"].index(x.get("severity","INFO")) if x.get("severity","INFO") in ["INFO","LOW","MEDIUM","HIGH"] else 0, reverse=True):
            cls = sev_class.get(f["severity"], "info")
            findings_html += (
                f'<div class="finding {cls}">'
                f'<strong>[{f["severity"]}] {f["title"]}</strong><br>'
                f'{f["detail"]}</div>\n'
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Enumeration Report — {r['meta']['domain']}</title>
<style>
  body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 20px; }}
  h1 {{ color: #00d4ff; }} h2 {{ color: #7ec8e3; border-bottom: 1px solid #444; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 12px; }}
  th {{ background: #16213e; color: #00d4ff; padding: 6px 10px; text-align: left; }}
  td {{ padding: 4px 10px; border-bottom: 1px solid #333; }}
  tr:hover td {{ background: #0f3460; }}
  .finding {{ padding: 8px 12px; margin: 6px 0; border-left: 4px solid; border-radius: 2px; }}
  .high {{ border-color: #ff4444; background: #2a1515; }}
  .medium {{ border-color: #ffaa00; background: #2a2010; }}
  .low {{ border-color: #44aaff; background: #10152a; }}
  .info {{ border-color: #44ff88; background: #10201a; }}
  .meta {{ background: #16213e; padding: 10px 16px; border-radius: 4px; margin-bottom: 20px; }}
  .stat {{ display: inline-block; margin: 4px 16px 4px 0; }}
  .stat span {{ color: #00d4ff; font-weight: bold; }}
</style>
</head>
<body>
<h1>Active Directory Enumeration Report</h1>
<div class="meta">
  <div class="stat">Domain: <span>{r['meta']['domain']}</span></div>
  <div class="stat">DC: <span>{r['meta']['target_dc']}</span></div>
  <div class="stat">Scan Time: <span>{r['meta']['scan_time']}</span></div>
  <div class="stat">Users: <span>{len(r['users'])}</span></div>
  <div class="stat">Groups: <span>{len(r['groups'])}</span></div>
  <div class="stat">Computers: <span>{len(r['computers'])}</span></div>
  <div class="stat">Kerberoastable: <span>{len(r['kerberoastable'])}</span></div>
  <div class="stat">AS-REP Roastable: <span>{len(r['asreproastable'])}</span></div>
</div>

<h2>Findings</h2>
{findings_html if findings_html else "<p><em>No findings.</em></p>"}

<h2>Password Policy</h2>
<table><tbody>
{"".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k,v in r['password_policy'].items())}
</tbody></table>

<h2>Kerberoastable Accounts</h2>
{table(["sam_account_name","spns","admin_count","password_never_expires"], r['kerberoastable'])}

<h2>AS-REP Roastable Accounts</h2>
{table(["sam_account_name","distinguished_name"], r['asreproastable'])}

<h2>Privileged Group Members</h2>
{table(["group","member_cn","member_dn"], r['privileged_users'])}

<h2>Users ({len(r['users'])})</h2>
{table(["sam_account_name","display_name","email","disabled","password_never_expires","stale","last_logon","description"], r['users'])}

<h2>Stale Users</h2>
{table(["sam_account_name","last_logon","disabled"], r['stale_users'])}

<h2>Computers ({len(r['computers'])})</h2>
{table(["name","dns_hostname","os","is_dc","stale","unconstrained_delegation","last_logon"], r['computers'])}

<h2>Stale Computers</h2>
{table(["name","last_logon","os"], r['stale_computers'])}

<h2>Groups ({len(r['groups'])})</h2>
{table(["sam_account_name","is_privileged","member_count","description"], r['groups'])}

<h2>Domain Trusts</h2>
{table(["name","direction","type","transitive","within_forest","sid_filtering"], r['trusts'])}

<h2>Group Policy Objects ({len(r['gpos'])})</h2>
{table(["name","file_path","created","modified"], r['gpos'])}

</body></html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        cprint(f"[+] HTML report saved: {path}", "green")


# ─── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Active Directory Enumeration Tool — for authorized security assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Authenticated enumeration (all modules):
  python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --all

  # NTLM authentication:
  python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --ntlm --all

  # Anonymous bind (limited info):
  python ad_enum.py -d corp.local -H 192.168.1.10 --anonymous --users --groups

  # LDAPS (port 636):
  python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --ssl --all

  # Export reports:
  python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --all \\
      --json report.json --csv reports/ --html report.html

  # Prompt for password (safer):
  python ad_enum.py -d corp.local -u john -H 192.168.1.10 --all
        """,
    )
    # Connection
    conn = parser.add_argument_group("Connection")
    conn.add_argument("-H", "--host", required=True, help="DC IP or hostname")
    conn.add_argument("-d", "--domain", required=True, help="Domain name (e.g. corp.local)")
    conn.add_argument("-u", "--username", default="", help="Username")
    conn.add_argument("-p", "--password", default=None, help="Password (omit to prompt)")
    conn.add_argument("--ntlm", action="store_true", help="Use NTLM authentication")
    conn.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    conn.add_argument("--anonymous", action="store_true", help="Anonymous bind")
    conn.add_argument("--timeout", type=int, default=15, help="Connection timeout (s)")

    # Modules
    mods = parser.add_argument_group("Enumeration modules")
    mods.add_argument("--all", action="store_true", help="Run all modules")
    mods.add_argument("--domain-info", action="store_true", help="Domain info + password policy")
    mods.add_argument("--users", action="store_true", help="Enumerate users")
    mods.add_argument("--groups", action="store_true", help="Enumerate groups")
    mods.add_argument("--computers", action="store_true", help="Enumerate computers")
    mods.add_argument("--trusts", action="store_true", help="Enumerate domain trusts")
    mods.add_argument("--gpos", action="store_true", help="Enumerate GPOs")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--json", metavar="FILE", help="Save JSON report")
    out.add_argument("--csv", metavar="DIR", help="Save CSV reports to directory")
    out.add_argument("--html", metavar="FILE", help="Save HTML report")
    out.add_argument("--stale-days", type=int, default=90,
                     help="Days of inactivity to flag as stale (default: 90)")

    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    global STALE_DAYS
    STALE_DAYS = args.stale_days

    # Prompt for password if not provided and not anonymous
    password = args.password
    if not args.anonymous and args.username and password is None:
        password = getpass(f"[?] Password for {args.username}@{args.domain}: ")

    enum = ADEnumerator(
        dc_ip=args.host,
        domain=args.domain,
        username=args.username,
        password=password or "",
        use_ssl=args.ssl,
        use_ntlm=args.ntlm,
        anonymous=args.anonymous,
        timeout=args.timeout,
    )

    if not enum.connect():
        sys.exit(1)

    run_all = args.all

    try:
        if run_all or args.domain_info:
            enum.enum_domain_info()
            enum.enum_password_policy()

        if run_all or args.users:
            enum.enum_users()

        if run_all or args.groups:
            enum.enum_groups()

        if run_all or args.computers:
            enum.enum_computers()

        if run_all or args.trusts:
            enum.enum_trusts()

        if run_all or args.gpos:
            enum.enum_gpos()

    finally:
        enum.disconnect()

    enum.print_summary()

    # Exports
    if args.json:
        enum.export_json(args.json)
    if args.csv:
        enum.export_csv(args.csv)
    if args.html:
        enum.export_html(args.html)

    if not (args.json or args.csv or args.html):
        cprint("[i] Tip: use --json / --csv / --html to save reports.", "cyan")


if __name__ == "__main__":
    main()
