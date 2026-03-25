# Active Directory Enumeration Tool

A comprehensive Python tool for enumerating Active Directory environments via LDAP.
Designed for authorized penetration testing, red team assessments, and security audits.

> **Warning:** Only run this tool against systems you own or have explicit written authorization to test.

---

## Features

| Category | What it enumerates |
|---|---|
| **Domain Info** | Domain name, SID, machine-account quota |
| **Password Policy** | Min length, lockout threshold, max age, history |
| **Users** | All accounts, UAC flags, last logon, password age |
| **Groups** | All groups, privileged group membership |
| **Computers** | All machines, OS version, DCs, delegation flags |
| **Kerberoasting** | Accounts with SPNs (TGS hash cracking candidates) |
| **AS-REP Roasting** | Accounts without Kerberos pre-auth |
| **Stale Accounts** | Users/computers inactive >90 days (configurable) |
| **Domain Trusts** | Trust direction, type, SID filtering status |
| **GPOs** | All Group Policy Objects and file paths |
| **Findings** | Auto-generated security findings with severity ratings |

---

## Installation

```bash
cd projects/ad_enum
pip install -r requirements.txt
```

---

## Usage

### Basic authenticated scan (all modules)
```bash
python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --all
```

### Prompt for password (safer — avoids shell history)
```bash
python ad_enum.py -d corp.local -u john -H 192.168.1.10 --all
```

### NTLM authentication
```bash
python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --ntlm --all
```

### LDAPS (port 636)
```bash
python ad_enum.py -d corp.local -u john -p 'Pass123!' -H 192.168.1.10 --ssl --all
```

### Anonymous bind (limited results)
```bash
python ad_enum.py -d corp.local -H 192.168.1.10 --anonymous --users --groups
```

### Selective modules
```bash
# Only users and groups
python ad_enum.py -d corp.local -u john -H 192.168.1.10 --users --groups

# Only Kerberoasting candidates (part of --users)
python ad_enum.py -d corp.local -u john -H 192.168.1.10 --users
```

### Export reports
```bash
python ad_enum.py -d corp.local -u john -H 192.168.1.10 --all \
    --json report.json \
    --csv  reports/ \
    --html report.html
```

### Adjust stale threshold
```bash
# Flag accounts inactive for more than 60 days
python ad_enum.py -d corp.local -u john -H 192.168.1.10 --all --stale-days 60
```

---

## Arguments

```
Connection:
  -H, --host         DC IP address or hostname (required)
  -d, --domain       Domain name, e.g. corp.local (required)
  -u, --username     Username
  -p, --password     Password (omit to be prompted securely)
  --ntlm             Use NTLM authentication instead of Simple bind
  --ssl              Use LDAPS on port 636
  --anonymous        Anonymous bind (no credentials)
  --timeout          TCP connection timeout in seconds (default: 15)

Enumeration modules:
  --all              Run every module
  --domain-info      Domain properties and default password policy
  --users            All user accounts (includes Kerberoast/AS-REP checks)
  --groups           All groups and privileged membership
  --computers        All machine accounts (includes delegation checks)
  --trusts           Domain and forest trusts
  --gpos             Group Policy Objects

Output:
  --json FILE        Write full results to JSON
  --csv  DIR         Write per-category CSV files to a directory
  --html FILE        Write self-contained HTML report
  --stale-days N     Inactivity threshold for stale accounts (default: 90)
```

---

## Output Reports

### Terminal
Colour-coded output with a summary table and findings list.

### JSON (`--json`)
Full structured data dump suitable for parsing or importing into other tools.

### CSV (`--csv`)
Separate CSV files per category: `users.csv`, `groups.csv`, `computers.csv`,
`kerberoastable.csv`, `asreproastable.csv`, `findings.csv`.

### HTML (`--html`)
Self-contained dark-theme HTML report with all tables and findings — no internet
connection required to view.

---

## Security Findings

The tool automatically generates severity-rated findings for:

| Severity | Example |
|---|---|
| HIGH | Kerberoastable accounts |
| HIGH | AS-REP Roastable accounts |
| HIGH | Unconstrained delegation on non-DCs |
| HIGH | Weak or missing password policy |
| HIGH | Possible credentials in description fields |
| HIGH | SID filtering disabled on trusts |
| MEDIUM | Stale enabled user/computer accounts |
| MEDIUM | ms-DS-MachineAccountQuota > 0 |

---

## Lab Setup (HTB / TryHackMe / Own DC)

1. Spin up a Windows Server VM and promote it to DC.
2. Create test OUs, users, groups, GPOs, and SPNs.
3. Connect from your Kali/Parrot attack machine:
   ```bash
   python ad_enum.py -d lab.local -u attacker -H 10.10.10.5 --all --html lab_report.html
   ```
4. Open `lab_report.html` in a browser to review findings.

---

## How it Works

The tool uses the `ldap3` Python library to:

1. **Bind** to the DC using Simple (UPN), NTLM, or anonymous authentication.
2. **Query** the directory with targeted LDAP filters across `SUBTREE` scope.
3. **Parse** `userAccountControl` bit flags, Windows FILETIME timestamps, SPN lists, etc.
4. **Correlate** data to surface high-value targets and misconfigurations.
5. **Export** structured results to JSON, CSV, and/or HTML.

LDAP filters used include:
- `(&(objectClass=user)(objectCategory=person))` — all user accounts
- `(objectClass=group)` — all groups
- `(objectClass=computer)` — all machine accounts
- `(objectClass=trustedDomain)` — trust objects
- `(objectClass=groupPolicyContainer)` — GPOs

---

## Ethical & Legal Notice

This tool is for **authorized** use only.

- Only run against systems you **own** or have **explicit written permission** to test.
- Unauthorized access to computer systems is illegal in most jurisdictions.
- Always obtain a signed Rules of Engagement / scope document before testing.
