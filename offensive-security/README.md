# Offensive Security — HackTheBox & Homelab Practice

## Overview

This section documents my offensive security practice across two areas: HackTheBox (HTB) retired machines and original homelab exercises. Each entry includes key vulnerability details, methodology, and links to full writeups on my blog.

- **HTB Profile:** https://app.hackthebox.com/users/2407781
- **Writeups Blog:** https://basil9099.github.io

---

## HackTheBox Machines

### Cap — Easy | Linux | Retired

**Vulnerabilities:** IDOR (Insecure Direct Object Reference), Linux Capabilities abuse (`cap_setuid`)

| Step | Detail |
|------|--------|
| Enumeration | Discovered web app with network capture feature; IDOR on `/data/<id>` endpoint — changed ID to `0` to download admin PCAP |
| PCAP Analysis | Opened in Wireshark; found cleartext FTP credentials for user `nathan` |
| Initial Access | SSH login as `nathan` using extracted credentials |
| PrivEsc | `getcap -r /` revealed `cap_setuid` on `/usr/bin/python3.8`; abused to `setuid(0)` and spawn root shell |

**Writeup:** https://basil9099.github.io/ctf/cap-htb/

---

### Blue — Easy | Windows | Retired

**Vulnerabilities:** MS17-010 (EternalBlue) — SMBv1 Remote Code Execution

| Step | Detail |
|------|--------|
| Enumeration | Nmap scan detected SMBv1 on port 445; `smb-vuln-ms17-010` confirmed the machine is unpatched |
| Exploitation | Ran EternalBlue exploit (Metasploit `exploit/windows/smb/ms17_010_eternalblue` or manual Python PoC) for unauthenticated RCE |
| Post-Exploitation | Obtained SYSTEM shell; extracted NTLM hashes from SAM database |

> The same MS17-010 vulnerability was weaponised by the WannaCry and NotPetya ransomware campaigns in 2017, affecting hundreds of thousands of machines globally.

---

### Optimum — Easy | Windows | Retired

**Vulnerabilities:** CVE-2014-6287 (HFS 2.3 RCE) + MS16-098 (kernel privilege escalation)

| Step | Detail |
|------|--------|
| Enumeration | HTTP enumeration revealed HttpFileServer (HFS) 2.3 |
| Exploitation | CVE-2014-6287: bug in `findMacroMarker` in `parserLib.pas` allows arbitrary command execution via crafted URL |
| PrivEsc | MS16-098 kernel exploit escalated from low-privilege user to SYSTEM |

---

### Wifinetic — Easy | Linux | Retired

**Vulnerabilities:** Anonymous FTP, OpenWRT backup credential leak, WPS PIN brute-force

| Step | Detail |
|------|--------|
| Enumeration | Anonymous FTP access exposed an OpenWRT configuration backup containing WiFi credentials |
| Initial Access | Credential reuse — leaked WiFi password also valid for SSH |
| PrivEsc | Wireless interface in monitor mode; used `reaver` to brute-force WPS PIN and recover root-level access |

---

## Homelab Exercises

### Pentest Workflow (Windows AD) — September 18, 2025

**Target:** Active Directory domain controller on local network (`homelab.local`)
**Tools:** Nmap, Kerbrute, CrackMapExec, Evil-WinRM

| Step | Detail |
|------|--------|
| Host Discovery | `nmap -sn 192.168.0.0/24` ping sweep — DC identified at `192.168.0.147` |
| Service Scan | `nmap -sV -sC` confirmed Windows AD DC (Kerberos port 88, LDAP, AD ports present) |
| User Enumeration | `kerbrute userenum` against KDC — found `administrator@homelab.local` |
| Password Brute-Force | `crackmapexec smb` with `rockyou.txt` — recovered valid credentials; `(Pwn3d!)` response confirmed admin access |
| Shell | `evil-winrm` with discovered credentials — authenticated remote PowerShell session obtained |
| Proof | `Set-Content` via Evil-WinRM to write `proof.txt` on the Administrator Desktop |

**Key lessons:** disable anonymous Kerberos user lookups; rate-limit and alert on auth brute-force; enforce MFA for privileged accounts; apply strong password policy on domain admins.

**Writeup:** https://basil9099.github.io/homelab/windows_pentest/

---

### Phishing Simulation — September 20, 2025

**Target:** Isolated lab environment (Kali attacker VM + lab target VM)
**Tools:** GoPhish, Social-Engineer Toolkit (SET)

> Lab use only. Do not deploy against real users or networks without explicit written permission.

| Step | Detail |
|------|--------|
| Infrastructure | Started GoPhish dashboard on attacker VM; configured SMTP sending profile with lab Gmail + app password |
| Landing Page | Created GoPhish landing page using SET Google 2FA HTML template (`/usr/share/set/src/html/templates/google/index.html`); added JS redirect to real Google site post-submission |
| Email Template | Pasted SET 2-step verification HTML into GoPhish email template; ticked "Change links to landing page" to rewrite all links |
| Campaign | Set campaign URL to attacker IP + listener port (`http://<ATTACKER_IP>:8080#`); added lab recipient addresses; launched campaign |
| Credential Capture | Target opened phishing email, clicked link, submitted credentials on cloned landing page; GoPhish campaign view showed captured creds and metadata (IP, user-agent, timestamp) |

**Writeup:** https://basil9099.github.io/homelab/phishing_simulation/

---

## Other Completed Machines

Additional machines have been completed but writeups are still in progress. This list will be updated as they are published.

---

## Tools & Techniques Reference

| Category | Tools / Techniques |
|----------|--------------------|
| Recon | Nmap, FTP enumeration |
| Web | Burp Suite, IDOR exploitation |
| Traffic Analysis | Wireshark, PCAP inspection |
| Exploitation | Metasploit, EternalBlue, CVE PoCs |
| Wireless | Reaver (WPS brute-force), monitor mode |
| Active Directory | Kerbrute (user enum), CrackMapExec (SMB brute-force), Evil-WinRM (remote shell) |
| Phishing | GoPhish, Social-Engineer Toolkit (SET) |
| Linux PrivEsc | Linux capabilities (`getcap`), SUID abuse |
| Windows PrivEsc | Kernel exploits (MS16-098), SAM extraction |
