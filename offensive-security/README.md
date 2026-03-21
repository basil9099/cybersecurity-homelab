# Offensive Security — HackTheBox Practice

## Overview

This section documents my HackTheBox pentesting practice. HackTheBox (HTB) is an online platform providing intentionally vulnerable machines to develop and refine offensive security skills in a legal, controlled environment. Each machine below includes key vulnerability details and methodology. Full writeups are published on my blog.

- **HTB Profile:** https://app.hackthebox.com/users/2407781
- **Writeups Blog:** https://basil9099.github.io

---

## Machines With Writeups

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
| Linux PrivEsc | Linux capabilities (`getcap`), SUID abuse |
| Windows PrivEsc | Kernel exploits (MS16-098), SAM extraction |
