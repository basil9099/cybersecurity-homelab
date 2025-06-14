# Privilege Escalation Report – Metasploitable2

## Initial Shell
- User: www-data
- Access gained via vsftpd 2.3.4 exploit

## Enumeration Results

### SUID Binaries
- `/usr/bin/nmap` — vulnerable to interactive shell breakout
  - Used: `nmap --interactive` + `!sh`
  - Result: Root shell obtained ✅

### Cron Jobs
- Found several daily/weekly jobs
- No writable or abusable scripts found

### Credential Dump
- Extracted `/etc/passwd` and `/etc/shadow`
- Password hashes obtained for:
  - `root`
  - `msfadmin`
  - `postgres`
  - `user`
  - `service`

### Tools Present
- `/bin/bash`, `/bin/nc`, `/usr/bin/python`
- Ready for reverse shells or data exfil

## Exploitation Summary
- Privilege escalation achieved via nmap SUID
- Post-exploitation data collection successful

## Next Step
→ Crack password hashes with John the Ripper
