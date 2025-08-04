# Recon2Root: Metasploitable2 Exploitation Walkthrough

This project demonstrates a full penetration testing workflow against the Metasploitable2 virtual machine using Kali Linux tools.

## 🧰 Tools Used

- Nmap
- Nikto
- Metasploit
- Searchsploit
- Hydra
- John the Ripper

## 🖥️ Lab Environment

- **Attacker Machine**: Kali Linux
- **Target Machine**: Metasploitable2

## 🕵️‍♂️ Steps Overview

1. **Reconnaissance**: Identify open ports and services using Nmap.
2. **Enumeration**: Gather detailed information using Nikto.
3. **Vulnerability Analysis**: Search for known exploits with Searchsploit.
4. **Exploitation**: Gain access using Metasploit.
5. **Post-Exploitation**: Perform privilege escalation and extract sensitive data.
6. **Password Cracking**: Crack extracted hashes using John the Ripper.

## 📁 Files Included

- `nmap_scan.txt`: Output from Nmap scanning.
- `nikto_report.txt`: Nikto scan results.
- `metasploit_session.txt`: Metasploit session details.
- `privilege_escalation_notes.md`: Notes on privilege escalation steps.
- `cracked_passwords.txt`: Results from password cracking.
- `screenshots/`: Visual evidence of each step.

## 📸 Screenshots

![Nmap Scan](screenshots/nmap_scan.png)
![Nikto Scan](screenshots/nikto_scan.png)
![Metasploit Exploit](screenshots/metasploit_exploit.png)
![Privilege Escalation](screenshots/privilege_escalation.png)

## ✅ Results

-  Gained shell access via FTP backdoor
-  Escalated privileges to root
-  Extracted and cracked user credentials


## 🧠 Lessons Learned

- Importance of thorough reconnaissance.
- Leveraging known vulnerabilities for exploitation.
- Techniques for privilege escalation on Linux systems.
- Password cracking methodologies.

## ⚠️ Disclaimer

This project is for educational purposes only. Ensure you have proper authorization before conducting penetration testing activities.


## 🔗 Reference

Metasploitable2: https://sourceforge.net/projects/metasploitable  
Kali Linux: https://www.kali.org
