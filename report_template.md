# 🔍 Lab Report: [TITLE HERE]

## 🎯 Objective
What is the goal of this lab?

## 💻 Environment
- Attacker: Kali Linux [version]
- Target: [e.g., Metasploitable 2, Juice Shop]
- Network: Bridged/NAT, IPs: [List IPs]

## 🧰 Tools Used
- Tool 1 (e.g., Nmap)
- Tool 2 (e.g., Burp Suite)

## 🚀 Steps & Execution
1. **Initial Recon**
   - Command: `nmap -sV -A [target]`
   - Output: `Port 80 open`
   - Screenshot: `screenshots/nmap_output.png`

2. **Exploitation**
   - Manual injection payload: `' OR 1=1 --`
   - Result: Admin panel access

3. **Post Exploitation**
   - Reverse shell
   - Privilege escalation

## 📸 Screenshots
Include at least 1–2 screenshots per key step.

## 🧠 Key Learnings
- Discovered how XXE works in Node apps
- Practiced lateral movement via SMB

## 🛡️ Remediation Suggestions (Optional)
- Patch version
- Disable directory listing
