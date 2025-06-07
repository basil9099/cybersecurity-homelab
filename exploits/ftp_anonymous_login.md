# 🔍 Lab Report: FTP Anonymous Login on Metasploitable 2

## 🎯 Objective
Demonstrate unauthorized access via anonymous FTP login to Metasploitable 2.

## 💻 Environment
- **Attacker**: Kali Linux (192.168.74.128)
- **Target**: Metasploitable 2 (192.168.74.129)
- **Network Mode**: Host-only (same subnet)

## 🧰 Tools Used
- Nmap
- FTP client (command-line)

## 🚀 Steps & Execution

### 1. Scan the target for open FTP port and version info:
```bash
nmap -sV -p 21 192.168.74.129

#### 2. Connected via FTP:
```bash
ftp 192/168.74.129

##### 3. Logged in using:
Username: anonymous
Password: [pressed Enter]

###### 4. Verified access by listing directory:
```bash
ls
```

![FTP Login Success](../screenshots/ftp_anonymous_login.png)

