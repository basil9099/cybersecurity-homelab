#  FTP Brute-Force Attack Using Hydra

##  Objective

Use Hydra to perform an online brute-force attack against an FTP service running on Metasploitable 2, and gain unauthorized access by cracking a weak password.

---

##  Lab Environment

| Component | Value |
|----------|-------|
| Attacker | Kali Linux (192.168.74.128) |
| Target   | Metasploitable 2 (192.168.74.129) |
| Service  | vsftpd 2.3.4 (FTP on port 21) |
| Tool     | Hydra |

---

##  Tools Used

- `hydra`: For brute-forcing login credentials
- `nmap`: For initial port and service discovery
- `gnome-screenshot`: To document output
- `git`: For version control and reporting

---

##  Discovery Phase

First, identify that FTP is running:

```bash
nmap -sV -p 21 192.168.74.129
