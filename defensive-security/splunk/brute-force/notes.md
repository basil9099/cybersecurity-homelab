# 🔐 Brute-Force Detection Simulation (Kali ➡️ Windows ➡️ Splunk)

This test was conducted to validate Splunk's ability to detect brute-force login activity across the lab network.

---

## ✅ Goal

Simulate failed login attempts from Kali Linux to a Windows 10 host and verify:

- Event logging on the Windows system
- Log forwarding via Universal Forwarder
- Detection and alerting in Splunk

---

## 🧪 Steps

### 1. Nmap Scan

Initial enumeration of the target host to identify SMB and RDP services.

![Nmap](./screenshots/01_nmap-scan.png)

---

### 2. Hydra SMB Brute-Force

```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt smb://192.168.0.147
```

Expected to produce `NT_STATUS_LOGON_FAILURE`.

![Hydra](./screenshots/02_hydra-bruteforce.png)

---

### 3. Manual SMBClient Attempt

```bash
smbclient -L //192.168.0.147 -u testuser
```

![SMBClient](./screenshots/03_smbclient-attempt.png)

---

### 4. Failed Login Confirmation

```bash
smbclient -L //192.168.0.147 -u testuser
# returns NT_STATUS_LOGON_FAILURE
```

![Login Failed](./screenshots/04_smbclient-failed-login.png)

---

### 5. Scripted Brute-Force Loop

```bash
for i in {1..10}; do
  smbclient -L //192.168.0.147 -u testuser%"wrongpass" -m SMB2
done
```

![Loop](./screenshots/05_scripted-bruteforce.png)
![Loop Output](./screenshots/06_scripted-output.png)

---

## 📡 Splunk Detection

Splunk alert triggered based on EventCode 4625 (Failed Logon):

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

![Triggered Alerts](./screenshots/07_splunk-triggered-alerts.png)

---

## ✅ Success Criteria Met

✔️ Attack from Kali  
✔️ Logged by Windows (EventCode 4625)  
✔️ Forwarded by Universal Forwarder  
✔️ Indexed and searched by Splunk  
✔️ Alert triggered and visible in dashboard  

---

> 💡 This method can be adapted for other brute-force vectors: RDP, SSH, FTP, HTTP Auth.