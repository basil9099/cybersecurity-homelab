# 🪤 Simple Python Honeypot (Port 8080)

A lightweight TCP honeypot script written in Python, designed for use in a home cybersecurity lab.

---

## 📂 Project Structure

```
honeypot/
├── honeypot.py
├── honeypot.log
└── screenshots/
    ├── 01_script-code.png
    ├── 02_script-running.png
    ├── 03_netcat-connection.png
    └── 04_output-verified.png
```

---

## ⚙️ How It Works

- Listens for incoming connections on **port 8080**
- Accepts and logs connection info (IP, port, data sent)
- Outputs to both console and `honeypot.log`

---

## 🚀 Running the Honeypot

```bash
python3 honeypot.py
```

Use `nc` to simulate an attacker:
```bash
nc localhost 8080
hello
```

✅ Output will be printed and saved:
```
[2025-08-04 16:53:48] Connection from 127.0.0.1:37576
Data: hello
```

---

## 🔐 Notes

- Port can be changed by modifying `LISTEN_PORT` in the script.
- Use with firewall rules to safely trap unauthorized scans or connections.

---

📸 See the `screenshots/` folder for visual proof of concept and execution.