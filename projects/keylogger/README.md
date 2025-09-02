# 🔐 USB-Based Keylogger (Educational Red Team Tool)

This project is a **Python-based keylogger** that runs from a USB drive and captures both **keystrokes** and **screenshots** silently in the background. It is designed for ethical cybersecurity testing, malware analysis labs, and red team simulations.

> ⚠️ **Legal Disclaimer**  
> This tool is provided strictly for **educational purposes** and **authorized testing environments** only. Do not use this keylogger on systems you do not own or have explicit permission to test. Unauthorized use may violate computer misuse laws and result in legal consequences.

---

## 🧩 Features

- ✅ Logs all keystrokes to a `logs/` folder  
- 🖼️ Captures screenshots every 30 seconds into `screenshots/`  
- 🛠️ Built with Python 3.12 for full compatibility  
- 🧳 Designed to run directly from a USB drive  
- 🕵️‍♂️ Compiles into a silent `.exe` using PyInstaller (`--noconsole`)

---

## 📁 Output Structure

When run from USB (e.g., `E:\`):

```
E:
├── keylogger.exe
├── logs
│   └── keylog_YYYY-MM-DD_HH-MM-SS.txt
└── screenshots
    └── screenshot_YYYY-MM-DD_HH-MM-SS.png
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/basil9099/cybersecurity-homelab.git
cd projects/keylogger
```

### 2. Set Up Environment (Python 3.12 Required)

Install Python 3.12 from [python.org](https://www.python.org/downloads/), then install dependencies:

```bash
pip install pynput pyautogui pillow
```

### 3. Build the Executable (Optional)

```bash
py -3.12 -m pyinstaller --noconsole --onefile keylogger.py
```

Copy `dist/keylogger.exe` to the USB root directory.

---

## 🧪 Testing

1. Plug in USB and run `keylogger.exe`
2. Wait ~30 seconds and type some keys
3. Press `Esc` to stop
4. Check `logs/` and `screenshots/` folders on the USB

---

## 🛡️ Ethical Use Cases

- ✔️ Red team exercises  
- ✔️ Cybersecurity labs or homelabs  
- ✔️ Malware behavior simulations  
- ❌ Never use on live production or personal systems without consent

---

## 📸 Sample Output

You can find sample logs and screenshots in the `sample_output/` folder.

---

## 📄 License

MIT License — see [LICENSE](../../LICENSE) for more information.

---

## 🙏 Credits

Built by **[Your Name or GitHub Handle]**  
Inspired by real-world TTPs for educational replication in safe environments.
