# USB-Based Keylogger (Educational Red Team Tool)

This project is a Python-based keylogger that runs from a USB drive and captures both keystrokes and screenshots silently in the background. It is designed for ethical cybersecurity testing, malware analysis labs, and red team simulations.

> **Legal Disclaimer**
> This tool is provided strictly for educational purposes and authorized testing environments only. Do not use this keylogger on systems you do not own or have explicit permission to test. Unauthorized use may violate computer misuse laws and result in legal consequences.

---

## Features

- Logs all keystrokes to a `logs/` folder
- Captures screenshots every 30 seconds into `screenshots/`
- Built with Python 3.12 for full compatibility
- Designed to run directly from a USB drive
- Compiles into a silent `.exe` using PyInstaller (`--noconsole`)

---

## Output Structure

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

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/basil19099/cybersecurity-homelab.git
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

## Testing

1. Plug in the USB drive and run `keylogger.exe`
2. Wait approximately 30 seconds and type some keys
3. Press `Esc` to stop
4. Review the `logs/` and `screenshots/` folders on the USB

---

## Ethical Use Cases

- Red team exercises
- Cybersecurity labs and homelabs
- Malware behavior simulations

**Note:** Never use this tool on live production or personal systems without explicit written consent from the system owner.

---

## Sample Output

Sample logs and screenshots can be found in the `sample_output/` folder.

---

## License

MIT License — see [LICENSE](../../LICENSE) for more information.
