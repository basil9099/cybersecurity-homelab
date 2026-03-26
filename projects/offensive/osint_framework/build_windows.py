#!/usr/bin/env python3
"""
Build helper — compile OSINT Framework into a standalone Windows executable.

Usage:
    python build_windows.py           # build the exe
    python build_windows.py --clean   # remove build artifacts first

Requires:
    pip install -r requirements.txt pyinstaller

Output:
    dist/osint_framework.exe
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 10)
PROJECT_DIR = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Build OSINT Framework Windows executable")
    parser.add_argument("--clean", action="store_true",
                        help="Remove build/ and dist/ directories before building")
    args = parser.parse_args()

    # Check Python version
    if sys.version_info < MIN_PYTHON:
        print(f"[!] Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required "
              f"(found {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)

    # Check PyInstaller is available
    try:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            capture_output=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[*] PyInstaller not found — installing ...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyinstaller"],
            check=True,
        )

    # Clean if requested
    if args.clean:
        for d in ("build", "dist"):
            path = PROJECT_DIR / d
            if path.exists():
                print(f"[*] Removing {path}")
                shutil.rmtree(path)

    # Build
    spec_file = PROJECT_DIR / "osint_framework.spec"
    if not spec_file.exists():
        print(f"[!] Spec file not found: {spec_file}")
        sys.exit(1)

    print(f"[*] Building from {spec_file} ...")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", str(spec_file)],
        cwd=str(PROJECT_DIR),
    )
    if result.returncode != 0:
        print("[!] Build failed.")
        sys.exit(1)

    exe_path = PROJECT_DIR / "dist" / "osint_framework.exe"
    if exe_path.exists():
        print(f"\n[+] Build successful: {exe_path}")
        print(f"    Size: {exe_path.stat().st_size / 1024 / 1024:.1f} MB")
    else:
        # On non-Windows, the output has no .exe extension
        alt = PROJECT_DIR / "dist" / "osint_framework"
        if alt.exists():
            print(f"\n[+] Build successful: {alt}")
            print(f"    Size: {alt.stat().st_size / 1024 / 1024:.1f} MB")
        else:
            print("[!] Build completed but executable not found in dist/")
            sys.exit(1)


if __name__ == "__main__":
    main()
