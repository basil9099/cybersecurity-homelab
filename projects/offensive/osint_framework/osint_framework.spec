# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for OSINT Reconnaissance Framework
# Build: pyinstaller osint_framework.spec
# Output: dist/osint_framework.exe (standalone, no Python required)


a = Analysis(
    ['osint_framework.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('gui/templates/index.html', 'gui/templates'),
    ],
    hiddenimports=[
        # Conditional TOML import (Python <3.11 fallback)
        'tomllib',
        'tomli',
        # FastAPI / Pydantic
        'fastapi',
        'pydantic',
        'email_validator',
        'multipart',
        'python_multipart',
        # Uvicorn — plugin-based auto-detection requires explicit listing
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'uvicorn.lifespan.off',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='osint_framework',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
