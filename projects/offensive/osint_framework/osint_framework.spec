# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['osint_framework.py'],
    pathex=[],
    binaries=[],
    datas=[('gui/templates/index.html', 'gui/templates')],
    hiddenimports=[
        'modules.whois_recon',
        'modules.dns_recon',
        'modules.social_recon',
        'modules.breach_check',
        'modules.search_recon',
        'modules.reporter',
        'gui.app',
        'uvicorn.logging',
        'uvicorn.loops.auto',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan.on',
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
