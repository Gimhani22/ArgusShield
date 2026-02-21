# -*- mode: python ; coding: utf-8 -*-
import os

# Path to the bin folder containing the background service
# SPECPATH is the directory containing this spec file (ArgusShield-Dashboard)
bin_folder = os.path.join(SPECPATH, 'bin')

a = Analysis(
    [os.path.join('src', 'ArgusShield.py')],
    pathex=[],
    binaries=[],
    datas=[
        # Include the bin folder with ArgusShieldService.exe
        (bin_folder, 'bin'),
    ],
    hiddenimports=[],
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
    name='ArgusShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
