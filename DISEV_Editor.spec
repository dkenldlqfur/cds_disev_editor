# -*- mode: python ; coding: utf-8 -*-
import os
import json

_project_root = os.path.abspath(SPECPATH)
with open(os.path.join(_project_root, 'Resources', 'data', 'app_config.json'), encoding='utf-8') as _config_file:
    _app_version = json.load(_config_file)['version']

a = Analysis(
    [os.path.join(_project_root, 'DISEV_Editor.pyw')],
    pathex=[_project_root],
    binaries=[],
    datas=[(os.path.join(_project_root, 'Resources'), 'Resources')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

splash = Splash(
    os.path.join(_project_root, 'Resources', 'splash.jpg'),
    binaries=a.binaries,
    datas=a.datas,
    text_pos=None,
    text_size=12,
    minify_script=True,
    always_on_top=True,
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    splash,
    splash.binaries,
    [],
    name='DISEV_Editor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(_project_root, 'Resources', 'Icon.ico')],
)
