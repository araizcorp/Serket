# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.hooks import collect_all

datas = []
hiddenimports = ['Crypto.Hash.MD4', 'jaraco', 'jaraco.text', 'jaraco.context', 'jaraco.functools', 'more_itertools']
datas += collect_data_files('serket')
hiddenimports += collect_submodules('serket')

# Optional native window (--gui): pywebview + pythonnet WebView2 backend.
try:
    webview_datas, webview_binaries, webview_hidden = collect_all('webview')
    datas += webview_datas
    hiddenimports += webview_hidden + ['webview.platforms.winforms', 'clr', 'clr_loader']
except Exception:
    pass


a = Analysis(
    ['serket.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
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
    name='serket',
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
