from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

DEV_ARTIFACT_SUFFIXES = {".h", ".lib", ".pyx", ".pxi"}

def _is_runtime_data(item) -> bool:
    return Path(str(item[0])).suffix.lower() not in DEV_ARTIFACT_SUFFIXES

ROOT = Path.cwd()

#streamlit_datas, streamlit_binaries, streamlit_hidden = collect_all("streamlit")
holehe_hidden = collect_submodules("holehe.modules")

#datas = list(streamlit_datas)
#binaries = list(streamlit_binaries)
#hiddenimports = list(streamlit_hidden)
hiddenimports = []
datas = []
binaries = []
hiddenimports += holehe_hidden

datas += [
    (str(ROOT / "app.py"), "."),
    (str(ROOT / ".env.example"), "."),
    (str(ROOT / "prompts"), "prompts"),
]

hiddenimports += [
    "services.pipeline",
    "streamlit.web.cli",
    "holehe",
    "holehe.core",
    "holehe.localuseragent",
    "holehe.instruments",
    "holehe.modules",
]

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[str(ROOT / "packaging" / "hooks")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "trio_websocket",
        "ddgs",
        "primp",
    ],
    noarchive=False,
)

# Remove build-time headers/import libraries/Cython sources from every hook.
# These files are useful for development but are not required by the packaged runtime.
before_datas = len(a.datas)
a.datas = [item for item in a.datas if _is_runtime_data(item)]
print(f"[Slimming Pass 4] Removed {before_datas - len(a.datas)} development data files.")

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PrivacyAuditor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[
        "python312.dll",
        "libcrypto-3.dll",
        "_rust.pyd",
    ],
    name="PrivacyAuditor",
)
