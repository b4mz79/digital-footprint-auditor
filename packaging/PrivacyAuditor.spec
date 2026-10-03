from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

DEV_ARTIFACT_SUFFIXES = {".h", ".lib", ".pyx", ".pxi"}

STREAMLIT_OPTIONAL_ASSET_PREFIXES = (
    "PlotlyChart.",
    "DeckGlJsonChart.",
    "EChartsChart.",
    "GraphVizChart.",
    "cytoscape.",
    "mermaid.",
    "MermaidChart.",
    "ArrowVegaLiteChart.",
    "architectureDiagram-",
    "sequenceDiagram-",
    "swimlanes-",
    "c4Diagram-",
    "ganttDiagram-",
    "xychartDiagram-",
    "mindmap-definition-",
    "StreamlitSyntaxHighlighter.",
)

PIL_OPTIONAL_BINARIES = {
    "_webp.pyd",
    "_imagingft.pyd",
    "_imagingcms.pyd",
    "_imagingmath.pyd",
    "_imagingtk.pyd",
}

def _is_runtime_data(item) -> bool:
    return Path(str(item[0])).suffix.lower() not in DEV_ARTIFACT_SUFFIXES

def _is_unused_streamlit_asset(item) -> bool:
    source = Path(str(item[0]))
    if source.suffix.lower() not in {".js", ".css"}:
        return False
    return any(source.name.startswith(prefix) for prefix in STREAMLIT_OPTIONAL_ASSET_PREFIXES)

def _is_lxml_item(item) -> bool:
    source = Path(str(item[0]))
    normalized = str(source).replace("\\", "/").lower()
    return "/lxml/" in normalized or source.name.lower().startswith("lxml")


ROOT = Path.cwd()

holehe_hidden = collect_submodules("holehe.modules")

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
        "altair",
        "pyarrow.parquet",
        "pyarrow.parquet.core",
        "pyarrow._parquet",
        "pyarrow.dataset",
        "pyarrow._dataset",
        "pyarrow._dataset_orc",
        "pyarrow._dataset_parquet",
        "pyarrow._dataset_parquet_encryption",
        # Pass 9: AVIF support is not used by Privacy Auditor.
        "PIL.AvifImagePlugin",
        "PIL._avif",
        # Pass 10: unused Pillow optional native extensions.
        "PIL.WebPImagePlugin",
        "PIL._webp",
        "PIL.ImageFont",
        "PIL._imagingft",
        "PIL.ImageCms",
        "PIL._imagingcms",
        "PIL.ImageMath",
        "PIL._imagingmath",
        "PIL.ImageTk",
        "PIL._imagingtk",
        # Pass 12: lxml is not used by Privacy Auditor.
        "lxml",
        "lxml.etree",
        "lxml.html",
        "lxml.cssselect",
        ],
        noarchive=False,
)

before_datas = len(a.datas)
a.datas = [item for item in a.datas if _is_runtime_data(item)]
print(
    f"[Slimming Pass 4] Removed "
    f"{before_datas - len(a.datas)} development data files."
)

# Pass 9: Remove Pillow's AVIF native extension if collected by a hook.

before_pil_binaries = len(a.binaries)
a.binaries = [
    item
    for item in a.binaries
        if not Path(str(item[0])).name.lower().startswith("_avif.")
]
print(
    f"[Slimming Pass 9] Removed "
    f"{before_pil_binaries - len(a.binaries)} Pillow AVIF binaries."
)

# Pass 10: Remove Pillow optional native extensions that are not loaded

# by the application's tested runtime path.

PIL_OPTIONAL_BINARIES = {
    "_webp.pyd",
    "_imagingft.pyd",
    "_imagingcms.pyd",
    "_imagingmath.pyd",
    "_imagingtk.pyd",
}

before_optional_pil_binaries = len(a.binaries)
a.binaries = [
    item
    for item in a.binaries
        if Path(str(item[0])).name.lower() not in PIL_OPTIONAL_BINARIES
]
print(
    f"[Slimming Pass 10] Removed "
    f"{before_optional_pil_binaries - len(a.binaries)} optional Pillow binaries."
)

# Pass 11: Remove Streamlit frontend assets for chart/diagram features

# that are not used by Privacy Auditor.

before_streamlit_assets = len(a.datas)
removed_streamlit_assets = [
    item for item in a.datas if _is_unused_streamlit_asset(item)
]

a.datas = [
    item for item in a.datas if not _is_unused_streamlit_asset(item)
]

print(
    f"[Slimming Pass 11] Removed "
    f"{before_streamlit_assets - len(a.datas)} unused "
    f"Streamlit frontend assets."
)

for item in removed_streamlit_assets:
    print(f"  [Pass 11] {Path(str(item[0])).name}")

# Pass 12: Remove lxml binaries/data if the standard/custom hook

# still contributes them despite the Analysis exclusion.

before_lxml_binaries = len(a.binaries)
a.binaries = [
    item for item in a.binaries if not _is_lxml_item(item)
]
print(
    f"[Slimming Pass 12] Removed {before_lxml_binaries - len(a.binaries)} lxml binaries."
)

before_lxml_datas = len(a.datas)
a.datas = [
    item for item in a.datas if not _is_lxml_item(item)
]
print(
    f"[Slimming Pass 12] Removed {before_lxml_datas - len(a.datas)} lxml data files."
)

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
    name="PrivacyAuditor",
)