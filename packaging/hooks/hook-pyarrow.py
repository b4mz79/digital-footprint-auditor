# ------------------------------------------------------------------
# Privacy Auditor - minimal PyArrow runtime hook for PyInstaller.
#
# Streamlit requires PyArrow for dataframe serialization, but the
# standard PyInstaller hook collects every PyArrow submodule, data
# file, and shared library. That also pulls optional components
# such as Flight, Parquet, Dataset, and Substrait into the bundle.
#
# Keep only the Python modules needed by Streamlit's dataframe path.
# PyInstaller's normal binary dependency analysis will then collect
# only the native libraries actually required by those modules.
# ------------------------------------------------------------------

hiddenimports = [
    "pyarrow.lib",
    "pyarrow.pandas_compat",
    "pyarrow.ipc",
    "pyarrow.types",
    "pyarrow.util",
    "pyarrow.vendored.version",
]

datas = []
binaries = []