from PyInstaller.utils.hooks import collect_all, copy_metadata


datas, binaries, hiddenimports = collect_all("streamlit")
datas += copy_metadata("streamlit")
