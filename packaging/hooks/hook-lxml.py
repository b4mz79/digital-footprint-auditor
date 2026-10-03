from PyInstaller.utils.hooks import collect_data_files

hiddenimports = [
    "lxml",
    "lxml.etree",
    "lxml.html",
]

datas = collect_data_files("lxml")