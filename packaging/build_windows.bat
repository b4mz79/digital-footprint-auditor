@echo off
setlocal

cd /d "%~dp0.."

echo ==============================================
echo Privacy Auditor - Windows Packaging
echo ==============================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] venv tidak ditemukan.
    echo Jalankan build dari project yang sudah memiliki venv.
    exit /b 1
)

call venv\Scripts\activate.bat
python packaging\check_packaging.py
if errorlevel 1 exit /b 1
python -m pip install --upgrade "pyinstaller>=6.20,<7"
python -c "import holehe, trio, httpx, bs4; print('[OK] Embedded Holehe + HTTP/HTML dependencies available.')"
if errorlevel 1 (
    echo [ERROR] Package yang diperlukan tidak terpasang di venv build.
    exit /b 1
)

echo.
echo [1/4] Cleaning previous build...
if exist dist\PrivacyAuditor rmdir /s /q dist\PrivacyAuditor
if exist dist\holehe.exe del /q dist\holehe.exe
if exist dist\LICENSE del /q dist\LICENSE
if exist dist\README_EN.docx del /q dist\README_EN.docx
if exist dist\README_ID.docx del /q dist\README_ID.docx

echo.
echo [1/2] Building PrivacyAuditor...
python -m PyInstaller packaging\PrivacyAuditor.spec --noconfirm
if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build gagal.
    exit /b 1
)

echo.
echo [2/2] Build verification...
if not exist "dist\PrivacyAuditor\PrivacyAuditor.exe" (
    echo [ERROR] PrivacyAuditor.exe tidak ditemukan.
    exit /b 1
)

copy LICENSE dist\PrivacyAuditor\
packaging\pandoc\pandoc.exe packaging\THIRD_PARTY_NOTICES.md -o dist\PrivacyAuditor\THIRD_PARTY_NOTICES.docx --quiet
packaging\pandoc\pandoc.exe README.md -o dist\PrivacyAuditor\README_EN.docx --quiet
packaging\pandoc\pandoc.exe README_ID.md -o dist\PrivacyAuditor\README_ID.docx --quiet

if not exist "dist\PrivacyAuditor\PrivacyAuditor.exe" (
    echo [ERROR] PrivacyAuditor.exe tidak ditemukan.
    exit /b 1
)

if not exist "dist\PrivacyAuditor\LICENSE" (
    echo [ERROR] LICENSE tidak ditemukan.
    exit /b 1
)

if not exist "dist\PrivacyAuditor\THIRD_PARTY_NOTICES.docx" (
    echo [ERROR] THIRD_PARTY_NOTICES.docx tidak ditemukan.
    exit /b 1
)

if not exist "dist\PrivacyAuditor\README_EN.docx" (
    echo [ERROR] README_EN.docx tidak ditemukan.
    exit /b 1
)

if not exist "dist\PrivacyAuditor\README_ID.docx" (
    echo [ERROR] README_ID.docx tidak ditemukan.
    exit /b 1
)

if exist "dist\PrivacyAuditor\holehe.exe" (
    echo [ERROR] holehe.exe masih terbawa ke distribution.
    exit /b 1
)

if exist "dist\PrivacyAuditor\_internal\primp\primp.pyd" (
    echo [ERROR] primp.pyd masih terbawa ke distribution.
    exit /b 1
)

copy LICENSE dist\PrivacyAuditor\
packaging\pandoc\pandoc.exe packaging\THIRD_PARTY_NOTICES.md -o dist\PrivacyAuditor\THIRD_PARTY_NOTICES.docx --quiet
packaging\pandoc\pandoc.exe README.md -o dist\PrivacyAuditor\README_EN.docx --quiet
packaging\pandoc\pandoc.exe README_ID.md -o dist\PrivacyAuditor\README_ID.docx --quiet

echo.
echo ==============================================
echo [OK] Windows Packaging build selesai.
echo ==============================================
echo Installer build is separate:
echo     ISCC.exe packaging\installer\PrivacyAuditor.iss
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='dist\PrivacyAuditor'; $s=(Get-ChildItem $p -Recurse -File | Measure-Object Length -Sum).Sum; Write-Host ('Bundle size: {0:N2} MB' -f ($s/1MB))"

echo.
endlocal
