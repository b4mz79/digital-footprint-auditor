@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion

rem Always run relative to this script, not the caller's working directory.
cd /d "%~dp0" || (
    echo [ERROR] Tidak dapat berpindah ke direktori proyek.
    exit /b 1
)

set "RESET_MODE=false"
set "FULL_RESET_MODE=false"
set "NO_RUN=false"
set "INVALID_ARGS=false"
set "DOCKER_MODE="

rem Supported modes:
rem   run.bat
rem   run.bat reset
rem   run.bat full-reset
rem   run.bat reset-only
rem   run.bat full-reset-only
rem   run.bat docker-build
rem   run.bat docker-test
rem   run.bat docker-dev
for %%A in (%*) do (
    if /i "%%~A"=="docker-build" (
        set "DOCKER_MODE=build"
    ) else if /i "%%~A"=="docker-test" (
        set "DOCKER_MODE=test"
    ) else if /i "%%~A"=="docker-dev" (
        set "DOCKER_MODE=dev"
    ) else if /i "%%~A"=="reset" (
        set "RESET_MODE=true"
    ) else if /i "%%~A"=="full-reset" (
        set "RESET_MODE=true"
        set "FULL_RESET_MODE=true"
    ) else if /i "%%~A"=="reset-only" (
        set "RESET_MODE=true"
        set "NO_RUN=true"
    ) else if /i "%%~A"=="full-reset-only" (
        set "RESET_MODE=true"
        set "FULL_RESET_MODE=true"
        set "NO_RUN=true"
    ) else (
        echo [ERROR] Argumen tidak dikenal: %%~A
        set "INVALID_ARGS=true"
    )
)

if "%INVALID_ARGS%"=="true" (
    echo.
    echo Penggunaan: run.bat [reset^|full-reset^|reset-only^|full-reset-only^|docker-build^|docker-test^|docker-dev]
    exit /b 2
)

if not "%DOCKER_MODE%"=="" (
    if "%RESET_MODE%"=="true" (
        echo [ERROR] Mode Docker tidak dapat digabung dengan mode reset.
        exit /b 2
    )
    if /i "%DOCKER_MODE%"=="build" (
        call "%~dp0scripts\build-docker.bat"
        exit /b !ERRORLEVEL!
    )
    if /i "%DOCKER_MODE%"=="test" (
        call "%~dp0scripts\build-docker.bat" --test
        exit /b !ERRORLEVEL!
    )
    if /i "%DOCKER_MODE%"=="dev" (
        call "%~dp0scripts\build-docker.bat" --shell
        exit /b !ERRORLEVEL!
    )
)

if "%RESET_MODE%"=="true" (
    echo [INFO] Membersihkan cache proyek...

    if exist "log.txt" (
        del /q "log.txt" >nul 2>&1
        if exist "log.txt" (
            echo [WARN] Tidak dapat menghapus log.txt.
        ) else (
            echo [OK] log.txt dihapus.
        )
    )

    rem Exclude virtual environments, Git metadata, and packaging output.
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$root=(Get-Location).Path; Get-ChildItem -LiteralPath $root -Directory -Recurse -Force -Filter '__pycache__' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '[\x5c/](venv|\.venv|\.git|build|dist)[\x5c/]' } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }"
    if errorlevel 1 (
        echo [WARN] Pembersihan sebagian folder __pycache__ mungkin gagal.
    ) else (
        echo [OK] Cache Python proyek dibersihkan.
    )

    if "%FULL_RESET_MODE%"=="true" (
        for %%D in ("cache" ".pytest_cache" "build\PrivacyAuditor" "dist\PrivacyAuditor" "dist\installer") do (
            if exist "%%~D" (
                rd /s /q "%%~D" >nul 2>&1
                if exist "%%~D" (
                    echo [WARN] Tidak dapat menghapus %%~D.
                ) else (
                    echo [OK] %%~D dihapus.
                )
            )
        )
    )

    rem Reset intentionally targets the exact TCP port 8501.
    for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; Get-NetTCPConnection -State Listen -LocalPort 8501 | Select-Object -ExpandProperty OwningProcess -Unique"') do (
        echo [INFO] Menghentikan proses pada port 8501 ^(PID %%P^)...
        taskkill /PID %%P /T /F >nul 2>&1
        if errorlevel 1 (
            echo [WARN] Gagal menghentikan PID %%P.
        )
    )
)

if "%NO_RUN%"=="true" (
    echo [OK] Reset selesai; aplikasi tidak dijalankan.
    exit /b 0
)

if not exist "app.py" (
    echo [ERROR] app.py tidak ditemukan di direktori proyek.
    exit /b 1
)

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment tidak ditemukan: venv\Scripts\python.exe
    echo Buat environment dan install dependensi terlebih dahulu.
    exit /b 1
)

rem Use the venv interpreter explicitly; do not depend on PATH activation.
set "VENV_PYTHON=%CD%\venv\Scripts\python.exe"

for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; Get-NetTCPConnection -State Listen -LocalPort 8501 | Select-Object -ExpandProperty OwningProcess -Unique"') do (
    echo [WARN] Port 8501 sudah digunakan ^(PID %%P^).
    echo Buka http://localhost:8501 atau hentikan proses tersebut secara manual.
    exit /b 0
)

echo [INFO] Menjalankan Privacy Auditor melalui Streamlit pada port 8501...
"%VENV_PYTHON%" -m streamlit run app.py --server.address 127.0.0.1
set "APP_EXIT_CODE=%ERRORLEVEL%"
if not "%APP_EXIT_CODE%"=="0" (
    echo [ERROR] Streamlit berhenti dengan exit code %APP_EXIT_CODE%.
)
exit /b %APP_EXIT_CODE%
