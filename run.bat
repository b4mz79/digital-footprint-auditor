@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion


:: Pindah ke direktori tempat script ini berada
cd /d "%~dp0"

:: Parsing parameter untuk mengecek perintah 'reset' dan 'web'
set "RESET_MODE=false"
set "FULL_RESET_MODE=false"
set "NO_RUN=false"
set "ARGS="

for %%a in (%*) do (
    if /i "%%~a"=="reset" (
        set "RESET_MODE=true"
    ) else if /i "%%~a"=="full-reset" (
	    set "RESET_MODE=true"
        set "FULL_RESET_MODE=true"
    ) else if /i "%%~a"=="reset-only" (
	    set "RESET_MODE=true"
		set "NO_RUN=true"
    ) else if /i "%%~a"=="full-reset-only" (
	    set "RESET_MODE=true"
		set "FULL_RESET_MODE=true"
		set "NO_RUN=true"
    ) else (
        set "ARGS=!ARGS! %%~a"
    )
)

if "%NO_RUN%"=="false" (
	:: Cek & aktifkan virtual environment (Windows path)
	if exist "venv\Scripts\activate.bat" (
		echo 🔌 Mengaktifkan virtual environment ^(venv^)...
		call venv\Scripts\activate.bat
	) else (
		echo ❌ Virtual environment 'venv\Scripts\activate.bat' tidak ditemukan!
		exit /b 1
	)
)

:: Eksekusi reset jika parameter terdeteksi
if "%RESET_MODE%"=="true" (
    echo 🧹 Parameter 'reset' terdeteksi! Membersihkan cache...
	del log.txt
    for /d /r . %%d in (__pycache__) do (
        if exist "%%d" rd /s /q "%%d" 2>nul
    )
    echo ✅ Folder __pycache__ berhasil dibersihkan!
	
	if "%FULL_RESET_MODE%"=="true" (
		for /d /r . %%d in (cache) do (
			if exist "%%d" rd /s /q "%%d" 2>nul
		)
		echo ✅ Folder cache berhasil dibersihkan!
		for /d /r . %%d in (.pytest_cache) do (
			if exist "%%d" rd /s /q "%%d" 2>nul
		)
		echo ✅ Folder Pytest cache berhasil dibersihkan!
	)
	
    :: Jika Streamlit lagi jalan di port 8501, matikan prosesnya
    set "KILLED=false"
    for /f "tokens=5" %%p in ('netstat -aon ^| findstr :8501 ^| findstr LISTENING 2^>nul') do (
        if "!KILLED!"=="false" (
            echo 🛑 Mematikan proses yang sedang berjalan di port 8501 ^(PID: %%p^)...
            taskkill /f /pid %%p >nul 2>&1
            set "KILLED=true"
        )
    )
    if "!KILLED!"=="true" (
        timeout /t 2 /nobreak >nul
        echo ✅ Proses lama di port 8501 berhasil di-kill!
    )
)

if "%NO_RUN%"=="false" (
	:: Eksekusi aplikasi berdasarkan mode
	netstat -aon | findstr :8501 | findstr LISTENING >nul 2>&1
	if !errorlevel! neq 0 (
		echo 🌐 Menjalankan Web UI via Streamlit di ^(port 8501^)...
		:: streamlit run app.py > log.txt 2>&1
		streamlit run app.py
	) else (
		echo ⚠️ Server Web UI di port 8501 sudah berjalan!
		echo 🌐 Akses via browser: http://localhost:8501
	)
)