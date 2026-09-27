#!/bin/bash

# Pindah ke direktori tempat script ini berada
cd "$(dirname "$0")"

# Cek & aktifkan virtual environment (Linux/macOS path)
if [ -f "venv/bin/activate" ]; then
    echo "🔌 Mengaktifkan virtual environment (venv)..."
    source venv/bin/activate
else
    echo "❌ Virtual environment 'venv/bin/activate' tidak ditemukan!"
    exit 1
fi

# Parsing parameter untuk mengecek perintah 'reset'
RESET_MODE=false
ARGS=""
for arg in "$@"; do
    if [ "$arg" = "reset" ]; then
        RESET_MODE=true
    else
        ARGS="\(ARGS\)arg"
    fi
done

# Eksekusi reset jika parameter 'reset' terdeteksi
if [ "$RESET_MODE" = "true" ]; then
    echo "🧹 Parameter 'reset' terdeteksi! Membersihkan cache..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
    echo "✅ Folder __pycache__ berhasil dibersihkan!"

    # Matikan proses yang sedang berjalan di port 8501 jika ada
    if command -v lsof &> /dev/null && lsof -i :8501 >/dev/null 2>&1; then
        echo "🛑 Mematikan proses yang sedang berjalan di port 8501..."
        kill -9 $(lsof -t -i:8501) 2>/dev/null
        sleep 2
        echo "✅ Proses lama di port 8501 berhasil di-kill!"
    elif command -v fuser &> /dev/null; then
        echo "🛑 Mematikan proses di port 8501 menggunakan fuser..."
        fuser -k 8501/tcp >/dev/null 2>&1
        sleep 2
    fi
fi

# Cek apakah port 8501 sudah digunakan
PORT_IN_USE=false
if command -v lsof &> /dev/null; then
    if lsof -i :8501 >/dev/null 2>&1; then
        PORT_IN_USE=true
    fi
elif command -v nc &> /dev/null; then
    if nc -z localhost 8501 2>/dev/null; then
        PORT_IN_USE=true
    fi
fi

# Jalankan aplikasi Streamlit
if [ "$PORT_IN_USE" = false ]; then
    echo "🌐 Menjalankan Web UI via Streamlit (port 8501)..."
    streamlit run app.py
else
    echo "⚠️ Server Web UI di port 8501 sudah berjalan!"
    echo "🌐 Akses via browser: http://localhost:8501"
fi