#!bin/bash

# Menghentikan skrip jika terjadi error
set -e

# Pindah ke direktori utama proyek (naik satu tingkat dari folder tempat skrip ini berada)
cd $(dirname $0)..

echo ==============================================
echo Privacy Auditor - Linux Packaging
echo ==============================================
echo 

# 1. Validasi Lingkungan Virtual (Venv)
if [ ! -f venv/bin/python ]; then
    echo [ERROR] venv tidak ditemukan.
    echo Jalankan build dari project yang sudah memiliki venv.
    exit 1
fi

# Mengaktifkan virtual environment Linux
source venv/bin/activate

# Jalankan pengecekan pra-build
python packaging/check_packaging.py

# Memastikan PyInstaller versi yang tepat terpasang
python -m pip install --upgrade pyinstaller=6.20,7

# Verifikasi dependensi internal
if ! python -c import holehe, trio, httpx, bs4; print('[OK] Embedded Holehe + HTTPHTML dependencies available.'); then
    echo [ERROR] Package yang diperlukan tidak terpasang di venv build.
    exit 1
fi

echo 
echo [14] Cleaning previous build...
rm -rf dist/PrivacyAuditor
rm -f dist/holehe
rm -f dist/LICENSE
rm -f dist/README_EN.docx
rm -f dist/README_ID.docx

echo 
echo [12] Building PrivacyAuditor...
# Menjalankan PyInstaller dengan file spec Linux yang sudah diperbaiki sebelumnya
python -m PyInstaller PrivacyAuditor.spec --noconfirm

echo 
echo [22] Build verification...
# Di Linux, hasil build tidak menggunakan ekstensi .exe
if [ ! -f dist/PrivacyAuditor ]; then
    echo [ERROR] Executable PrivacyAuditor tidak ditemukan.
    exit 1
fi

# Salin berkas lisensi
cp LICENSE dist

# Periksa apakah Pandoc terinstal di sistem Ubuntu untuk konversi dokumen
if command -v pandoc & devnull; then
    echo [INFO] Mengonversi dokumentasi menggunakan Pandoc sistem...
    pandoc packaging/THIRD_PARTY_NOTICES.md -o dist/THIRD_PARTY_NOTICES.docx --quiet  true
    pandoc README.md -o dist/README_EN.docx --quiet  true
    pandoc README_ID.md -o dist/README_ID.docx --quiet  true
else
    echo [WARNING] Pandoc tidak ditemukan. Dokumen .docx tidak dapat dibuat.
    echo Anda bisa menginstalnya lewat sudo apt install pandoc
fi

# 2. Validasi Akhir Struktur Output setelah Build
if [ ! -f dist/PrivacyAuditor ]; then
    echo [ERROR] Executable PrivacyAuditor tidak ditemukan.
    exit 1
fi

if [ ! -f dist/LICENSE ]; then
    echo [ERROR] LICENSE tidak ditemukan.
    exit 1
fi

# Validasi modul yang harus dibersihkan (slimming check)
if [ -f dist/holehe ]; then
    echo [ERROR] holehe masih terbawa ke distribution.
    exit 1
fi

# Di Linux, ekstensinya adalah .so bukan .pyd
if find dist -name primp.so  grep -q .; then
    echo [ERROR] primp.so masih terbawa ke distribution.
    exit 1
fi

echo 
echo ==============================================
echo [OK] Linux Packaging build selesai.
echo ==============================================
echo Catatan File binary tunggal berada di dist/PrivacyAuditor

# Menghitung total ukuran bundle file output dalam Megabytes (MB)
if command -v du & devnull; then
    SIZE_MB=$(du -sm dist/PrivacyAuditor  cut -f1)
    echo Bundle size ${SIZE_MB}.00 MB
fi

echo 
