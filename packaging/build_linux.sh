#!/usr/bin/env bash
set -euo pipefail

# Jalankan dari root repository, terlepas dari direktori pemanggil.
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=============================================="
echo "Privacy Auditor - Linux Packaging"
echo "=============================================="

# 1. Validasi lingkungan virtual.
if [[ ! -x "venv/bin/python" ]]; then
    echo "[ERROR] venv tidak ditemukan."
    echo "Jalankan build dari project yang sudah memiliki venv."
    exit 1
fi

# Aktifkan virtual environment Linux.
source venv/bin/activate

# Pemeriksaan pra-build.
python packaging/check_packaging.py

# Samakan batas versi PyInstaller dengan build Windows.
python -m pip install --upgrade "pyinstaller>=6.20,<7"

# Verifikasi dependency yang dibutuhkan pada jalur packaging.
python -c "import holehe, trio, httpx, bs4; print('[OK] Embedded Holehe + HTTP/HTML dependencies available.')"

echo
echo "[1/4] Cleaning previous build..."
rm -rf dist/PrivacyAuditor
rm -f dist/holehe dist/LICENSE dist/README_EN.docx dist/README_ID.docx dist/THIRD_PARTY_NOTICES.docx

echo
echo "[2/4] Building PrivacyAuditor..."
python -m PyInstaller packaging/PrivacyAuditor.spec --noconfirm

echo
echo "[3/4] Build verification..."
if [[ ! -f "dist/PrivacyAuditor" ]]; then
    echo "[ERROR] Executable dist/PrivacyAuditor tidak ditemukan."
    exit 1
fi

# Salin berkas lisensi.
cp LICENSE dist/PrivacyAuditor.LICENSE.tmp
mv dist/PrivacyAuditor.LICENSE.tmp dist/LICENSE

# Buat dokumentasi jika Pandoc tersedia.
if command -v pandoc >/dev/null 2>&1; then
    echo "[INFO] Mengonversi dokumentasi menggunakan Pandoc sistem..."
    pandoc packaging/THIRD_PARTY_NOTICES.md -o dist/THIRD_PARTY_NOTICES.docx --quiet
    pandoc README.md -o dist/README_EN.docx --quiet
    pandoc README_ID.md -o dist/README_ID.docx --quiet
else
    echo "[WARNING] Pandoc tidak ditemukan. Dokumen .docx tidak dapat dibuat."
    echo "Anda bisa menginstalnya lewat package manager distribusi Linux."
fi

# Validasi akhir.
if [[ ! -f "dist/PrivacyAuditor" || ! -f "dist/LICENSE" ]]; then
    echo "[ERROR] Executable atau LICENSE tidak ditemukan setelah build."
    exit 1
fi

if [[ -f "dist/holehe" ]]; then
    echo "[ERROR] holehe masih terbawa ke distribution."
    exit 1
fi

if find dist -type f -name 'primp.so' -print -quit | grep -q .; then
    echo "[ERROR] primp.so masih terbawa ke distribution."
    exit 1
fi

echo
echo "=============================================="
echo "[OK] Linux Packaging build selesai."
echo "=============================================="
echo "Catatan: executable berada di dist/PrivacyAuditor"

SIZE_MB="$(du -sm dist/PrivacyAuditor | cut -f1)"
echo "Bundle size: ${SIZE_MB} MB"
echo
