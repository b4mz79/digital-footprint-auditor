# Workflow Docker untuk Contributor

Workflow ini menyediakan image untuk menjalankan aplikasi secara lokal dan image test terpisah yang bersifat disposable. Konfigurasi ini tidak mengubah logika runtime aplikasi atau mengaktifkan fitur opsional.

## Persyaratan

- Docker Desktop (Windows/macOS) atau Docker Engine dengan Docker Compose v2.24 atau lebih baru (Linux).
- Git.

## 1. Siapkan konfigurasi lokal

Dari root repository, salin file contoh environment:

```bash
cp .env.example .env
```

Isi `PII_PEPPER_KEY` dengan secret acak minimal 32 karakter. Contoh, jika Python tersedia di komputer:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Konfigurasikan hanya provider yang ingin digunakan. Image Docker tidak menyertakan file `.env`, API key, kredensial Gmail, cache key, atau cache hasil scan lokal.

Di Windows PowerShell, gunakan `Copy-Item .env.example .env` jika lebih sesuai.

## 2. Build image runtime

Linux/macOS:

```bash
./scripts/build-docker.sh
```

Windows:

```powershell
.\scripts\build-docker.bat
```

Tag default image adalah `privacy-auditor:dev`. Untuk build ulang tanpa memakai layer cache, tambahkan `--no-cache`. Untuk memilih tag lain, gunakan `--tag privacy-auditor:local`.

## 3. Masuk ke development shell contributor

Linux/macOS/WSL:

```bash
./scripts/build-docker.sh --shell
```

Windows PowerShell atau Command Prompt:

```powershell
.\scripts\build-docker.bat --shell
```

Script membangun image `devshell` (berisi dependency dari `requirements.txt` dan `requirements-test.txt`), lalu membuka Bash interaktif di direktori `/app`. Repository di-mount langsung dari host, sehingga perubahan file di dalam container tersimpan pada checkout host. Setelah selesai, jalankan `exit`; container sementara akan dihapus otomatis.

Contoh perintah di dalam shell:

```bash
python --version
python -m pytest -q
python -m compileall -q .
```

Gunakan shell ini untuk development contributor, debugging, dan test tanpa perlu memasang dependency Python proyek langsung di WSL. Shell memakai `PII_PEPPER_KEY` tetap yang khusus untuk test; **jangan gunakan development shell ini untuk data scan nyata**. File `.env` dari host tidak dimuat secara otomatis.

Untuk membangun ulang image development tanpa cache, tambahkan `--no-cache`:

```bash
./scripts/build-docker.sh --shell --no-cache
```

## 4. Jalankan aplikasi


```bash
docker compose up --build
```

Buka [http://localhost:8501](http://localhost:8501). Secara default, Compose hanya mempublikasikan port ke localhost, bukan ke jaringan LAN. Direktori source di-mount ke container agar contributor dapat mengedit kode dari host. Restart service setelah perubahan yang memerlukan proses dimulai ulang.

Hentikan service dengan `Ctrl+C` atau jalankan:

```bash
docker compose down
```

Named volume `privacy-auditor-data` menyimpan cache dan cache encryption key di luar source tree. Perintah `docker compose down -v` juga menghapus volume beserta isinya; gunakan hanya jika memang ingin menghapus cache persisten dan key container.

## 5. Jalankan test di Docker

Linux/macOS:

```bash
./scripts/build-docker.sh --test
```

Windows:

```powershell
.\scripts\build-docker.bat --test
```

Script membangun target `test` lalu menjalankan `pytest -q` di container disposable. Target test menggunakan `PII_PEPPER_KEY` tetap yang hanya untuk test; jangan pernah gunakan key ini untuk data scan nyata. Test tidak memuat file `.env` host dan tidak membutuhkan API key provider.

## Ollama lokal

Saat aplikasi berjalan di Docker, `127.0.0.1` menunjuk ke container itu sendiri. Compose menggunakan default `OLLAMA_HOST=http://host.docker.internal:11434` agar container dapat mengakses Ollama yang berjalan di host. Jika `OLLAMA_HOST` diisi secara eksplisit dalam `.env`, gunakan hostname tersebut, bukan alamat loopback container.

## Catatan

- Image runtime berjalan sebagai user non-root.
- Image membuka Streamlit pada port container 8501, sedangkan Compose hanya mempublikasikannya pada loopback host.
- Provider scan eksternal tetap melakukan request jaringan jika dikonfigurasi; Docker tidak menjadikan request tersebut lokal.
- Gunakan aplikasi hanya untuk data milik sendiri atau data yang auditnya telah diotorisasi.
- Jangan commit `.env`, isi cache, atau artefak scan privat lainnya.
