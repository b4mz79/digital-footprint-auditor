# 🔍 Digital Footprint & OSINT Data Breach Auditor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)

**Language / Bahasa:** [English](README.md) | [Bahasa Indonesia](README_ID.md)

Digital Footprint & OSINT Data Breach Auditor adalah aplikasi Python dan Streamlit untuk meninjau jejak digital seseorang melalui input email, nomor telepon, OSINT, dan pencarian breach yang dilakukan dengan persetujuan atau otorisasi yang sesuai. Aplikasi menggabungkan bukti layanan yang terdeteksi dengan bukti kontekstual opsional dari publikasi keamanan serta analisis risiko privasi berbantuan AI. Aplikasi juga dapat menyusun draf **Data Subject Request (DSR)** yang harus ditinjau subjek data sebelum dikirim ke pengendali data.

Aplikasi ditujukan untuk audit privasi pribadi, riset defensif yang berizin, dan tujuan edukasi. Aplikasi tidak menjamin semua akun atau kebocoran akan ditemukan.

---

## ✨ Fitur Utama

- **Gmail IMAP Scanner** — mengidentifikasi layanan dari email pendaftaran, konfirmasi, dan pesan terkait yang cocok. Pemindaian Gmail memerlukan App Password jika diaktifkan.
- **OSINT Account Checker** — menggunakan Holehe untuk memeriksa sinyal keberadaan akun pada layanan yang didukung.
- **Pencarian breach multi-engine** — dapat menggunakan BreachDirectory (RapidAPI), Have I Been Pwned (HIBP), Google Custom Search, fallback pencarian Google/Bing/DuckDuckGo, Tavily, serta instance SearXNG yang dikonfigurasi secara opsional. Ketersediaan provider bergantung pada konfigurasi dan batas layanan eksternal.
- **Normalisasi nomor telepon** — menghasilkan variasi format nasional dan internasional yang dibatasi berdasarkan region konfigurasi.
- **Normalisasi evidence dan provenance** — menyimpan observasi pemindaian sebagai evidence terstruktur dengan informasi sumber dan karakteristik evidence untuk ditinjau lebih lanjut.
- **Enrichment opsional dari publikasi keamanan** — jika diaktifkan dan dikonfigurasi dengan API key Firecrawl, aplikasi mencari materi kontekstual publikasi keamanan berdasarkan domain yang telah dinormalisasi. Evidence kontekstual ini bukan bukti bahwa akun pengguna atau domain tersebut telah dibobol.
- **Verifikasi URL evidence** — memeriksa aksesibilitas URL yang sudah ada dalam record evidence. Ini bukan audit keamanan terhadap situs atau domain tujuan.
- **Analisis risiko privasi berbantuan AI** — memvalidasi output model dan menerapkan pengaman deterministik berbasis evidence. Alur provider dapat mencakup Google Gemini, Groq, OpenAI, dan Ollama lokal; urutan provider dan mode lokal-saja dapat dikonfigurasi.
- **Draf Data Subject Request (DSR)** — menghasilkan draf permintaan yang dapat diedit; pengguna perlu memeriksa fakta, dasar hukum, dan penerima sebelum mengirimkannya.
- **Cache lokal terenkripsi dan identitas cache berbasis tenant** — mengurangi permintaan berulang sekaligus memisahkan identitas cache tenant yang dikonfigurasi.
- **Runtime Add-On** — mendukung ekstensi opsional berbasis manifest. Lihat [Panduan Teknis Add-On](docs/ADDON_TECH_GUIDE_ID.md) dan [sample Add-On](addons/just-sample/).

## 🔐 Privasi dan Batasan

- Gunakan aplikasi hanya terhadap data milik sendiri atau data yang auditnya telah diotorisasi secara eksplisit.
- Simpan kredensial dalam file `.env` lokal. Jangan pernah commit API key, kredensial Gmail, atau rahasia lainnya.
- Hasil scan bergantung pada cakupan provider, indeks pencarian, rate limit, dan kredensial yang tersedia. Scan yang berhasil tanpa temuan **tidak** membuktikan bahwa tidak ada exposure.
- Artikel keamanan kontekstual dapat membahas layanan atau domain secara umum; jangan menganggapnya sebagai bukti langsung tentang akun individu.
- Output AI merupakan alat bantu keputusan, bukan kesimpulan hukum atau jaminan status keamanan. Tinjau finding dan draf DSR sebelum mengambil tindakan.
- Ollama lokal dapat menjaga inferensi model tetap lokal jika dikonfigurasi dengan benar, tetapi provider scan/enrichment eksternal tetap melakukan request jaringan jika diaktifkan.

---

## 🚀 Instalasi dan Penggunaan

### 1. Persyaratan

- Python 3.10 atau lebih baru.
- Git.
- Gmail App Password jika akan menggunakan pemindaian IMAP Gmail.
- Kredensial API hanya untuk provider opsional yang ingin digunakan.
- Layanan Ollama lokal yang berjalan jika ingin menggunakan model lokal.

### 2. Clone dan instal dependensi

```bash
git clone https://github.com/b4mz79/digital-footprint-auditor.git
cd digital-footprint-auditor

python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows PowerShell
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-test.txt  # hanya jika ingin menjalankan test
```

### 3. Konfigurasi `.env`

Salin file contoh lalu edit secara lokal:

```bash
cp .env.example .env
```

Setidaknya, isi `PII_PEPPER_KEY` dengan secret acak minimal 32 karakter. Contoh pembuatannya:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Selanjutnya, konfigurasi hanya provider yang ingin digunakan. Pengaturan umum:

| Pengaturan | Kegunaan |
|---|---|
| `GOOGLE_API_KEY_1` … `GOOGLE_API_KEY_6`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` | Kredensial Gemini / rotasi key |
| `GROQ_API_KEY`, `OPENAI_API_KEY` | Provider AI cloud |
| `LLM_PROVIDER_ORDER` | Urutan provider AI |
| `LLM_LOCAL_ONLY=true` | Mencegah pemanggilan AI cloud dan hanya menggunakan Ollama lokal |
| `OLLAMA_HOST`, `OLLAMA_MODEL` | Endpoint dan model Ollama lokal |
| `RAPIDAPI_KEY` | Provider BreachDirectory |
| `HIBP_API_KEY` | Metadata breach Have I Been Pwned |
| `GOOGLE_SEARCH_API_KEY`, `GOOGLE_CX_ID` | Google Custom Search |
| `TAVILY_API_KEY`, `SEARXNG_INSTANCE_URL` | Provider pencarian breach opsional |
| `FIRECRAWL_API_KEY` | Enrichment kontekstual publikasi keamanan opsional |
| `TENANT_ID` | Identitas tenant/cache lokal |

Lihat [`.env.example`](.env.example) untuk seluruh pengaturan dan nilai default. Jangan memasukkan secret ke laporan issue atau commit file `.env`.

### 4. Menjalankan aplikasi

Gunakan launcher sesuai sistem operasi atau jalankan Streamlit langsung:

```bash
# Linux / macOS
./run.sh

# Atau jalankan langsung
python -m streamlit run app.py
```

Di Windows, jalankan `run.bat` melalui Command Prompt atau PowerShell. Dashboard biasanya menggunakan `http://localhost:8501`.

Launcher mendukung mode reset. Pelajari dampaknya terlebih dahulu karena mode reset tertentu menghapus cache/artifact build lokal dan dapat menghentikan proses yang mendengarkan port 8501.

### Docker (contributor)

Untuk environment pengembangan berbasis container dan test runner Docker terpisah, lihat [workflow Docker untuk contributor](docs/DOCKER_ID.md). Konfigurasi Compose hanya mengikat dashboard ke localhost dan menjaga secret serta cache persisten tetap di luar image.

---

## 🛠️ Alur Pencarian Breach

```text
Input Email / Telepon
        |
        v
Validasi Input dan Normalisasi Nomor Telepon
        |
        v
Cache per Target / per Engine
        |
        v
Engine Pencarian Breach yang Dikonfigurasi
        |
        v
Finding Ternormalisasi + Status Engine
        |
        v
Pipeline Evidence / UI / Analisis AI
```

Breach scanner menggunakan worker queue yang dibatasi, rate limiter per engine, circuit breaker dan pelacakan kesehatan, mekanisme retry/cooldown, batas ukuran response, serta finding yang dinormalisasi. Status engine membedakan hasil kosong yang berhasil dari engine yang dilewati, terkena rate limit, timeout, atau gagal.

## 🧪 Pengujian

Instal dependensi test dan jalankan seluruh suite:

```bash
pip install -r requirements-test.txt
python -m pytest
```

Lihat [Integration Test Suite](docs/Integration_Test_Suite_ID.md) untuk cakupan dan panduan contributor.

## 🧩 Mengembangkan Proyek

- Untuk mengintegrasikan provider pencarian breach bawaan, ikuti [Custom Breach Engine Extension](docs/Custom_Breach_Engine_Extension_ID.md). Engine breach didaftarkan pada plan scanner inti; mekanisme ini berbeda dari Add-On yang dipasang melalui ZIP.
- Untuk mengembangkan Add-On opsional, ikuti [Add-On Tech Guide](docs/ADDON_TECH_GUIDE.md).
- Sebelum membuat Pull Request, jalankan test dan sertakan regression test yang relevan.

## 🤝 Berkontribusi

1. Fork repository.
2. Buat branch fitur.
3. Buat perubahan yang terfokus dan tambahkan/perbarui test.
4. Jalankan `python -m pytest`.
5. Buat Pull Request yang menjelaskan perubahan, hasil test, dan implikasi konfigurasi atau migrasi.

## ⚖️ Lisensi dan Disclaimer

Proyek ini menggunakan [MIT License](LICENSE).

> **Disclaimer:** Tool ini ditujukan untuk edukasi, audit privasi pribadi, dan riset OSINT defensif yang berizin. Jangan memindai data atau target tanpa otorisasi yang sesuai. Hasil pencarian dapat tidak lengkap atau tidak akurat; pengguna bertanggung jawab memvalidasi temuan dan menentukan tindakan selanjutnya.
