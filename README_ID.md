# 🔍 Digital Footprint & OSINT Data Breach Auditor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)

**Language / Bahasa:** [English](README.md)  |  [Bahasa Indonesia](README_ID.md)

**Digital Footprint & OSINT Data Breach Auditor** adalah alat analisis jejak digital personal dan pemeriksa kebocoran data (*data breach*) berbasis Python dan Streamlit. Tool ini dirancang untuk memindai exposure akun email, variasi nomor telepon, serta jejak layanan terdaftar (via IMAP & OSINT) secara multi-layer, lalu memberikan analisis risiko privasi serta draf **Surat Permintaan Penghapusan Data (DSR)** otomatis berdasarkan **UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP Indonesia)**.

---

## ✨ Fitur Utama

* 📧 **Gmail IMAP Scanner**: Mengidentifikasi layanan digital yang terhubung secara otomatis dengan memindai subjek email konfirmasi/pendaftaran.
* 🕵️ **OSINT Account Checker**: Mengintegrasikan *Holehe* untuk mendeteksi keberadaan akun terdaftar di puluhan platform digital.
* 🛡️ **Multi-Layer Breach Engine**:
* BreachDirectory DB API (Spesialis Database Dump)
* Google Custom Search API & Scraper Fallback (`googlesearch-python`)
* Bing Search Scraper (via `BeautifulSoup`)
* Tavily AI Search API
* SearXNG MetaSearch & DuckDuckGo


* 📱 **Dynamic Phone Number Normalization**: Memecah dan mencari variasi format nomor HP nasional (`08xx`) hingga internasional (`+62xx`, `62xx`) secara presisi.
* 🤖 **Multi-Model AI Risk Assessment**: Analisis tingkat risiko kebocoran data secara otomatis yang mendukung fleksibilitas berbagai provider LLM (Google Gemini, Groq, OpenAI) hingga **Local Ollama** untuk analisis *privacy-first* secara *offline*.
* 📜 **DSR Generator (UU PDP)**: Menggenerasi draf surat resmi *Data Subject Request* untuk penghapusan/pemusnahan data pribadi dari pengendali data.
* ⚡ **Caching & Noise Filter**: Dilengkapi sistem *caching* lokal TTL 12 jam dan *ignoring domain filter* untuk mencegah *false positive*.

---

## 🚀 Panduan Instalasi & Penggunaan

### 1. Prasyarat System

* Python 3.10 atau versi yang lebih baru.
* Akun Gmail dengan **App Password** terintegrasi (jika ingin menggunakan fitur Scan Inbox Gmail).

### 2. Kloning Repository & Install Dependensi

```bash
# Clone repository
git clone https://github.com/b4mz79/digital-footprint-auditor
cd digital-footprint-auditor

# Buat virtual environment (opsional tapi disarankan)
python -m venv venv
source venv/bin/activate  # Untuk Linux/macOS
# venv\Scripts\activate   # Untuk Windows

# Install dependensi pustaka
pip install -r requirements.txt

```

### 3. Konfigurasi Environment Variable (`.env`)

Salin file `.env.example` menjadi `.env`:

```bash
cp .env.example .env

```

Buka file `.env` dan isi kunci API yang Anda miliki (semakin lengkap API key, semakin maksimal hasil pencarian):

```env
GEMINI_API_KEY_1=your_gemini_key_here
RAPIDAPI_KEY=your_rapidapi_key_here
GOOGLE_SEARCH_API_KEY=your_google_api_key_here
GOOGLE_CX_ID=your_custom_search_cx_here
TAVILY_API_KEY=your_tavily_key_here
DELAY_SECONDS=2

```

### 4. Jalankan Aplikasi

Jalankan dashboard aplikasi melalui Streamlit (atau eksekusi `./run.sh` / `run.bat`):

```bash
streamlit run app.py

```

Aplikasi akan otomatis terbuka di browser lokal Anda di `http://localhost:8501`.

---

## 🛠️ Arsitektur Singkat Pencarian Breach

```text
[ Input Email & Phone ]
          │
          ├──> 1. Normalisasi Nomor HP (Variasi 08xx, +62xx, Spasi, Dash)
          ├──> 2. Cek Cache Lokal (cache/breach/)
          └──> 3. Multi-Engine Iterative Scanning:
                   ├── BreachDirectory API
                   ├── Google API / Scraper Fallback
                   ├── Bing Scraper
                   ├── Tavily AI Search
                   ├── SearXNG MetaSearch
                   └── DuckDuckGo

```

---

## 🤝 Berkontribusi (Contributing)

Kontribusi terbuka lebar untuk siapa saja! Jika Anda ingin menambahkan fitur baru, memperbaiki bug, atau meningkatkan integrasi OSINT:

1. *Fork* repository ini.
2. Buat branch fitur baru (`git checkout -b fitur/FiturKerenAplikasi`).
3. Commit perubahan Anda (`git commit -m 'Menambahkan Fitur Keren'`).
4. Push ke branch Anda (`git push origin fitur/FiturKerenAplikasi`).
5. Buat **Pull Request (PR)** baru.
6. Detail teknis mengenai **Integration Test Suite**, silakan baca [Integration Test Suite](Integration_Test_Suite_ID.md)
7. Detail teknis mengenai cara mengintegrasikan **Custom Breach Engine Extension**, silakan baca [Custom Breach Engine Extension](Custom_Breach_Engine_Extension_ID.md)

---

## ⚖️ Lisensi

Proyek ini dilisensikan di bawah **MIT License** - lihat file [LICENSE](LICENSE) untuk detail selengkapnya.

> **Disclaimer**: Tool ini dibuat hanya untuk tujuan edukasi, analisis privasi pribadi, dan riset keamanan informasi (*defensive OSINT*). Penggunaan tool ini terhadap target tanpa izin merupakan tanggung jawab penuh masing-masing pengguna.

