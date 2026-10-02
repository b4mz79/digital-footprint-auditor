# 🧪 Integration Test Suite

Proyek ini menyediakan integration test suite otomatis untuk memverifikasi fungsi utama aplikasi dan mencegah regression saat pengembangan.

## Cakupan Pengujian

Test suite melakukan validasi terhadap:

- Pipeline klasifikasi risiko (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN/Gray`)
- Penerapan risk floor berbasis evidence
- Validasi respons AI dan integritas format JSON
- Mekanisme fallback provider AI (contoh Gemini → Groq)
- Integritas sistem translasi
- Perilaku integrasi aplikasi

## Menjalankan Test

Install dependency untuk testing:

```bash
pip install -r requirements-test.txt
```

Jalankan seluruh test:

```bash
pytest
```

Contoh hasil sukses:

```text
5 passed
```

## Untuk Contributor

Sebelum membuat Pull Request, contributor disarankan menjalankan integration test secara lokal:

1. Buat dan aktifkan virtual environment.
2. Install dependency aplikasi dan testing.
3. Jalankan `pytest`.
4. Pastikan seluruh test berhasil sebelum mengirim perubahan.

Test suite ini dibuat untuk mendeteksi regression pada komponen yang bersifat sensitif terhadap keamanan, terutama validasi AI, analisis risiko privasi, dan mekanisme fallback.
