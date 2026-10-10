# 🧪 Integration Test Suite

**Language / Bahasa:** [English](Integration_Test_Suite.md) | [Bahasa Indonesia](Integration_Test_Suite_ID.md)

Proyek ini menggunakan pytest untuk menguji perilaku inti dan mengurangi regresi pada pemindaian, pemrosesan evidence, analisis AI, cache, Add-On, dan integrasi aplikasi.

## Cakupan Pengujian

Suite mencakup pengujian untuk:

- **Breach scanner:** eksekusi engine, penanganan status, perilaku queue, dan kebijakan redirect hasil pencarian.
- **Analisis AI:** validasi response/schema, pengaman risiko berbasis evidence, batas ukuran prompt/evidence, dan fallback provider.
- **Pipeline evidence:** normalisasi dan provenance evidence, enrichment kontekstual, semantik waktu, verifikasi URL, serta kondisi verifikasi gagal/unknown.
- **Integrasi pipeline:** orkestrasi tahapan scan, output evidence, integrasi lifecycle Add-On, dan validasi tenant ID.
- **Perilaku cache:** identitas cache, lifecycle cache, kontrol cache per modul, dan penggunaan ulang hasil sukses.
- **Keamanan dan lifecycle Add-On:** struktur paket, validasi authority, kebijakan filesystem, validasi keamanan, instalasi, aktivasi/invocation, dan packaging sample Add-On.
- **Transport OSINT dan launcher:** kebijakan transport serta pemeriksaan regresi/keamanan launcher.
- **Translasi:** integritas key terjemahan dan bahasa.

Test menggunakan mock dan fixture terkontrol jika sesuai; test ini bukan pengganti smoke test provider langsung atau scan nyata dengan credential.

## Instal Dependensi Test

Dari root repository, aktifkan virtual environment lalu instal dependensi:

```bash
pip install -r requirements.txt
pip install -r requirements-test.txt
```

## Menjalankan Suite

Jalankan seluruh test:

```bash
python -m pytest
```

Jalankan modul test tertentu saat menelusuri masalah, misalnya:

```bash
python -m pytest tests/test_evidence_enrichment.py
python -m pytest tests/test_provider_fallback.py
python -m pytest tests/addons/
```

Jangan mengandalkan jumlah test contoh yang tetap di dokumen ini karena jumlahnya berubah seiring bertambahnya coverage. Gunakan ringkasan pytest aktual dari checkout yang sedang diuji sebagai sumber kebenaran.

## Checklist Contributor

Sebelum membuka Pull Request:

1. Tambahkan atau perbarui test untuk perilaku yang berubah, termasuk jalur kegagalan yang relevan.
2. Jalankan seluruh suite dengan `python -m pytest`.
3. Tinjau kegagalan dan warning; jangan melaporkan test sukses jika collection atau eksekusi terhenti.
4. Jika perubahan memengaruhi provider eksternal, tambahkan smoke test terkontrol jika credential dan ketentuan provider mengizinkan.
5. Cantumkan perintah dan hasil aktual pada deskripsi Pull Request.

Suite ini bertujuan menangkap regresi pada perilaku yang sensitif terhadap keamanan. Test yang lulus tidak membuktikan provider eksternal selalu tersedia, seluruh breach pasti ditemukan, atau aplikasi bebas dari kerentanan.
