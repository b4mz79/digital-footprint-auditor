# Custom Breach Engine Extension

Dokumen ini menjelaskan cara menambahkan provider ke breach scanner bawaan. Isinya menjelaskan kontrak integrasi core saat ini, bukan API plugin breach engine yang dapat dimuat secara dinamis.

> **Penting:** breach engine didaftarkan di `services/breach_scanner.py`. Engine ini bukan Add-On yang dipasang melalui ZIP dan dikelola oleh runtime Add-On. Penambahan built-in breach engine saat ini memerlukan perubahan kode pada plan scanner beserta test terkait.

## 1. Arsitektur Scanner Saat Ini

Scanner menggunakan worker queue yang dibatasi dan shared execution wrapper:

```text
Input Target
    |
    v
Validasi Input / Normalisasi Nomor Telepon
    |
    v
build_plan() di scan_data_breaches()
    |
    v
run_engine_queue_v2()
    |
    v
execute_engine_v2()
    |
    v
EngineResult + finding ternormalisasi
    |
    v
Cache / hasil scan gabungan / UI
```

Lapisan eksekusi bersama menyediakan rate limiting per engine, circuit breaker dan pelacakan kesehatan, cooldown, timeout, serta pelaporan status standar. Scanner membedakan hasil kosong yang berhasil dari engine yang tidak berhasil menyelesaikan proses.

### Kontrak status engine

Nilai `EngineStatus` saat ini:

| Status | Arti |
|---|---|
| `success` | Request selesai; daftar finding boleh kosong. |
| `skipped` | Engine belum dikonfigurasi atau tidak berlaku untuk target tersebut. |
| `rate_limited` | Provider atau limiter lokal menolak percobaan karena batas request. |
| `timeout` | Eksekusi melewati batas waktu yang diizinkan. |
| `circuit_open` | Circuit breaker mencegah request saat engine sedang tidak sehat. |
| `failed` | Eksekusi gagal atau response provider tidak dapat diproses. |

Jangan mengubah status failed, skipped, timeout, atau rate-limited menjadi “breach tidak ditemukan”.

## 2. Checklist Integrasi Provider

Sebelum mengimplementasikan provider:

1. Pastikan ketentuan layanan dan API mengizinkan penggunaan defensif yang dimaksud.
2. Tentukan jenis target yang didukung (email, telepon, atau keduanya).
3. Identifikasi credential dan variabel konfigurasi.
4. Tetapkan batas ukuran response, timeout, retry, dan rate limit.
5. Normalisasi data provider ke format finding yang sudah ada.
6. Tambahkan engine ke konfigurasi enabled/skipped dan `build_plan()` pada scanner.
7. Tambahkan test dengan provider mock untuk finding valid, hasil kosong yang valid, credential tidak tersedia, response malformed, rate limit, timeout, dan isolasi kegagalan.
8. Pastikan cache hanya menyimpan hasil sukses yang valid dan status engine tetap terlihat.

## 3. Mendaftarkan Built-in Engine

Mapping `engine_enabled` dan `build_plan()` saat ini berada di dalam `scan_data_breaches()`. Tambahkan identifier engine internal yang stabil sesuai konvensi yang sudah digunakan, lalu tambahkan pemeriksaan variabel environment.

Pola ilustratif berikut perlu disesuaikan dengan nama dan signature fungsi aktual:

```python
ENGINE_CUSTOM = "Custom Provider"

custom_api_key = os.getenv("CUSTOM_API_KEY", "").strip()
engine_enabled[ENGINE_CUSTOM] = bool(custom_api_key)

# Di dalam build_plan(), tambahkan engine hanya jika sudah
# dikonfigurasi dan target didukung.
if engine_enabled[ENGINE_CUSTOM] and custom_target_is_supported(target):
    plan.append((
        ENGINE_CUSTOM,
        lambda: scan_custom_async(client, target, custom_api_key, lang=lang),
    ))
```

Ini adalah sketsa integrasi, bukan patch mandiri yang bisa langsung ditempel. Pertahankan konsistensi identifier, signature, dan registrasi dengan implementasi yang ada. Jangan membuat queue kedua atau memanggil engine di luar shared execution wrapper.

Jika provider hanya mendukung email, daftarkan hanya untuk target email yang sudah dinormalisasi. Jangan kirim variasi nomor telepon kecuali provider memang mendukungnya.

## 4. Normalisasi Finding

Fungsi engine mengembalikan `list[dict]` berisi finding yang sudah disanitasi. Gunakan schema dan helper normalisasi saat ini di `services/breach_scanner.py` sebagai acuan; jangan meneruskan payload provider langsung ke UI.

Finding ternormalisasi dapat berisi field seperti:

```json
{
  "source": "Custom Provider",
  "kind": "breach_db",
  "dataset": "Nama dataset",
  "title": "Judul yang terbaca dan sudah disanitasi",
  "url": "https://provider.example/report",
  "breach_date": "2025-01-01",
  "has_password": false,
  "snippet": "Ringkasan singkat yang sudah disanitasi"
}
```

Sertakan hanya field yang benar-benar didukung oleh response provider. Jangan menyimpulkan password terekspos hanya dari nama dataset atau hasil pencarian generik. Metadata opsional boleh disimpan jika berguna dan tidak mengandung data personal mentah, credential, atau record bocor.

## 5. Contoh Have I Been Pwned (HIBP)

HIBP sudah terintegrasi sebagai built-in provider ketika `HIBP_API_KEY` dikonfigurasi. Gunakan implementasinya sebagai referensi sebelum menambahkan provider serupa.

Metadata breach dapat mencakup `Name`, `Title`, `Domain`, `BreachDate`, `AddedDate`, `ModifiedDate`, `PwnCount`, `DataClasses`, dan flag verifikasi. Normalisasikan hanya field yang dibutuhkan schema finding aplikasi. Sebagai contoh, `has_password` harus diturunkan dari metadata data-class provider jika tersedia, bukan di-hard-code menjadi `true`.

Jangan pernah menyimpan atau mengeluarkan raw breach record, password, hash password, token autentikasi, atau credential dump. Simpan hanya metadata tersanitasi minimum yang diperlukan untuk menjelaskan exposure.

## 6. Persyaratan Keamanan

### Credential

- Baca credential dari environment variable.
- Jangan pernah mencatat credential ke log atau memasukkannya ke finding.
- Jangan simpan credential dalam cache atau pesan exception.
- Pastikan file `.env` tidak masuk version control.

### Response provider yang tidak tepercaya

- Terapkan timeout request dan batas ukuran response.
- Validasi bentuk response dan tipe field sebelum diproses.
- Normalisasi URL dan sanitasi judul/snippet menggunakan helper yang ada.
- Jangan render HTML provider sebagai markup tepercaya.
- Batasi jumlah dan panjang finding yang disimpan.
- Hindari penyimpanan raw breach record atau informasi personal yang tidak diperlukan.

### Resiliensi dan cache

- Gunakan shared execution wrapper, limiter, circuit breaker, dan health tracking.
- Biarkan wrapper mengklasifikasikan rate limit, timeout, dan kegagalan.
- Cache hanya hasil ternormalisasi yang sukses, termasuk daftar kosong yang valid.
- Jangan menganggap scan gagal atau tidak lengkap sebagai bukti tidak ada exposure.
- Tambahkan regression test untuk isolasi kegagalan provider dan perilaku cache.

## 7. Deduplication dan Test

Gunakan perilaku merge/deduplication global yang sudah ada, bukan membuat cache atau pipeline hasil terpisah. Untuk record breach database, tuple ternormalisasi seperti `(url, dataset, breach_date)` dapat membantu mengenali duplikasi, tetapi periksa implementasi merge aktual sebelum mengandalkannya.

Minimal, tambahkan test untuk:

- kondisi provider terkonfigurasi dan tidak terkonfigurasi;
- kecocokan target email/telepon;
- finding valid dan response kosong yang valid;
- response malformed atau terlalu besar;
- timeout, rate limit, dan error provider;
- redaksi secret dan raw record;
- cache hanya digunakan ulang untuk hasil sukses;
- tidak ada regresi pada engine lain ketika provider ini gagal.

Jalankan seluruh suite:

```bash
python -m pytest
```

## Catatan Contributor

Built-in breach engine baru biasanya membutuhkan fungsi provider async (atau wrapper thread berbatas waktu untuk library blocking), pemetaan response, konfigurasi environment, registrasi pada plan scanner, dan regression test. Hindari mengubah queue bersama, status model, pipeline cache, atau UI kecuali kebutuhan provider memang mengharuskannya.
