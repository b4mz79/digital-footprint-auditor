# Arsitektur Breach Scanner v2

Breach Scanner v2 menambahkan lapisan kontrol untuk
mengelola engine eksternal.

Fitur:

- Worker queue
- Rate limiter per engine
- Circuit breaker
- Monitoring kesehatan engine
- Penanganan HTTP 429
- Isolasi kegagalan provider


## Mengapa menggunakan worker queue?

Versi sebelumnya menjalankan seluruh engine secara paralel
langsung.

Hal ini dapat menyebabkan burst request.

---

# Custom Breach Engine Extension

Breach Scanner v2 dirancang dengan arsitektur modular sehingga engine breach tambahan dapat ditambahkan tanpa mengubah core scanner.

Engine baru hanya perlu mengikuti **engine contract** yang sudah digunakan oleh engine bawaan.

## Engine Lifecycle

Setiap engine mengikuti alur:

```
Input Target
      |
      v
build_plan()
      |
      v
execute_engine_v2()
      |
      v
EngineResult
      |
      v
Unified Findings Pipeline
      |
      v
Cache / UI / Reporting
```

Engine tambahan tidak boleh melakukan:

* penyimpanan cache sendiri
* perubahan schema output utama
* bypass `execute_engine_v2()`
* memasukkan data mentah provider langsung ke UI

---

# Engine Registration

Tambahkan identifier engine:

```python
ENGINE_CUSTOM = "Custom Breach Engine"
```

Tambahkan konfigurasi environment:

```python
CUSTOM_API_KEY = os.getenv(
    "CUSTOM_API_KEY",
    ""
).strip()
```

Tambahkan ke engine availability:

```python
engine_enabled = {
    ENGINE_CUSTOM: bool(CUSTOM_API_KEY),
}
```

Jika API key tidak tersedia, engine harus dianggap:

```
status = skipped
```

dan tidak boleh menyebabkan scan gagal.

---

# Engine Integration

Engine dimasukkan melalui `build_plan()`:

```python
if engine_enabled[ENGINE_CUSTOM]:
    plan.append(
        (
            ENGINE_CUSTOM,
            lambda: scan_custom_async(
                client,
                target,
                CUSTOM_API_KEY,
            ),
        )
    )
```

Function engine harus mengembalikan:

```python
list[dict]
```

dengan format finding internal.

---

# Finding Schema

Semua engine wajib melakukan normalisasi output ke schema internal:

```json
{
  "source": "Engine Name",
  "kind": "breach_db",
  "dataset": "Dataset Name",
  "title": "Human readable title",
  "url": "Provider URL",
  "has_password": true,
  "snippet": "Short sanitized summary"
}
```

Field tambahan diperbolehkan selama:

* tidak mengandung PII mentah
* tidak menyimpan credential
* tidak menyimpan raw breach record

---

# Have I Been Pwned (HIBP) Integration Example

HIBP menggunakan endpoint API yang mengembalikan JSON breach metadata.

Contoh response:

```json
{
  "Name": "Adobe",
  "Title": "Adobe",
  "Domain": "adobe.com",
  "BreachDate": "2013-10-04",
  "PwnCount": 152445165,
  "DataClasses": [
    "Email addresses",
    "Passwords",
    "Usernames"
  ],
  "IsVerified": true
}
```

Response tersebut harus diubah menjadi internal finding:

```json
{
  "source": "HaveIBeenPwned API",
  "kind": "breach_db",
  "dataset": "Adobe",
  "title": "Breach dataset: Adobe",
  "url": "https://haveibeenpwned.com",
  "breach_date": "2013-10-04",
  "has_password": true,
  "data_classes": [
    "Email addresses",
    "Passwords",
    "Usernames"
  ],
  "verified": true
}
```

---

# Security Requirements

Custom engine wajib mengikuti aturan berikut:

## 1. API Key Handling

API key:

* hanya dibaca dari environment variable
* tidak boleh masuk log
* tidak boleh masuk cache
* tidak boleh masuk finding output

Contoh:

```python
CUSTOM_API_KEY = os.getenv("CUSTOM_API_KEY")
```

---

## 2. Response Sanitization

Provider response dianggap **untrusted data**.

Engine wajib:

* membatasi ukuran response
* melakukan validasi JSON schema
* tidak meneruskan HTML mentah
* tidak menyimpan raw breach record

Contoh:

```python
title = clean_title(item.get("Title"))
```

---

## 3. Password Exposure Mapping

Engine dapat memberikan informasi risiko password melalui flag:

```python
has_password = True
```

berdasarkan metadata provider.

Jangan pernah menyimpan:

* password
* hash
* credential dump
* raw leaked record

---

# Engine Status Handling

Engine harus menggunakan mekanisme status standar:

| Kondisi                 | Status       |
| ----------------------- | ------------ |
| API berhasil            | SUCCESS      |
| API key tidak tersedia  | SKIPPED      |
| Rate limit provider     | RATE_LIMITED |
| Timeout                 | TIMEOUT      |
| Schema provider berubah | FAILED       |

---

# Deduplication

Semua finding akan diproses melalui pipeline deduplication global.

Untuk database breach:

```python
(
    url,
    dataset,
    breach_date
)
```

digunakan sebagai identifier.

Engine tidak perlu melakukan dedupe sendiri.

---

# Contributor Guidelines

Contributor yang menambahkan breach engine baru cukup menyediakan:

1. Async engine function

```python
async def scan_custom_async(...):
    ...
    return findings
```

2. Mapping response provider ke internal schema

3. Environment configuration

4. Penambahan engine identifier

Tidak diperlukan perubahan pada:

* queue system
* circuit breaker
* limiter
* cache layer
* reporting pipeline
* UI layer

Dengan desain ini, breach provider baru dapat ditambahkan sebagai plugin engine tanpa mengganggu engine yang sudah berjalan.
