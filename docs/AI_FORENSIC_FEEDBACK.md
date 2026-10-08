# AI Forensic Feedback

## Purpose

File ini adalah template feedback untuk investigasi **Evidence → AI payload**.

Tujuan investigasi saat ini hanya menentukan sumber pembengkakan request AI. **Jangan mengubah EvidenceRecord, evidence enrichment, sanitizer, provider chain, atau prompt hanya berdasarkan file ini.**

Branch yang digunakan:

`feat/evidence-enrichment-foundation`

---

## 1. Real-run yang dibutuhkan

Jalankan **1 full scan real** dengan:

```env
AI_FORENSIC_TELEMETRY=true
```

Gunakan kondisi normal yang sekarang sedang bermasalah. Jangan mengubah provider order hanya untuk eksperimen ini.

Setelah selesai, kirim kembali **log hasil run tersebut** atau isi bagian di bawah dengan nilai yang muncul.

---

## 2. Wajib dikirim

Copy baris log yang diawali:

```
[AI Forensic]
```

dan baris error dari provider:

- Gemini
- Groq
- OpenAI
- Ollama, jika ikut aktif

Jangan kirim API key, email, nomor telepon, token, cookie, atau credential.

---

## 3. Snapshot pipeline

Isi dari run yang sama:

```text
services =
evidence =
breach =
addon_results =
failed_engines =
```

Jika addon tidak aktif:

```text
addon_results = none
```

---

## 4. Payload measurements

Dari telemetry yang tersedia, catat:

```text
user_chars =
user_estimated_tokens =

system_chars =
system_estimated_tokens =

combined_chars =
combined_estimated_tokens =
```

Jika suatu nilai tidak tersedia di log, tulis:

```
N/A
```

**Jangan menebak nilainya.**

---

## 5. Provider failure

Untuk setiap provider yang gagal, copy **jenis error + message ringkasnya**.

Contoh format:

```text
Gemini:
- key #1: ...
- key #2: ...

Groq:
- model:
- HTTP/status:
- error:

OpenAI:
- model:
- HTTP/status:
- error:
```

Tidak perlu menyertakan API key.

---

## 6. Evidence composition

Kalau log/runtime bisa memberikan informasi ini, isi:

```text
total evidence records =

direct evidence count =
contextual evidence count =

verified/reachable count =
unverified/unknown count =

security-publication/contextual count =

base service evidence count =
```

Kalau belum tersedia, tulis `N/A`.

---

## 7. Yang TIDAK perlu dikirim

Jangan dump:

- full system prompt
- full user prompt
- full EvidenceRecord payload
- email target
- nomor telepon
- API key
- token
- credential
- cookie
- raw private mailbox content

Kita sedang mengukur **ukuran dan komposisi payload**, bukan membutuhkan isi PII mentah.

---

## 8. Optional: log file

Kalau lebih mudah, cukup kirim file log hasil real-run daripada mengisi template ini.

Yang paling penting adalah mempertahankan satu run yang sama sehingga:

```
services
    ↓
evidence
    ↓
build_user_prompt
    ↓
provider request
    ↓
provider failure/success
```

bisa dikorelasikan.

---

## 9. Catatan investigasi

Baseline yang sudah diketahui sebelum feedback ini:

- services = 80
- evidence = 88
- breach = 0
- Gemini mengalami kombinasi 503 provider capacity dan 429 quota
- Groq mengalami 413 / input-token-per-minute limit
- OpenAI mengalami 429 / insufficient quota

Temuan **Groq 413** adalah indikasi kuat bahwa request terlalu besar, tetapi belum cukup untuk menentukan komponen mana yang menjadi penyebab utama.

### Hipotesis yang sedang diuji

```text
EvidenceRecord lengkap
        ↓
sanitize_evidence_records()
        ↓
UNTRUSTED_EVIDENCE
        ↓
build_user_prompt()
        ↓
provider payload
```

Kita belum memutuskan apakah solusi akhirnya:

1. memperbaiki kualitas/ukuran contextual evidence;
2. membuat AI Evidence Projection yang lebih compact;
3. mengurangi komponen non-evidence;
4. provider-specific budget;
5. atau kombinasi beberapa hal.

**Jangan implementasikan salah satu solusi tersebut berdasarkan hipotesis ini sebelum decomposition datanya tersedia.**

---

## 10. Hasil yang diharapkan dari audit

Feedback ini akan dipakai untuk menjawab satu pertanyaan:

> **Komponen mana yang benar-benar mengonsumsi token/request budget AI, dan apakah Evidence Enrichment merupakan sumber utama pembengkakan tersebut?**

Setelah itu baru dilakukan perubahan pada call-chain yang memang terbukti diperlukan.
