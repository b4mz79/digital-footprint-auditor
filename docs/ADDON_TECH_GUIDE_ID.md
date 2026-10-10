# Panduan Teknis Add-On

**Language / Bahasa:** [English](ADDON_TECH_GUIDE.md) | [Bahasa Indonesia](ADDON_TECH_GUIDE_ID.md)

## 1. Tujuan

Panduan ini mendokumentasikan arsitektur Add-On publik Privacy Auditor.

Sistem Add-On memungkinkan ekstensi yang dikemas secara independen untuk dipasang, ditemukan, diaktifkan, dipanggil, dinonaktifkan, dan dihapus tanpa menjadikan setiap kemampuan opsional sebagai layanan bawaan.

Panduan ini menjelaskan kontrak host dan Add-On referensi `just-sample`.

> Ini adalah panduan arsitektur dan integrasi. Implementasi Add-On privat atau komersial tidak dibahas di sini.

## 2. Konsep Add-On

Add-On adalah paket ekstensi eksternal yang implementasinya dimiliki Add-On, sedangkan host mengelola kontrak runtime.

Alur dasarnya:

```text
ZIP
 ↓
INSTALL
 ↓
DISCOVER
 ↓
REGISTER
 ↓
ENABLE
 ↓
CALL
```

Tanggung jawab host:
- instalasi dan validasi paket;
- parsing manifest;
- registrasi;
- pengelolaan lifecycle dan status aktivasi;
- routing invocation dan dispatch event;
- validasi hasil;
- pemanggilan UI;
- isolasi error.

Tanggung jawab Add-On:
- implementasi sendiri;
- kontrak input dan hasil yang dideklarasikan;
- implementasi UI jika diperlukan;
- logika domain internal.

## 3. Layanan Bawaan vs Add-On

Layanan bawaan merupakan bagian dari core Privacy Auditor, misalnya IMAP scanning, OSINT scanning, breach scanning, evidence enrichment, evidence verification, dan analisis AI.

Add-On adalah ekstensi opsional yang dimuat melalui Add-On Manager. Pemisahan ini disengaja: implementasi Add-On tidak seharusnya perlu dipindahkan ke core agar bisa digunakan.

## 4. Referensi Add-On Publik

Distribusi publik/komunitas menggunakan `just-sample` sebagai Add-On referensi. Contoh ini menunjukkan:
- Add-On tipe hybrid;
- deklarasi manifest;
- invocation berbasis event;
- validasi input;
- pembuatan hasil;
- rendering UI;
- aliran data antara host dan Add-On.

Implementasinya sengaja dibuat sederhana.

## 5. Struktur Paket

Paket hybrid minimal dapat menggunakan struktur berikut:

```text
addons/
└── just-sample/
    ├── __init__.py
    ├── manifest.json
    ├── plugin.py
    └── ui.py
```

Add-On yang lebih besar dapat memiliki modul implementasi, konfigurasi, resource, dan test sendiri. Host tetap harus memperlakukan direktori Add-On sebagai batas paket.

## 6. `manifest.json`

Manifest adalah kontrak Add-On yang dibaca host. Contoh:

```json
{
  "id": "just-sample",
  "name": "just-sample",
  "caption": "Hello World",
  "version": "1.0.0",
  "entrypoint": "plugin.py",
  "type": "hybrid",
  "invocation": {
    "function": "run",
    "mode": "on_event",
    "input": { "required": true },
    "return": { "type": "result", "required": true }
  },
  "ui": { "entrypoint": "ui.py", "function": "render" },
  "events": [{
    "name": "discovery.imap.completed",
    "input": { "required": true },
    "return": { "type": "result", "required": true }
  }],
  "result_key": null,
  "ai_context": false,
  "default_active": true
}
```

| Field | Arti |
|---|---|
| `id` | Identifier Add-On yang stabil |
| `name` | Nama tampilan/identitas |
| `caption` | Deskripsi yang mudah dibaca |
| `version` | Versi Add-On |
| `entrypoint` | File entrypoint backend |
| `type` | `backend`, `ui`, atau `hybrid` |
| `invocation.function` | Fungsi backend yang diekspos ke host |
| `invocation.mode` | `on_demand` atau `on_event` |
| `invocation.input.required` | Apakah input invocation wajib |
| `invocation.return.type` | `result` atau `none` |
| `invocation.return.required` | Apakah hasil wajib dikembalikan |
| `ui.entrypoint` / `ui.function` | Entry point dan fungsi UI opsional |
| `events` | Event yang dikonsumsi Add-On berbasis event |
| `result_key` | Key opsional untuk memilih hasil bagi UI |
| `ai_context` | Apakah hasil boleh dimasukkan ke konteks AI |
| `default_active` | Status aktivasi awal dalam manifest |

Fungsi backend yang digunakan saat ini adalah `run`. Ini merupakan kontrak tetap, bukan nama fungsi arbitrer yang dipilih saat runtime.

## 7. Jenis Add-On

Tiga jenis didukung:
- **backend** — hanya logika backend;
- **ui** — hanya ekstensi UI;
- **hybrid** — logika backend dan UI.

Add-On referensi `just-sample` bertipe hybrid.

## 8. Mode Invocation

### `on_demand`

Host memanggil Add-On secara eksplisit melalui `AddonManager.invoke(addon_id, context)`.

### `on_event`

Host mengirim event kanonis melalui `AddonManager.dispatch_event(...)`, lalu Add-On aktif yang berlangganan event tersebut dapat dijalankan.

Add-On `on_event` harus mendeklarasikan event yang dikonsumsi. Add-On `on_demand` tidak boleh mendeklarasikan langganan event.

## 9. Kontrak Event

Event adalah kontrak runtime tingkat host, misalnya:

```text
discovery.imap.completed
discovery.osint.completed
breach.scan.completed
evidence.enriched
evidence.verified
```

Contoh konteks event:

```python
context = {
    "event": "discovery.imap.completed",
    "data": imap_result,
}
```

Add-On harus mengikuti kontrak payload yang dideklarasikan dan tidak bergantung pada state pipeline internal yang tidak terkait.

## 10. Kontrak Backend

Host memanggil fungsi backend yang ditentukan manifest. Contoh pola:

```python
from collections.abc import Mapping
from typing import Any

def run(context: Mapping[str, Any]) -> dict[str, Any]:
    data = context.get("data")
    if not isinstance(data, Mapping):
        raise TypeError("just-sample requires context['data'] as a mapping")

    services = data.get("services", [])
    if not isinstance(services, list):
        raise TypeError("just-sample requires data['services'] as a list")

    return {"jumlah_email": len(services)}
```

Add-On harus memvalidasi input yang dibutuhkannya sendiri. Jangan mengasumsikan event tersedia hanya karena Add-On sudah dipasang.

## 11. Kontrak Hasil

Add-On yang menghasilkan output harus mengembalikan mapping yang sesuai dengan kontrak manifest. Contoh output `just-sample`:

```json
{ "jumlah_email": 3 }
```

Host memvalidasi bahwa hasil wajib tersedia. Hasil sebaiknya berisi data milik Add-On, bukan mengubah state host secara langsung.

## 12. Kontrak UI

Add-On yang memiliki UI mendeklarasikan entrypoint dan fungsi UI. Contoh:

```python
from collections.abc import Mapping
import streamlit as st

def render(context):
    result = context.get("result")
    if not isinstance(result, Mapping):
        return

    jumlah_email = result.get("jumlah_email")
    if not isinstance(jumlah_email, int):
        return

    st.info(f"{jumlah_email} hasil scan email ditemukan sesuai kriteria")
```

UI harus gagal dengan aman ketika hasil yang diharapkan tidak ada atau formatnya tidak valid. Host menentukan kapan dan di mana UI dirender.

## 13. Routing `result_key`

`result_key` adalah mekanisme routing sisi host yang bersifat opsional. Jika dideklarasikan, host dapat memilih nilai tertentu dari output Add-On sebelum meneruskan hasil ke UI. UI harus mengikuti kontrak routing yang tercantum pada manifest. Untuk `just-sample`, nilainya `null`.

## 14. Lifecycle

Hook lifecycle yang didukung saat ini hanya:

```text
after_install
before_activate
after_activate
before_deactivate
after_deactivate
before_uninstall
```

Alur:
- **Install:** instalasi lalu `after_install`;
- **Activate:** `before_activate`, aktivasi, lalu `after_activate`;
- **Deactivate:** `before_deactivate`, deaktivasi, lalu `after_deactivate`;
- **Uninstall:** `before_uninstall`.

Kontrak saat ini tidak memiliki hook `before_install` atau `after_uninstall`.

## 15. Tanggung Jawab Add-On Manager

Add-On Manager merupakan batas host. Tanggung jawabnya mencakup:
1. menemukan paket terpasang;
2. memvalidasi manifest;
3. mendaftarkan Add-On;
4. mengelola status aktivasi;
5. menjalankan hook lifecycle;
6. memanggil Add-On on-demand;
7. mendispatch event;
8. memuat entrypoint;
9. memvalidasi input dan hasil;
10. memanggil entrypoint UI;
11. mengisolasi kegagalan Add-On.

Add-On tidak boleh melewati manager untuk mengubah registrasi atau status lifecycle host.

## 16. Registrasi dan Status

Manager menyimpan status registrasi dan aktivasi secara terpisah dari implementasi Add-On. Alur konseptualnya:

```text
Installed → Registered → Active / Inactive
```

Instalasi tidak berarti Add-On harus langsung dieksekusi. Aktivasi menentukan apakah Add-On memenuhi syarat untuk invocation atau dispatch event.

## 17. Instalasi ZIP dan Keamanan

Add-On dipasang dari paket ZIP dan kontennya divalidasi sebelum ekstraksi. Pengamanan saat ini meliputi:
- maksimum 500 file;
- maksimum 50 MB konten hasil ekstraksi;
- penolakan path traversal dan symlink;
- path ekstraksi yang aman;
- validasi manifest.

Installer tidak boleh membiarkan arsip menulis di luar direktori Add-On yang dituju.

> **Batas keamanan runtime:** direktori paket adalah batas instalasi, bukan sandbox proses. Kode Python Add-On berjalan di proses Privacy Auditor dan memiliki izin sistem operasi yang sama dengan proses host. Pasang hanya Add-On yang kodenya dipercaya.

Instalasi dimulai dalam keadaan nonaktif, walaupun manifest menyatakan `default_active`. Aktivasi merupakan tindakan eksplisit host sehingga instalasi saja tidak menjalankan kode Add-On melalui invocation atau dispatch event normal.

## 18. Isolasi Error

Add-On bersifat opsional dan tidak boleh membuat pipeline inti rapuh. Jika Add-On gagal, kegagalan tersebut harus terlihat melalui logging dan status/hasil host, sementara pipeline inti tetap berfungsi.

## 19. Isolasi Kegagalan Dispatch Event

Dispatch mengisolasi kegagalan antar-Add-On yang cocok. Jika satu Add-On melempar exception, manager mencatat kegagalan lalu melanjutkan dispatch event yang sama ke Add-On aktif lain yang berlangganan.

## 20. Guardrail Routing Hasil

`result_key` bersifat opsional dan divalidasi host sebelum instalasi. Nilainya harus berupa identifier huruf kecil dan tidak boleh menunjuk key state inti yang dicadangkan, seperti `services`, `evidence`, `breach`, `ai`, atau `tenant_id`.

Add-On yang mengembalikan hasil harus memberikan mapping. Host menolak tipe hasil yang tidak kompatibel sebelum menyimpan atau melakukan routing.

## 21. Alur Dispatch Event

```text
Built-in Service selesai
        ↓
Host mengirim event kanonis
        ↓
AddonManager.dispatch_event()
        ↓
Cari Add-On aktif yang berlangganan
        ↓
Validasi input → Muat entrypoint → Panggil run(context)
        ↓
Validasi dan simpan hasil
        ↓
Hasil tersedia untuk UI / konsumen opsional
```

Contoh: IMAP Scanner → `discovery.imap.completed` → `just-sample` → hasil `jumlah_email`.

## 22. Alur Rendering UI

Eksekusi backend dan rendering UI merupakan langkah terpisah:

```text
Event → Eksekusi backend → Penyimpanan hasil
      → Payload UI → Pemanggilan UI → render(context)
```

UI tidak boleh menjalankan ulang operasi backend hanya untuk memperoleh data yang akan ditampilkan.

## 23. Add-On Referensi: `just-sample`

`just-sample` adalah Add-On demo untuk arsitektur publik. Kontraknya:
- nama: `just-sample`;
- caption: `Hello World`;
- tipe: `hybrid`;
- invocation: `run`;
- mode: `on_event`;
- event: `discovery.imap.completed`;
- input: hasil IMAP scanner;
- output: result;
- UI: renderer Streamlit.

Backend membaca daftar `services` dari hasil IMAP dan mengembalikan jumlahnya. UI menampilkan pesan jumlah hasil scan yang sesuai kriteria. Implementasi dibuat kecil agar kontrak host mudah dipahami.

## 24. Pengujian

Uji Add-On secara independen dari aplikasi penuh jika memungkinkan.

**Instalasi**
- ZIP berhasil dipasang;
- manifest malformed ditolak;
- path tidak aman ditolak;
- paket terlalu besar ditolak.

**Registrasi**
- Add-On ditemukan;
- field manifest diparsing;
- status aktivasi benar.

**Invocation**
- input valid diteruskan ke `run`;
- input tidak valid ditolak dengan aman;
- hasil wajib dikembalikan;
- hasil tidak valid diisolasi.

**Event**
- event yang cocok memanggil Add-On;
- event lain tidak memanggilnya;
- Add-On nonaktif tidak dieksekusi;
- kegagalan event tidak merusak host.

**UI**
- entrypoint UI dimuat;
- hasil yang diharapkan dirender;
- hasil hilang/malformed ditangani aman;
- routing mengikuti `result_key`.

Untuk integrasi nyata `just-sample`, kemas Add-On, pasang pada Add-On Manager terisolasi, aktifkan, dispatch event IMAP, berikan hasil mirip IMAP yang valid, periksa `jumlah_email`, lalu pastikan event yang tidak relevan tidak menjalankannya.

## 25. Integrasi Pipeline

Sistem Add-On terhubung dengan pipeline melalui kontrak host dan event kanonis:

```text
Privacy Auditor → Built-in Service → Canonical Event
               → AddonManager → Optional Add-On
```

Pipeline inti harus tetap berfungsi saat tidak ada Add-On, Add-On nonaktif, Add-On gagal, atau Add-On dihapus.

## 26. Konteks AI

Add-On dapat mendeklarasikan `"ai_context": true`. Ini berarti host boleh meneruskan hasilnya ke konteks analisis AI setelah menerapkan sanitasi dan aturan konteks normal.

Hal tersebut **tidak** memberi Add-On hak untuk mengubah kebijakan risiko deterministik, mengubah risiko final secara langsung, melewati aturan evidence, atau memaksakan kesimpulan AI. Host tetap menentukan bagaimana konteks tersebut digunakan.

## 27. Hal yang Tidak Boleh Dilakukan Add-On

Add-On tidak boleh:
- mengubah source core saat runtime;
- melewati registrasi Add-On Manager;
- membuat hook lifecycle yang tidak dideklarasikan;
- mengonsumsi event yang tidak dideklarasikan;
- mengasumsikan payload memiliki field internal arbitrer;
- mengubah state pipeline yang tidak terkait tanpa kontrak host;
- berjalan diam-diam saat nonaktif;
- membuat pipeline inti bergantung pada keberhasilannya;
- menggunakan UI sebagai pengganti proses backend;
- mengklaim kewenangan atas risiko hanya karena hasilnya tersedia bagi AI.

## 28. Prinsip Kompatibilitas

Utamakan kontrak stabil: manifest, kontrak event, input, hasil, dan UI. Hindari ketergantungan pada fungsi host privat, variabel pipeline privat, atau detail implementasi internal.

Saat host berkembang, kompatibilitas dievaluasi berdasarkan kontrak yang dideklarasikan.

## 29. Titik Ekstensi Masa Depan

Arsitektur saat ini menyediakan ruang untuk event kanonis tambahan, metadata manifest, konfigurasi, permission/capability, deklarasi kompatibilitas versi host, dependency, penyimpanan persisten, API, metadata distribusi, dan interaksi antar-Add-On yang terkontrol.

Ini adalah kemungkinan pengembangan, bukan persyaratan kontrak saat ini. Jangan mengimplementasikannya hanya karena arsitektur menyediakan ruang.

## 30. Definisi Selesai

Add-On belum dianggap selesai hanya karena ZIP berhasil dipasang. Add-On berkualitas produksi seharusnya memiliki implementasi, manifest valid, call path host nyata, lifecycle bila relevan, validasi kontrak event/input/hasil, integrasi UI bila relevan, isolasi kegagalan, integration test otomatis, validasi lokal nyata, kegagalan yang dapat diamati, dan dokumentasi.

Urutan engineering yang disarankan:

```text
PATCH → REAL TEST → DOCUMENT
```

## 31. Checklist Developer

Sebelum mendistribusikan Add-On:
- [ ] ID unik dan stabil;
- [ ] `manifest.json` valid;
- [ ] entrypoint tersedia;
- [ ] `run(context)` mengikuti kontrak;
- [ ] mode invocation benar;
- [ ] event dideklarasikan untuk `on_event`;
- [ ] tidak ada event untuk `on_demand`;
- [ ] kontrak hasil benar;
- [ ] kontrak UI benar bila berlaku;
- [ ] semantik `result_key` dipahami;
- [ ] lifecycle hook hanya dari daftar yang didukung;
- [ ] paket lolos validasi keamanan ZIP;
- [ ] status nonaktif mencegah eksekusi;
- [ ] kegagalan terisolasi;
- [ ] integration test lulus;
- [ ] eksekusi lokal nyata divalidasi;
- [ ] dokumentasi disertakan.

---

**Implementasi referensi:** `addons/just-sample/`

**Batas host:** `services/addon_manager.py`

**Cakupan publik:** mekanisme Add-On, Add-On Manager, kontrak, lifecycle, event system, dan `just-sample`.
