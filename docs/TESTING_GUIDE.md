# Integration Test Guide

## Install

```
pip install -r requirements.txt
pip install -r requirements-test.txt
```

## Run

```
pytest
```

## Contributor rules

EN:
- Add regression tests for every change in security logic.
- Don't use production data.
- All AI output must still pass a validation layer.
- Keep UNKNOWN/gray as the default if evidence is insufficient.

ID:
- Tambahkan regression test untuk setiap perubahan security logic.
- Jangan menggunakan data produksi.
- Semua AI output harus tetap melewati validation layer.
- Pertahankan UNKNOWN/gray sebagai default jika evidence tidak cukup.
