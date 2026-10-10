from __future__ import annotations

import services.osint_scanner as osint_scanner


def test_osint_http_client_does_not_trust_environment_by_default(monkeypatch):
    captured = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def aclose(self):
            return None

    monkeypatch.delenv("HTTPX_TRUST_ENV", raising=False)
    monkeypatch.setattr(osint_scanner.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(osint_scanner, "_load_holehe_modules", lambda: [])

    assert osint_scanner.scan_osint_footprint("user@example.com") == []
    assert captured["trust_env"] is False


def test_osint_http_client_can_explicitly_trust_environment(monkeypatch):
    captured = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def aclose(self):
            return None

    monkeypatch.setenv("HTTPX_TRUST_ENV", "true")
    monkeypatch.setattr(osint_scanner.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(osint_scanner, "_load_holehe_modules", lambda: [])

    assert osint_scanner.scan_osint_footprint("user@example.com") == []
    assert captured["trust_env"] is True
