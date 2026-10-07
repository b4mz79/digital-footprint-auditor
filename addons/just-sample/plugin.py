from __future__ import annotations

from typing import Any, Mapping


def run(context: Mapping[str, Any]) -> dict[str, Any]:
    """Process the canonical IMAP completion payload."""
    data = context.get("data")
    if not isinstance(data, Mapping):
        raise TypeError("just-sample requires context['data'] as a mapping")

    services = data.get("services", [])
    if not isinstance(services, list):
        raise TypeError("just-sample requires data['services'] as a list")

    return {
        "jumlah_email": len(services),
    }
