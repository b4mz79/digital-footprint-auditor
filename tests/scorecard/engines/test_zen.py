from __future__ import annotations

import importlib.util

def test_zen_candidate_is_optional_until_selected() -> None:
    """Do not make an OSS candidate a production dependency."""
    installed = importlib.util.find_spec("zen") is not None
    if installed:
        import zen  # type: ignore[import-not-found]
        assert hasattr(zen, "ZenEngine")
    else:
        assert installed is False
