from __future__ import annotations

import pytest


def test_zen_candidate_is_optional_until_selected() -> None:
    """Do not make an OSS candidate a production dependency."""
    zen = pytest.importorskip(
        "zen", reason="ZEN candidate is not installed in this environment"
    )
    assert hasattr(zen, "ZenEngine")
