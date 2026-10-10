from __future__ import annotations

from typing import Any, Mapping

import streamlit as st


def render(context: Mapping[str, Any]) -> None:
    """Render the number of IMAP results supplied by the add-on."""
    result = context.get("result")
    if not isinstance(result, Mapping):
        return

    jumlah_email = result.get("jumlah_email")
    if not isinstance(jumlah_email, int):
        return

    st.info(f"{jumlah_email} hasil scan email ditemukan sesuai kriteria")
