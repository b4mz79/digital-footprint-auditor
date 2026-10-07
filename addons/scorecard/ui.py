from __future__ import annotations

from typing import Any, Mapping

import pandas as pd
import streamlit as st

_RISK_ICONS = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unknown": "UNKNOWN",
}

def _risk_key(value: Any) -> str:
    key = str(value or "unknown").strip().casefold()
    return key if key in _RISK_ICONS else "unknown"

def render(context: Mapping[str, Any]) -> None:
    """Render the Scorecard result supplied by the host UI invoker."""
    result_wrapper = context.get("result")
    if not isinstance(result_wrapper, Mapping):
        return
    result = result_wrapper.get("scorecard")
    if not isinstance(result, Mapping):
        return
    st.divider()
    st.subheader("Scorecard Add-on")
    risk_key = _risk_key(result.get("risk_band"))
    score = result.get("score")
    score_text = "UNKNOWN" if score is None else "{:.2f}".format(float(score))
    st.metric("Score", score_text)
    st.markdown("**Risk band:** " + _RISK_ICONS[risk_key] + " • **State:** `" + str(result.get("state", "unknown")) + "`")
    st.caption("Scorecard: `" + str(result.get("scorecard_id", "-")) + "` / version `" + str(result.get("scorecard_version", "-")) + "` • Result: `" + str(result.get("result_id", "-")) + "`")
    contributions = result.get("contributions") or []
    if isinstance(contributions, list):
        rows = [
            {
                "KPI": item.get("kpi_id", ""),
                "Value": item.get("value"),
                "Weight": item.get("weight"),
                "Contribution": item.get("contribution"),
            }
            for item in contributions
            if isinstance(item, Mapping)
        ]
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch")
    lineage = result.get("calculation_lineage")
    if lineage:
        with st.expander("Scorecard calculation lineage", expanded=False):
            st.json(lineage)
