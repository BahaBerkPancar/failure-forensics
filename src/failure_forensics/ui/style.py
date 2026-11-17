"""Palette and the one stylesheet. The stylesheet is a constant written here; no data ever goes into it."""

from __future__ import annotations

LIGHT = {
    "bg": "#F8F8F6", "surface": "#EFEFEC", "line": "#DAD9D3", "text": "#1D1D1B", "text2": "#55554F",
    "muted": "#85857E", "accent": "#B23A24",
    "ramp": ["#3A3A36", "#66665F", "#8E8E86", "#B4B4AC", "#CFCFC8"], "other": "#E3E3DD",
}
DARK = {
    "bg": "#161615", "surface": "#1F1F1D", "line": "#34342F", "text": "#ECECE8", "text2": "#B4B4AC",
    "muted": "#85857E", "accent": "#E4806A",
    "ramp": ["#E2E2DA", "#BDBDB5", "#97978F", "#74746C", "#58584F"], "other": "#3E3E39",
}


def palette() -> dict:
    """Colours for charts, matching the active Streamlit theme (light when it cannot be read)."""
    try:
        import streamlit as st

        return DARK if st.context.theme.type == "dark" else LIGHT
    except Exception:  # noqa: BLE001 - no browser context, e.g. in tests
        return LIGHT


CSS = """
<style>
:root { --ff-accent: #B23A24; --ff-line: rgba(29,29,27,.12); --ff-muted: #85857E; --ff-text2: #55554F; }
@media (prefers-color-scheme: dark) { :root { --ff-accent: #E4806A; --ff-line: rgba(236,236,232,.14); } }
html, body, .stApp, [class*="st-"]:not([data-testid="stIconMaterial"]):not([class*="Icon"]) {
  font-family: "Avenir Next", "Segoe UI", system-ui, sans-serif; font-variant-numeric: tabular-nums;
}
code, pre, kbd, samp, .ff-mono { font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace !important; }
h1, h2, h3 { font-family: "Iowan Old Style", "Charter", "Palatino", Georgia, serif !important;
  font-weight: 500 !important; letter-spacing: -0.01em; }
h1 { font-size: 32px !important; line-height: 40px !important; padding: 0 0 4px !important; }
h2 { font-size: 22px !important; line-height: 28px !important; padding: 24px 0 8px !important; }
h3 { font-size: 18px !important; line-height: 24px !important; padding: 16px 0 8px !important; }
.block-container { max-width: 1280px; padding: 48px 32px 64px !important; }
header[data-testid="stHeader"] { background: transparent; }

/* sidebar */
section[data-testid="stSidebar"] { border-right: 1px solid var(--ff-line); }
section[data-testid="stSidebar"] [data-testid="stSidebarContent"] { padding: 8px 8px 24px; }
[data-testid="stPageLink-NavLink"] { height: 36px; padding: 0 12px; border-radius: 8px; }
[data-testid="stPageLink-NavLink"][aria-current="page"] { background: rgba(127,127,120,.14); font-weight: 500; }
.ff-brand { font-family: "Iowan Old Style", Charter, Georgia, serif; font-size: 20px; line-height: 28px; padding: 16px 12px 0; }
.ff-brand-sub { color: var(--ff-muted); font-size: 13px; line-height: 20px; padding: 0 12px 16px; }
.ff-side-meta { color: var(--ff-muted); font-size: 13px; line-height: 20px; padding: 8px 12px; }
.ff-side-meta span { color: var(--ff-text2); }

/* page header */
.ff-sub { color: var(--ff-text2); font-size: 15px; line-height: 24px; margin: 0 0 24px; }
.ff-label { color: var(--ff-muted); font-size: 13px; line-height: 20px; }

/* figures */
[data-testid="stMetric"] { border-top: 1px solid var(--ff-line); padding: 12px 0 0; }
[data-testid="stMetricLabel"] p { color: var(--ff-muted); font-size: 13px; }
[data-testid="stMetricValue"], [data-testid="stMetricValue"] * { font-family: "Iowan Old Style", Charter, Georgia, serif; font-size: 36px; line-height: 44px; font-weight: 400; }

/* culprit rule and diff */
.st-key-culprit, .st-key-diverge { border-left: 3px solid var(--ff-accent); padding: 4px 0 4px 20px; }
.st-key-culprit p, .st-key-diverge p { margin: 0; }
.ff-chip { display: inline-flex; align-items: center; gap: 8px; font-size: 14px; line-height: 20px; color: var(--ff-text2); }
.ff-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ff-muted); display: inline-block; }
.ff-dot.fail { background: var(--ff-accent); }
.ff-dot.ok { background: #6F8F6B; }
.ff-meta { color: var(--ff-text2); font-size: 14px; line-height: 24px; }

[data-testid="stExpander"] { border: 1px solid var(--ff-line); border-radius: 12px; }
[data-testid="stExpander"] details summary { padding: 8px 16px; }
[data-testid="stDataFrame"] { border: 1px solid var(--ff-line); border-radius: 12px; overflow: hidden; }
button { transition: background-color .12s ease, border-color .12s ease, color .12s ease; }
</style>
"""
