"""Streamlit entry point: `ff ui` runs this file. The database path arrives in $FF_UI_DB."""

from __future__ import annotations

import os

import streamlit as st

from failure_forensics.ui import views


def main() -> None:
    db = os.environ.get("FF_UI_DB", "")
    st.set_page_config(page_title="failure-forensics", layout="wide", initial_sidebar_state="expanded")
    if not db:
        st.error("No database given. Start the UI with `ff ui --db PATH`.")
        st.stop()
    pages = {
        "overview": st.Page(lambda: views.overview_page(db), title="Overview", url_path="overview", default=True),
        "runs": st.Page(lambda: views.runs_page(db), title="Runs", url_path="runs"),
        "run": st.Page(lambda: views.run_page(db), title="Run detail", url_path="run"),
        "clusters": st.Page(lambda: views.clusters_page(db), title="Clusters", url_path="clusters"),
        "diff": st.Page(lambda: views.diff_page(db), title="Diff", url_path="diff"),
    }
    views.PAGES.update(pages)
    nav = st.navigation(list(pages.values()), position="hidden")
    views.sidebar(db)
    nav.run()


main()
