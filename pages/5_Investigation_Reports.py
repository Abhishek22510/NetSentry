import json
import streamlit as st

from app import _init
from src.reporting.report_generator import (
    build_report,
    build_pdf_bytes,
)


_init()

st.title("Investigation Reports")


if not st.session_state.records:
    st.info("Analyze a capture from the sidebar first.")

else:
    # Build the investigation report correctly
    report = build_report(
        filename=st.session_state.capture_name,
        records=st.session_state.records,
        alerts=st.session_state.alerts,
    )

    # Build the PDF separately
    pdf_bytes = build_pdf_bytes(
        filename=st.session_state.capture_name,
        records=st.session_state.records,
        alerts=st.session_state.alerts,
    )

    # Convert the report to JSON
    json_bytes = json.dumps(
        report,
        indent=2,
        default=str,
    ).encode("utf-8")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="Download PDF report",
            data=pdf_bytes,
            file_name="netsentry_investigation.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    with col2:
        st.download_button(
            label="Download JSON report",
            data=json_bytes,
            file_name="netsentry_investigation.json",
            mime="application/json",
            use_container_width=True,
        )

    st.subheader("Report Preview")

    st.json(report)
