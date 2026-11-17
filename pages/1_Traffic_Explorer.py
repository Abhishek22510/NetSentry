import streamlit as st
from app import _init
from src.capture.pcap_parser import records_to_dataframe
_init(); st.title('Traffic Explorer'); df=records_to_dataframe(st.session_state.records)
if df.empty: st.info('Analyze a capture from the sidebar first.')
else:
    for col in ['source_ip','destination_ip','protocol']:
        options=sorted(df[col].dropna().astype(str).unique()); chosen=st.multiselect(col.replace('_',' ').title(),options)
        if chosen: df=df[df[col].astype(str).isin(chosen)]
    st.dataframe(df,hide_index=True,use_container_width=True)
