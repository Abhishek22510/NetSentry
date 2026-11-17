import streamlit as st
from app import _init, load_config
from src.analysis.dns_analyzer import analyze_dns
_init(); st.title('DNS Investigation'); d=analyze_dns(st.session_state.records,load_config()['rules']['NET-005']['max_query_length'],load_config()['rules']['NET-004']['query_count'])
if not st.session_state.records: st.info('Analyze a capture from the sidebar first.')
else:
 st.metric('DNS queries',d['query_count']); st.subheader('Frequently queried domains'); st.dataframe(d['top_domains'],use_container_width=True); st.subheader('Long query names'); st.dataframe(d['long_queries'],hide_index=True,use_container_width=True)
