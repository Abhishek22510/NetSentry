import streamlit as st
from app import _init
from src.analysis.protocol_analyzer import analyze_protocols
_init(); st.title('Protocol Analysis'); a=analyze_protocols(st.session_state.records)
if not st.session_state.records: st.info('Analyze a capture from the sidebar first.')
else:
 c=st.columns(4)
 for x,(k,v) in zip(c,[('TCP',a['tcp']['packets']),('UDP',a['udp']['packets']),('ICMP',a['icmp']['packets']),('DNS queries',a['dns']['queries'])]): x.metric(k,v)
 st.subheader('TCP flags'); st.bar_chart(a['tcp_flags'])
 st.subheader('Top destination ports'); st.dataframe(a['top_destination_ports'],use_container_width=True)
