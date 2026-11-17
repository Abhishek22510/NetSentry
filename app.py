
from __future__ import annotations
import json, tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from src.capture.pcap_parser import PcapParser, PcapParseError, records_to_dataframe
from src.analysis.traffic_analyzer import analyze_traffic
from src.analysis.protocol_analyzer import analyze_protocols
from src.analysis.dns_analyzer import analyze_dns
from src.detection.detection_engine import run_detections
from src.reporting.report_generator import build_report
ROOT=Path(__file__).resolve().parent; CONFIG=ROOT/'config/detection_config.json'

def load_config(): return json.loads(CONFIG.read_text(encoding='utf-8'))
def _init():
    if 'records' not in st.session_state: st.session_state.records=[]
    if 'capture_name' not in st.session_state: st.session_state.capture_name=''
    if 'alerts' not in st.session_state: st.session_state.alerts=[]
def render_sidebar():
    with st.sidebar:
        st.title('NetSentry'); st.caption('Offline PCAP investigation workspace'); st.divider()
        upload=st.file_uploader('Upload PCAP or PCAPNG',type=['pcap','pcapng','cap'])
        if upload:
            cfg=load_config(); max_mb=cfg['limits']['max_upload_size_mb']
            if upload.size>max_mb*1024*1024: st.error(f'File exceeds configured {max_mb} MB limit.')
            elif st.button('Analyze capture',type='primary'):
                with st.spinner('Parsing and analyzing safely...'):
                    try:
                        with tempfile.NamedTemporaryFile(suffix=Path(upload.name).suffix,delete=False) as tmp: tmp.write(upload.getbuffer()); path=tmp.name
                        records=PcapParser(max_mb,cfg['limits']['max_packets']).parse(path); st.session_state.records=records; st.session_state.capture_name=upload.name; st.session_state.alerts=run_detections(records,cfg); Path(path).unlink(missing_ok=True); st.success(f'Loaded {len(records):,} packets.')
                    except PcapParseError as exc: st.error(str(exc))
                    except Exception as exc: st.error(f'Analysis failed safely: {exc}')
        st.divider(); st.caption('Rule-based heuristics • no payload storage • no packet replay')
def overview():
    _init(); records=st.session_state.records; stats=analyze_traffic(records); alerts=st.session_state.alerts
    st.title('NetSentry'); st.caption('Network Traffic & Anomaly Detection Dashboard')
    if not records: st.info('Upload a synthetic or real PCAP from the sidebar to begin. No packets are transmitted or replayed.'); return
    cols=st.columns(5)
    for c,(label,val) in zip(cols,[('Packets',stats['packet_count']),('Bytes',f"{stats['total_bytes']:,}"),('Unique IPs',stats['unique_ips']),('Alerts',len(alerts)),('High/Critical',sum(a['severity'] in {'High','Critical'} for a in alerts))]): c.metric(label,val)
    c1,c2=st.columns(2); c1.subheader('Protocol distribution'); c1.bar_chart(pd.Series(stats['protocol_distribution'])); c2.subheader('Top communicating IPs'); c2.dataframe(pd.DataFrame(list(stats['top_source_ips'].items()),columns=['Source IP','Packets']),hide_index=True,use_container_width=True)
    st.subheader('Recent alerts'); st.dataframe(pd.DataFrame(alerts).head(10),hide_index=True,use_container_width=True)
def main():
    st.set_page_config(page_title='NetSentry | SOC Dashboard',page_icon='🛡️',layout='wide'); st.markdown('<style>.stApp{background:#0b1220;color:#e5edf8}.stMetric{background:#172033;border:1px solid #263653;border-radius:10px;padding:12px}</style>',unsafe_allow_html=True); render_sidebar(); overview()
if __name__=='__main__': main()
