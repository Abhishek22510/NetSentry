import streamlit as st
from app import _init
import pandas as pd
_init(); st.title('Anomaly Alerts'); alerts=st.session_state.alerts
if not alerts: st.info('No heuristic alerts for the current capture. This does not prove the capture is safe.')
else:
 sev=st.multiselect('Severity',['Low','Medium','High','Critical']); det=st.multiselect('Detection ID',sorted({a['detection_id'] for a in alerts})); rows=[a for a in alerts if (not sev or a['severity'] in sev) and (not det or a['detection_id'] in det)]; st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
