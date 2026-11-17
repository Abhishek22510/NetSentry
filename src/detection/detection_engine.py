
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import pandas as pd

DEFAULT_CONFIG=Path(__file__).resolve().parents[2]/'config'/'detection_config.json'

def load_config(path=DEFAULT_CONFIG):
    with open(path, encoding='utf-8') as f: return json.load(f)

def _frame(records):
    df=pd.DataFrame([r.to_dict() if hasattr(r,'to_dict') else r for r in records])
    if df.empty:
        return df
    df['epoch']=pd.to_numeric(df['epoch'],errors='coerce').fillna(0); df['packet_size']=pd.to_numeric(df['packet_size'],errors='coerce').fillna(0)
    df['timestamp']=df['timestamp'].fillna('')
    return df.sort_values('epoch')

def _alert(rid,name,df,threshold,observed,count,severity,description,steps,source=None,destination=None,protocol=None,window=None,sp=None,dp=None):
    return {'alert_id':f'{rid}-{len(df)}-{int(observed) if isinstance(observed,(int,float)) else observed}','detection_id':rid,'detection_name':name,'timestamp':datetime.now(timezone.utc).isoformat(),'detection_window':window or 'capture-wide','source_ip':source,'destination_ip':destination,'source_port':sp,'destination_port':dp,'protocol':protocol,'severity':severity,'description':description,'triggered_threshold':threshold,'observed_value':observed,'matching_packet_count':int(count),'supporting_evidence':f'{count} matching packet(s); observed value {observed}.','recommended_investigation_steps':steps}

def run_detections(records, config=None):
    cfg=config or load_config(); rules=cfg.get('rules',{}); df=_frame(records); alerts=[]
    if df.empty: return alerts
    def enabled(r): return rules.get(r,{}).get('enabled',True)
    # NET-001
    r=rules.get('NET-001',{}); w=r.get('window_seconds',10); threshold=r.get('unique_ports',20)
    if enabled('NET-001'):
        for (src,dst),g in df[df.destination_port.notna()].groupby(['source_ip','destination_ip']):
            for start in g.epoch:
                x=g[(g.epoch>=start)&(g.epoch<=start+w)]; n=x.destination_port.nunique()
                if n>=threshold: alerts.append(_alert('NET-001',r.get('name','Possible Port Scan'),x,threshold,n,len(x),r.get('severity','Medium'),'Many destination ports contacted in a short window; this is a heuristic, not proof of scanning.','Validate the source asset, review port/service context, and correlate with authentication and endpoint telemetry.',src,dst,'TCP/UDP',f'{w}s')); break
    # NET-002
    r=rules.get('NET-002',{}); w=r.get('window_seconds',10); threshold=r.get('syn_packets',30)
    if enabled('NET-002'):
        syn=df[(df.protocol=='TCP') & df.tcp_flags.fillna('').str.contains('S') & ~df.tcp_flags.fillna('').str.contains('A')]
        for (src,dst),g in syn.groupby(['source_ip','destination_ip']):
            for start in g.epoch:
                x=g[(g.epoch>=start)&(g.epoch<=start+w)]
                if len(x)>=threshold: alerts.append(_alert('NET-002',r.get('name','Unusually High TCP SYN Activity'),x,threshold,len(x),len(x),r.get('severity','High'),'Suspicious SYN activity from one source to one destination; not automatically a SYN flood.','Check completed handshakes, destination service health, and source legitimacy.',src,dst,'TCP',f'{w}s')); break
    # NET-003
    r=rules.get('NET-003',{}); w=r.get('window_seconds',10); threshold=r.get('packet_count',50)
    if enabled('NET-003'):
        x=df[df.protocol=='ICMP'];
        if len(x)>=threshold: alerts.append(_alert('NET-003',r.get('name','ICMP Burst'),x,threshold,len(x),len(x),r.get('severity','Medium'),'High ICMP volume in this capture.','Determine whether diagnostic activity is authorized and correlate with host/network baselines.'))
    # NET-004
    r=rules.get('NET-004',{}); w=r.get('window_seconds',60); threshold=r.get('query_count',50)
    if enabled('NET-004'):
        q=df[df.is_dns_query.fillna(False)]
        for src,g in q.groupby('source_ip'):
            for start in g.epoch:
                x=g[(g.epoch>=start)&(g.epoch<=start+w)]
                if len(x)>=threshold: alerts.append(_alert('NET-004',r.get('name','DNS Query Spike'),x,threshold,len(x),len(x),r.get('severity','Medium'),'High DNS query volume from one source.','Review queried domains, process ownership, resolver policy, and possible automation or tunneling indicators.',src,None,'DNS',f'{w}s')); break
    # NET-005
    r=rules.get('NET-005',{}); threshold=r.get('max_query_length',100)
    if enabled('NET-005'):
        for _,x in df[df.dns_query_name.notna()].groupby(df.dns_query_name.fillna('').str.len()>threshold):
            if _:
                for _,row in x.iterrows(): alerts.append(_alert('NET-005',r.get('name','Long DNS Query Name'),x,threshold,len(str(row.dns_query_name)),1,r.get('severity','Low'),'DNS query name exceeds the configured length; long names can be legitimate.','Inspect the full domain, encoding patterns, query frequency, and originating process.',row.source_ip,row.destination_ip,'DNS',sp=row.source_port,dp=row.destination_port))
    # NET-006
    r=rules.get('NET-006',{}); expected=set(r.get('expected_ports',[]))
    if enabled('NET-006'):
        for _,row in df[df.destination_port.notna() & ~df.destination_port.isin(expected)].iterrows(): alerts.append(_alert('NET-006',r.get('name','Unusual Destination Port'),df,r.get('expected_ports',[]),int(row.destination_port),1,r.get('severity','Low'),'Traffic targets a port outside the configured expected list; uncommon does not automatically mean malicious.','Identify the service, validate business justification, and compare with host baselines.',row.source_ip,row.destination_ip,row.protocol,sp=row.source_port,dp=row.destination_port))
    # NET-007
    r=rules.get('NET-007',{}); threshold=r.get('bytes',10485760); w=r.get('window_seconds',60)
    if enabled('NET-007'):
        for src,g in df.groupby('source_ip'):
            for start in g.epoch:
                x=g[(g.epoch>=start)&(g.epoch<=start+w)]; n=x.packet_size.sum()
                if n>=threshold: alerts.append(_alert('NET-007',r.get('name','High Traffic Volume'),x,threshold,int(n),len(x),r.get('severity','Medium'),'Source traffic volume exceeds the configured time-window threshold.','Validate transfer purpose, destination reputation, and endpoint process context.',src,None,'ANY',f'{w}s')); break
    # NET-008
    r=rules.get('NET-008',{}); ratio=r.get('rst_ratio',.5); minimum=r.get('minimum_tcp_packets',20)
    if enabled('NET-008'):
        tcp=df[df.protocol=='TCP'];
        for src,g in tcp.groupby('source_ip'):
            if len(g)>=minimum:
                rst=g.tcp_flags.fillna('').str.contains('R').sum(); observed=rst/len(g)
                if observed>ratio: alerts.append(_alert('NET-008',r.get('name','High TCP Reset Ratio'),g,ratio,round(observed,3),len(g),r.get('severity','Medium'),'TCP resets exceed the configured ratio with enough packets for a meaningful heuristic.','Review failed connections, service availability, middleboxes, and application errors.',src,None,'TCP'))
    # duplicate reduction
    seen=set(); out=[]
    for a in alerts:
        key=(a['detection_id'],a.get('source_ip'),a.get('destination_ip'),a.get('destination_port'))
        if key not in seen: seen.add(key); out.append(a)
    return out
