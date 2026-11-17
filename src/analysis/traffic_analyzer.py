
from __future__ import annotations
import ipaddress
import pandas as pd

def _df(records):
    if isinstance(records, pd.DataFrame): df=records.copy()
    else: df=pd.DataFrame([r.to_dict() if hasattr(r,'to_dict') else r for r in records])
    for col in ['packet_size','epoch','source_port','destination_port']: df[col]=pd.to_numeric(df.get(col, pd.Series(dtype=float)), errors='coerce')
    return df

def is_internal_ip(value):
    try: return ipaddress.ip_address(str(value)).is_private
    except (ValueError, TypeError): return False

def analyze_traffic(records):
    df=_df(records)
    if df.empty: return {'packet_count':0,'total_bytes':0,'unique_source_ips':0,'unique_destination_ips':0,'unique_ips':0,'protocol_distribution':{},'top_source_ips':{},'top_destination_ips':{},'top_destination_ports':{},'conversations':pd.DataFrame(),'timeline':pd.DataFrame(),'packet_sizes':pd.DataFrame(),'tcp_flags':{},'internal_external':{}}
    df['internal_source']=df['source_ip'].map(is_internal_ip); df['internal_destination']=df['destination_ip'].map(is_internal_ip)
    def counts(col): return df[col].dropna().astype(str).value_counts().to_dict()
    conv=(df.groupby(['source_ip','destination_ip','protocol'], dropna=False).agg(packets=('packet_size','size'),bytes=('packet_size','sum')).reset_index().sort_values('packets',ascending=False))
    time_df=df.assign(timestamp_dt=pd.to_datetime(df['timestamp'], errors='coerce')).dropna(subset=['timestamp_dt'])
    timeline=time_df.set_index('timestamp_dt').resample('1min')['packet_size'].agg(['count','sum']).reset_index() if not time_df.empty else pd.DataFrame()
    return {'packet_count':len(df),'total_bytes':int(df['packet_size'].fillna(0).sum()),'unique_source_ips':int(df['source_ip'].nunique()),'unique_destination_ips':int(df['destination_ip'].nunique()),'unique_ips':int(pd.concat([df['source_ip'],df['destination_ip']]).nunique()),'protocol_distribution':counts('protocol'),'top_source_ips':counts('source_ip'),'top_destination_ips':counts('destination_ip'),'top_destination_ports':counts('destination_port'),'conversations':conv,'timeline':timeline,'packet_sizes':df[['packet_size']].dropna(),'tcp_flags':counts('tcp_flags'),'internal_external':{'internal_to_internal':int((df.internal_source & df.internal_destination).sum()),'internal_to_external':int((df.internal_source & ~df.internal_destination).sum()),'external_to_internal':int((~df.internal_source & df.internal_destination).sum())},'dataframe':df}
