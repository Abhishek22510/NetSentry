from __future__ import annotations
import pandas as pd

def analyze_dns(records, long_query_length=100, high_volume_threshold=50):
    df=pd.DataFrame([r.to_dict() if hasattr(r,'to_dict') else r for r in records])
    if df.empty: return {'queries':pd.DataFrame(),'query_count':0,'top_domains':{},'by_source':{},'response_codes':{},'long_queries':pd.DataFrame(),'high_volume_sources':{}}
    q=df[df.get('is_dns_query',False).fillna(False)].copy()
    if q.empty: return {'queries':q,'query_count':0,'top_domains':{},'by_source':{},'response_codes':{},'long_queries':q,'high_volume_sources':{}}
    q['query_length']=q.dns_query_name.fillna('').astype(str).str.len()
    return {'queries':q,'query_count':len(q),'top_domains':q.dns_query_name.value_counts().head(20).to_dict(),'by_source':q.source_ip.value_counts().to_dict(),'response_codes':q.dns_response_code.value_counts(dropna=False).to_dict(),'long_queries':q[q.query_length>long_query_length],'high_volume_sources':{str(k):int(v) for k,v in q.source_ip.value_counts().items() if v>=high_volume_threshold}}
