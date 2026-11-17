from __future__ import annotations
import pandas as pd

def analyze_protocols(records):
    df=pd.DataFrame([r.to_dict() if hasattr(r,'to_dict') else r for r in records])
    def subset(proto): return df[df.get('protocol','').eq(proto)] if not df.empty else df
    tcp=subset('TCP'); udp=subset('UDP'); icmp=subset('ICMP'); dns=df[df.get('is_dns_query',False).fillna(False)] if not df.empty else df
    return {'tcp':{'packets':len(tcp),'bytes':int(tcp.packet_size.sum()) if not tcp.empty else 0},'udp':{'packets':len(udp),'bytes':int(udp.packet_size.sum()) if not udp.empty else 0},'icmp':{'packets':len(icmp),'bytes':int(icmp.packet_size.sum()) if not icmp.empty else 0},'dns':{'queries':len(dns)},'tcp_flags':tcp.tcp_flags.value_counts().to_dict() if not tcp.empty else {},'top_destination_ports':df.destination_port.value_counts().head(15).to_dict() if not df.empty else {}}
