from pathlib import Path
import json
from src.capture.pcap_parser import PacketRecord,PcapParser,PcapParseError
from src.analysis.traffic_analyzer import analyze_traffic
from src.analysis.dns_analyzer import analyze_dns
from src.reporting.report_generator import export_csv,export_json

def test_empty_analysis(): assert analyze_traffic([])['packet_count']==0
def test_traffic_aggregation():
 r=[PacketRecord(1,'2025-01-01T00:00:00+00:00',1,100,'10.0.0.1','8.8.8.8','UDP',1,53),PacketRecord(2,'2025-01-01T00:00:01+00:00',2,200,'10.0.0.1','8.8.8.8','TCP',2,443,'S')]
 a=analyze_traffic(r); assert a['packet_count']==2 and a['total_bytes']==300 and a['unique_ips']==2
def test_dns_extraction():
 r=[PacketRecord(1,'',1,70,'10.0.0.1','8.8.8.8','DNS',1,53,None,'a.example','1',0,True)]
 assert analyze_dns(r)['top_domains']=={'a.example':1}
def test_invalid_path():
 try: PcapParser().parse('/no/such/file.pcap')
 except PcapParseError: assert True
 else: assert False
def test_exports(tmp_path):
 r=[PacketRecord(1,'',1,10,'a','b','TCP')]; assert len(export_csv(tmp_path,'x.pcap',r,[]))==3; assert export_json(tmp_path,'x.pcap',r,[]).exists()
