from src.capture.pcap_parser import PacketRecord
from src.detection.detection_engine import run_detections

def rec(i,proto='TCP',dport=443,flags='S',dns=False,size=100,src='10.0.0.1',dst='10.0.0.2'):
 return PacketRecord(i,f'2025-01-01T00:00:00+00:00',i*.1,size,src,dst,proto,40000+i,dport,flags,None,None,None,dns)
def test_rules_trigger():
 rs=[rec(i,dport=1000+i) for i in range(25)]+[rec(100+i,proto='ICMP',flags=None) for i in range(50)]
 ids={a['detection_id'] for a in run_detections(rs)}; assert 'NET-001' in ids and 'NET-003' in ids

def test_syn_threshold_false_positive(): assert not any(a['detection_id']=='NET-002' for a in run_detections([rec(i) for i in range(5)]))
