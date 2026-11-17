"""Generate harmless offline synthetic captures; never sends packets."""
from pathlib import Path
from scapy.all import IP,TCP,UDP,ICMP,DNS,DNSQR,wrpcap
OUT=Path(__file__).resolve().parents[1]/'data/samples'; OUT.mkdir(parents=True,exist_ok=True)
def write(name,packets): wrpcap(str(OUT/name),packets); print(f'Wrote synthetic capture {OUT/name} ({len(packets)} packets)')
def main():
 normal=[IP(src='10.0.0.10',dst='10.0.0.20')/TCP(sport=40000,dport=443,flags='S'),IP(src='10.0.0.20',dst='10.0.0.10')/TCP(sport=443,dport=40000,flags='SA'),IP(src='10.0.0.10',dst='8.8.8.8')/UDP(sport=50000,dport=53)]; write('normal_traffic.pcap',normal)
 dns=[IP(src='10.0.0.10',dst='8.8.8.8')/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname='example.com')) for i in range(5)]; write('dns_queries.pcap',dns)
 write('icmp_test.pcap',[IP(src='10.0.0.10',dst='10.0.0.20')/ICMP() for _ in range(5)])
 write('port_scan_test.pcap',[IP(src='10.0.0.10',dst='10.0.0.20')/TCP(sport=40000+i,dport=1000+i,flags='S') for i in range(25)])
 write('syn_activity_test.pcap',[IP(src='10.0.0.10',dst='10.0.0.20')/TCP(sport=40000+i,dport=443,flags='S') for i in range(35)])
 write('dns_spike_test.pcap',[IP(src='10.0.0.10',dst='8.8.8.8')/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=f'x{i}.example.com')) for i in range(55)])
 write('rst_ratio_test.pcap',[IP(src='10.0.0.10',dst='10.0.0.20')/TCP(sport=40000+i,dport=443,flags='R') for i in range(15)]+[IP(src='10.0.0.10',dst='10.0.0.20')/TCP(sport=41000+i,dport=443,flags='A') for i in range(5)])
if __name__=='__main__': main()
