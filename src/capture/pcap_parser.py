
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
import os

try:
    from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, PcapReader
except ImportError:  # allows importing utility code before dependencies are installed
    DNS = DNSQR = DNSRR = ICMP = IP = IPv6 = TCP = UDP = PcapReader = None

@dataclass(frozen=True)
class PacketRecord:
    packet_number: int
    timestamp: str
    epoch: float
    packet_size: int
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str = "OTHER"
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    dns_query_name: str | None = None
    dns_query_type: str | None = None
    dns_response_code: int | None = None
    is_dns_query: bool = False
    internal_source: bool | None = None
    internal_destination: bool | None = None

    def to_dict(self) -> dict[str, Any]: return asdict(self)

class PcapParseError(ValueError): pass

class PcapParser:
    def __init__(self, max_file_size_mb: int = 250, max_packets: int = 1_000_000):
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.max_packets = max_packets

    def validate_path(self, path: str | Path) -> Path:
        p = Path(path)
        if not p.exists() or not p.is_file(): raise PcapParseError(f"Capture file does not exist: {p}")
        if p.suffix.lower() not in {".pcap", ".pcapng", ".cap"}: raise PcapParseError("Only PCAP and PCAPNG files are supported.")
        if p.stat().st_size > self.max_file_size_bytes: raise PcapParseError(f"Capture exceeds the {self.max_file_size_bytes // (1024*1024)} MB file-size limit.")
        return p

    def iter_records(self, path: str | Path) -> Iterator[PacketRecord]:
        p = self.validate_path(path)
        if PcapReader is None: raise PcapParseError("Scapy is not installed; install requirements.txt first.")
        count = 0
        try:
            with PcapReader(str(p)) as reader:
                for packet in reader:
                    count += 1
                    if count > self.max_packets: raise PcapParseError(f"Capture exceeds the {self.max_packets:,} packet limit.")
                    yield self._record(packet, count)
        except PcapParseError: raise
        except Exception as exc: raise PcapParseError(f"Unable to parse capture safely: {exc}") from exc

    def parse(self, path: str | Path) -> list[PacketRecord]: return list(self.iter_records(path))

    @staticmethod
    def _record(packet: Any, number: int) -> PacketRecord:
        epoch = float(getattr(packet, "time", 0.0) or 0.0)
        timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else ""
        src = dst = None; proto = "OTHER"; sport = dport = None; flags = None
        if IP is not None and packet.haslayer(IP):
            layer = packet[IP]; src, dst = layer.src, layer.dst
        elif IPv6 is not None and packet.haslayer(IPv6):
            layer = packet[IPv6]; src, dst = layer.src, layer.dst
        if TCP is not None and packet.haslayer(TCP):
            layer = packet[TCP]; proto, sport, dport, flags = "TCP", int(layer.sport), int(layer.dport), str(layer.flags)
        elif UDP is not None and packet.haslayer(UDP):
            layer = packet[UDP]; proto, sport, dport = "UDP", int(layer.sport), int(layer.dport)
        elif ICMP is not None and packet.haslayer(ICMP): proto = "ICMP"
        elif src or dst: proto = "IP"
        qname = qtype = None; rcode = None; is_query = False
        if DNS is not None and packet.haslayer(DNS):
            dns = packet[DNS]; rcode = int(getattr(dns, "rcode", 0)) if getattr(dns, "rcode", None) is not None else None
            is_query = int(getattr(dns, "qr", 1)) == 0
            if DNSQR is not None and packet.haslayer(DNSQR):
                q = packet[DNSQR]; raw = getattr(q, "qname", b""); qname = raw.decode(errors="replace").rstrip(".") if isinstance(raw, bytes) else str(raw).rstrip(".")
                qtype = str(getattr(q, "qtype", ""))
                if proto == "OTHER": proto = "DNS"
        return PacketRecord(number, timestamp, epoch, len(packet), src, dst, proto, sport, dport, flags, qname, qtype, rcode, is_query)

def records_to_dataframe(records: list[PacketRecord]):
    import pandas as pd
    return pd.DataFrame([r.to_dict() for r in records])
