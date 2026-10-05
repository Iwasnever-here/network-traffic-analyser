from scapy.layers.inet import IP, TCP, UDP, ICMP

from src.models import Packetinfo

def parse_packet(packet):
    if IP not in packet:
        return None
    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
        
    return Packetinfo(
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        protocol=protocol,
        size=len(packet),
        timestamp=float(packet.time)
    )