from scapy.all import IP, TCP

from src.packet_reader import parse_packet

packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP()

result = parse_packet(packet)

print(result)
