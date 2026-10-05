from scapy.all import IP, TCP, UDP, ICMP
from src.analyser import TrafficAnalyser


packets = [
    IP(src="192.168.1.1", dst="192.168.1.2") / TCP(),
    IP(src="192.168.1.1", dst="8.8.8.8") / UDP(),
    IP(src="192.168.1.2", dst="8.8.8.8") / TCP(),
    IP(src="192.168.1.3", dst="192.168.1.1") / ICMP(),
]

analyser = TrafficAnalyser()

for packet in packets:
    analyser.process_packet(packet)

print("Packets:", analyser.packet_count)
print("Bytes:", analyser.total_bytes)
print("Protocols:", dict(analyser.protocol_counts))
print("Bytes by Source:", dict(analyser.bytes_by_source))
print("Bytes by Destination:", dict(analyser.bytes_by_destination))
print("Top Sources:", analyser.top_sources())
print("Top Destinations:", analyser.top_destinations())
print("Top Connections:", analyser.top_connections())