from scapy.all import IP, TCP, wrpcap

packets = []

# normal traffic
for timestamp in [0, 5, 10]:
    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
    packet.time = timestamp
    packets.append(packet)

# traffic spike
for _ in range(30):
    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
    packet.time = 15
    packets.append(packet)

wrpcap("sample.pcap", packets)

print("Created sample.pcap")