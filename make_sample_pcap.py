from scapy.all import IP, TCP, UDP, ICMP, wrpcap


packets = [
    IP(src="192.168.1.1", dst="192.168.1.2") / TCP(),
    IP(src="192.168.1.1", dst="8.8.8.8") / UDP(),
    IP(src="192.168.1.2", dst="8.8.8.8") / TCP(),
    IP(src="192.168.1.3", dst="192.168.1.1") / ICMP(),
]

wrpcap("sample.pcap", packets)

print("Created sample.pcap")