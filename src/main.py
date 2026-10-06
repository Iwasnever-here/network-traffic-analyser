from scapy.all import rdpcap

from src.analyser import TrafficAnalyser


packets = rdpcap("sample.pcap")

analyser = TrafficAnalyser()

for packet in packets:
    analyser.process_packet(packet)


print("=======================================")
print("   NETWORK TRAFFIC ANALYSIS REPORT")
print("=======================================")
print("Packets analysed:", analyser.packet_count)
print("Total Traffic:", analyser.total_bytes, "B")

print("---------------------------------------")
print("Protocol Breakdown:")
for protocol, count in analyser.protocol_counts.items():
    print(f"{protocol}: {count} packets")
print("---------------------------------------")
print("Top Sources:")
for source, count in analyser.top_sources():
    print(f"{source}: {count} B")
print("---------------------------------------")
print("Top Destinations:")
for destination, count in analyser.top_destinations():
    print(f"{destination}: {count} B")
print("---------------------------------------")
print("Top Connections:")
for connection, count in analyser.top_connections():
    src, dst = connection
    print(f"{src} -> {dst}: {count} B")

print("---------------------------------------")
print("Traffic by 5-second window:")

for window, total_bytes in analyser.traffic_windows():
    print(f"Window {window}: {total_bytes} B")

print("---------------------------------------")
print("Traffic Spikes:")

spikes = analyser.detect_spikes()

if not spikes:
    print("No spikes detected")
else:
    for window, total_bytes, average in spikes:
        multiplier = total_bytes / average

        print(
            f"Window {window}: "
            f"{total_bytes} B "
            f"({multiplier:.2f}x recent average)"
        )