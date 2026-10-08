# Network Traffic Analyser

A Python-based network traffic analyser built with Scapy.

The project reads packet capture (`.pcap`) files, extracts useful network metadata, aggregates traffic statistics, identifies the most active hosts and communication pairs, and detects unusual traffic spikes using fixed time windows and a rolling baseline.

The current version focuses on offline PCAP analysis. Live packet capture is planned as the next major feature.

## Features

- Parse IPv4 packets
- Detect TCP, UDP and ICMP traffic
- Extract source and destination IP addresses
- Track total packets and total bytes
- Aggregate traffic by source IP
- Aggregate traffic by destination IP
- Track source-to-destination connections
- Display top sources, destinations and connections
- Group traffic into 5-second time windows
- Detect traffic spikes using a rolling average
- Read packet data from `.pcap` files
- Unit tests for packet parsing and analyser behaviour

## Example Output

```text
=======================================
   NETWORK TRAFFIC ANALYSIS REPORT
=======================================
Packets analysed: 4
Total Traffic: 136 B
---------------------------------------
Protocol Breakdown:
TCP: 2 packets
UDP: 1 packets
ICMP: 1 packets
---------------------------------------
Top Sources:
192.168.1.1: 68 B
192.168.1.2: 40 B
192.168.1.3: 28 B
---------------------------------------
Top Destinations:
8.8.8.8: 68 B
192.168.1.2: 40 B
192.168.1.1: 28 B
---------------------------------------
Top Connections:
192.168.1.1 -> 192.168.1.2: 40 B
192.168.1.2 -> 8.8.8.8: 40 B
192.168.1.1 -> 8.8.8.8: 28 B
192.168.1.3 -> 192.168.1.1: 28 B
---------------------------------------
Traffic by 5-second window:
Window 0: 68 B
Window 1: 40 B
Window 2: 28 B
---------------------------------------
Traffic Spikes:
No spikes detected