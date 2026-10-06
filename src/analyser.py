from src.packet_reader import parse_packet
from collections import defaultdict, deque

class TrafficAnalyser:
    def __init__(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.bytes_by_source = defaultdict(int)
        self.bytes_by_destination = defaultdict(int)
        self.connection_counts = defaultdict(int)
        self.connection_bytes = defaultdict(int)

        self.window_size = 5
        self.bytes_by_window = defaultdict(int)
        self.recent_windows = deque(maxlen=5)
        self.spike_threshold = 3.0

    def process_packet(self, packet):
        parsed_packet = parse_packet(packet)
        if parsed_packet:
            self.packet_count += 1
            self.total_bytes += parsed_packet.size
            self.bytes_by_source[parsed_packet.src_ip] += parsed_packet.size
            self.bytes_by_destination[parsed_packet.dst_ip] += parsed_packet.size
            self.protocol_counts[parsed_packet.protocol] += 1

            window = int(parsed_packet.timestamp) // self.window_size
            self.bytes_by_window[window] += parsed_packet.size

            connection = (
                parsed_packet.src_ip,
                parsed_packet.dst_ip,   
            )

            self.connection_counts[connection] += 1
            self.connection_bytes[connection] += parsed_packet.size



    def top_sources(self, n=5):
        return sorted(
            self.bytes_by_source.items(), key=lambda x: x[1], reverse=True
        )[:n]

    def top_destinations(self, n=5):
        return sorted(
            self.bytes_by_destination.items(), key=lambda x: x[1], reverse=True
        )[:n]

    def top_connections(self, n=5):
        return sorted(
            self.connection_bytes.items(),
            key=lambda item: item[1],
            reverse=True
        )[:n]


    def traffic_windows(self):
        return sorted(self.bytes_by_window.items())

    def detect_spikes(self):
        spikes = []
        self.recent_windows.clear()

        for window, total_bytes in self.traffic_windows():
            if len(self.recent_windows) >= 3:
                avarage = sum(self.recent_windows) / len(self.recent_windows)
                if avarage > 0 and total_bytes > avarage * self.spike_threshold:
                    spikes.append((window, total_bytes, avarage))

            self.recent_windows.append(total_bytes)

        return spikes