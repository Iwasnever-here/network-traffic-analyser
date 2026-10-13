from scapy.all import IP, TCP

from src.analyser import TrafficAnalyser


def test_packet_count_and_total_bytes():
    analyser = TrafficAnalyser()

    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    analyser.process_packet(packet)

    snapshot = analyser.snapshot()

    assert snapshot["packet_count"] == 1
    assert snapshot["total_bytes"] == len(packet)


def test_protocol_count():
    analyser = TrafficAnalyser()

    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    analyser.process_packet(packet)

    snapshot = analyser.snapshot()

    assert snapshot["protocol_counts"]["TCP"] == 1


def test_source_bytes():
    analyser = TrafficAnalyser()

    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    analyser.process_packet(packet)

    snapshot = analyser.snapshot()

    assert snapshot["bytes_by_source"]["192.168.1.1"] == len(packet)


def test_destination_bytes():
    analyser = TrafficAnalyser()

    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    analyser.process_packet(packet)

    snapshot = analyser.snapshot()

    assert snapshot["bytes_by_destination"]["8.8.8.8"] == len(packet)


def test_connection_bytes():
    analyser = TrafficAnalyser()

    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    analyser.process_packet(packet)

    snapshot = analyser.snapshot()

    connection = ("192.168.1.1", "8.8.8.8")

    assert snapshot["connection_bytes"][connection] == len(packet)


def test_spike_detection():
    analyser = TrafficAnalyser()

    packets = []

    # normal traffic in three windows
    for timestamp in [0, 5, 10]:
        packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
        packet.time = timestamp
        packets.append(packet)

    # large spike in fourth window
    for _ in range(30):
        packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
        packet.time = 15
        packets.append(packet)

    for packet in packets:
        analyser.process_packet(packet)

    spikes = analyser.detect_spikes()

    assert len(spikes) == 1
    assert spikes[0][0] == 3


def test_normal_traffic_does_not_trigger_spike():
    analyser = TrafficAnalyser()

    for timestamp in [0, 5, 10, 15]:
        packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
        packet.time = timestamp
        analyser.process_packet(packet)

    spikes = analyser.detect_spikes()

    assert len(spikes) == 0