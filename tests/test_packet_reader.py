from scapy.all import IP, TCP, UDP, ICMP, Ether

from src.packet_reader import parse_packet


def test_parse_tcp_packet():
    packet = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()

    result = parse_packet(packet)

    assert result.src_ip == "192.168.1.1"
    assert result.dst_ip == "8.8.8.8"
    assert result.protocol == "TCP"


def test_parse_udp_packet():
    packet = IP(src="192.168.1.1", dst="8.8.8.8") / UDP()

    result = parse_packet(packet)

    assert result.protocol == "UDP"


def test_parse_icmp_packet():
    packet = IP(src="192.168.1.1", dst="8.8.8.8") / ICMP()

    result = parse_packet(packet)

    assert result.protocol == "ICMP"


def test_non_ip_packet_returns_none():
    packet = Ether()

    result = parse_packet(packet)

    assert result is None