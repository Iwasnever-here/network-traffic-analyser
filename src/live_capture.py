from scapy.all import sniff


def start_live_capture(analyser, packet_count=0):
    def handle_packet(packet):
        analyser.process_packet(packet)

    sniff(
        prn=handle_packet,
        store=False,
        count=packet_count
    )