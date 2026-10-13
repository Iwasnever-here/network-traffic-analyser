from scapy.all import sniff


def start_live_capture(analyser):
    sniff(
        prn=analyser.process_packet,
        store=False
    )