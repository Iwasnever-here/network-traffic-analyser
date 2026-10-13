import argparse

from scapy.all import rdpcap
import os
import threading
import time

from src.analyser import TrafficAnalyser
from src.live_capture import start_live_capture
from datetime import datetime

def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")


def print_report(analyser):
    print()
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

    for source, bytes_sent in analyser.top_sources():
        print(f"{source}: {bytes_sent} B")

    print("---------------------------------------")
    print("Top Destinations:")

    for destination, bytes_received in analyser.top_destinations():
        print(f"{destination}: {bytes_received} B")

    print("---------------------------------------")
    print("Top Connections:")

    for connection, total_bytes in analyser.top_connections():
        src, dst = connection
        print(f"{src} -> {dst}: {total_bytes} B")

    print("---------------------------------------")
    print("Traffic by 5-second window:")

    for window, total_bytes in analyser.traffic_windows():
        timestamp = window * analyser.window_size
        readable_time = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")

        print(f"{readable_time}: {total_bytes} B")

    print("---------------------------------------")
    print("Traffic Spikes:")

    spikes = analyser.detect_spikes()

    if not spikes:
        print("No spikes detected")
    else:

        for window, total_bytes, average in spikes:
            multiplier = total_bytes / average

            timestamp = window * analyser.window_size
            readable_time = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")

            print(
                f"{readable_time}: "
                f"{total_bytes} B "
                f"({multiplier:.2f}x recent average)"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyser"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--file",
        help="Analyse a PCAP file"
    )

    group.add_argument(
        "--live",
        action="store_true",
        help="Capture live network traffic"
    )

    args = parser.parse_args()

    analyser = TrafficAnalyser()

    if args.file:
        packets = rdpcap(args.file)

        for packet in packets:
            analyser.process_packet(packet)

    elif args.live:
        print("Starting live network capture...")
        print("Press Ctrl+C to stop.")

        capture_thread = threading.Thread(
            target=start_live_capture,
            args=(analyser,),
            daemon=True
        )

        capture_thread.start()

        try:
            while True:
                clear_terminal()

                print("LIVE NETWORK TRAFFIC")
                print("Press Ctrl+C to stop")

                print_report(analyser)

                time.sleep(2)

        except KeyboardInterrupt:
            print("\nCapture stopped.")
            return

    print_report(analyser)


if __name__ == "__main__":
    main()