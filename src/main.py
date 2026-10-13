import argparse
import os
import threading
import time
from collections import deque
from datetime import datetime

from scapy.all import rdpcap

from src.analyser import TrafficAnalyser
from src.live_capture import start_live_capture


def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")


def top_n(mapping, n=5):
    return sorted(
        mapping.items(),
        key=lambda item: item[1],
        reverse=True
    )[:n]


def detect_spikes_from_windows(
    windows,
    threshold=3.0,
    history_size=5
):
    recent = deque(maxlen=history_size)
    spikes = []

    for window, total_bytes in windows:
        if len(recent) >= 3:
            average = sum(recent) / len(recent)

            if average > 0 and total_bytes > average * threshold:
                spikes.append(
                    (window, total_bytes, average)
                )

        recent.append(total_bytes)

    return spikes


def print_report(analyser):
    snapshot = analyser.snapshot()

    print()
    print("=======================================")
    print("   NETWORK TRAFFIC ANALYSIS REPORT")
    print("=======================================")

    print("Packets analysed:", snapshot["packet_count"])
    print("Total Traffic:", snapshot["total_bytes"], "B")

    print("---------------------------------------")
    print("Protocol Breakdown:")

    for protocol, count in snapshot["protocol_counts"].items():
        print(f"{protocol}: {count} packets")

    print("---------------------------------------")
    print("Top Sources:")

    for source, bytes_sent in top_n(snapshot["bytes_by_source"]):
        print(f"{source}: {bytes_sent} B")

    print("---------------------------------------")
    print("Top Destinations:")

    for destination, bytes_received in top_n(
        snapshot["bytes_by_destination"]
    ):
        print(f"{destination}: {bytes_received} B")

    print("---------------------------------------")
    print("Top Connections:")

    for connection, total_bytes in top_n(
        snapshot["connection_bytes"]
    ):
        src, dst = connection
        print(f"{src} -> {dst}: {total_bytes} B")

    print("---------------------------------------")
    print("Traffic by 5-second window:")

    windows = sorted(snapshot["bytes_by_window"].items())

    for window, total_bytes in windows:
        timestamp = window * analyser.window_size

        readable_time = datetime.fromtimestamp(
            timestamp
        ).strftime("%H:%M:%S")

        print(f"{readable_time}: {total_bytes} B")

    print("---------------------------------------")
    print("Traffic Spikes:")

    spikes = detect_spikes_from_windows(
        windows,
        threshold=analyser.spike_threshold
    )

    if not spikes:
        print("No spikes detected")

    else:
        for window, total_bytes, average in spikes:
            multiplier = total_bytes / average

            timestamp = window * analyser.window_size

            readable_time = datetime.fromtimestamp(
                timestamp
            ).strftime("%H:%M:%S")

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

        print_report(analyser)

    elif args.live:
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
            clear_terminal()

            print("Capture stopped.")
            print_report(analyser)


if __name__ == "__main__":
    main()