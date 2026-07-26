from scapy.all import sniff, IP, TCP, UDP
import csv
import os
from datetime import datetime

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw', 'captured_packets.csv')

def init_csv():
    with open(OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'protocol', 'sport', 'dport', 'size'])

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        sport = dport = None
        proto_name = "OTHER"

        if TCP in packet:
            sport, dport, proto_name = packet[TCP].sport, packet[TCP].dport, "TCP"
        elif UDP in packet:
            sport, dport, proto_name = packet[UDP].sport, packet[UDP].dport, "UDP"

        row = [datetime.now().isoformat(), src, dst, proto_name, sport, dport, size]
        with open(OUTPUT_FILE, 'a', newline='') as f:
            csv.writer(f).writerow(row)

        print(f"{src}:{sport} -> {dst}:{dport} | {proto_name} | {size} bytes")

if __name__ == "__main__":
    init_csv()
    print("Starting capture... Ctrl+C to stop")
    sniff(prn=process_packet, store=False)