from scapy.all import sniff, IP, TCP, UDP
import csv
import os
from datetime import datetime

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw', 'captured_packets.csv')

buffer = []
BUFFER_LIMIT = 100  # write to disk every 100 packets instead of every single one

def init_csv():
    with open(OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'protocol', 'sport', 'dport', 'size'])

def flush_buffer():
    if buffer:
        with open(OUTPUT_FILE, 'a', newline='') as f:
            csv.writer(f).writerows(buffer)
        buffer.clear()

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
        buffer.append(row)

        if len(buffer) >= BUFFER_LIMIT:
            flush_buffer()

if __name__ == "__main__":
    init_csv()
    print("Starting capture... Ctrl+C to stop")
    try:
        sniff(prn=process_packet, store=False, iface="Hyper-V Virtual Ethernet Adapter")
    except KeyboardInterrupt:
        pass
    finally:
        flush_buffer()
        print("Capture stopped, buffer flushed.")