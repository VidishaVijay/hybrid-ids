from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr
from collections import defaultdict, deque
import time

PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 50
TIME_WINDOW = 5
ALERT_COOLDOWN = 10  # seconds before re-alerting same src_ip for same attack type

activity = defaultdict(deque)
last_alert = {}  # {(src_ip, attack_type): last_alert_time}

def clean_old_entries(src_ip, now):
    while activity[src_ip] and now - activity[src_ip][0][0] > TIME_WINDOW:
        activity[src_ip].popleft()

def should_alert(src_ip, attack_type, now):
    key = (src_ip, attack_type)
    if key not in last_alert or now - last_alert[key] > ALERT_COOLDOWN:
        last_alert[key] = now
        return True
    return False

def check_port_scan(src_ip, now):
    ports = set(p for (_, p) in activity[src_ip])
    if len(ports) >= PORT_SCAN_THRESHOLD:
        if should_alert(src_ip, "PORT_SCAN", now):
            print(f"[ALERT] PORT SCAN detected from {src_ip} — {len(ports)} unique ports hit in {TIME_WINDOW}s")

def check_syn_flood(src_ip, now):
    port_counts = defaultdict(int)
    for (_, p) in activity[src_ip]:
        port_counts[p] += 1
    for port, count in port_counts.items():
        if count >= SYN_FLOOD_THRESHOLD:
            if should_alert(src_ip, f"SYN_FLOOD_{port}", now):
                print(f"[ALERT] SYN FLOOD detected from {src_ip} — port {port} hit {count} times in {TIME_WINDOW}s")

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = time.time()

        activity[src_ip].append((now, dst_port))
        clean_old_entries(src_ip, now)

        check_port_scan(src_ip, now)
        check_syn_flood(src_ip, now)

def find_wsl_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip.startswith("172."):
                return iface
        except Exception:
            continue
    return None

if __name__ == "__main__":
    iface = find_wsl_interface()
    if iface is None:
        print("Could not auto-detect WSL interface. Falling back to default.")
        iface = None

    print(f"Using interface: {iface}")
    print("Starting detection engine... Ctrl+C to stop")
    try:
        sniff(prn=process_packet, store=False, iface=iface)
    except KeyboardInterrupt:
        print("\nDetection stopped.")