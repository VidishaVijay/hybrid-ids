from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, get_if_list, get_if_addr
from collections import defaultdict, deque
import time
import joblib
import pandas as pd
import os
import threading

app = Flask(__name__)

# ---- Load trained ML model ----
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'ids_model.pkl')
COLUMNS_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'model_columns.pkl')
model = joblib.load(MODEL_PATH)
model_columns = joblib.load(COLUMNS_PATH)

# ---- Detection settings ----
PORT_SCAN_THRESHOLD = 25
SYN_FLOOD_THRESHOLD = 50
TIME_WINDOW = 5
ALERT_COOLDOWN = 10

activity = defaultdict(deque)
last_alert = {}
alerts_log = []  # shared list the dashboard reads from
MAX_ALERTS = 50

def add_alert(alert_type, src_ip, message):
    alerts_log.insert(0, {
        "time": time.strftime("%H:%M:%S"),
        "type": alert_type,
        "src_ip": src_ip,
        "message": message
    })
    if len(alerts_log) > MAX_ALERTS:
        alerts_log.pop()

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
    ports = set(p for (_, p, _) in activity[src_ip])
    if len(ports) >= PORT_SCAN_THRESHOLD:
        if should_alert(src_ip, "PORT_SCAN", now):
            add_alert("Signature", src_ip, f"Port scan detected — {len(ports)} unique ports in {TIME_WINDOW}s")

def check_syn_flood(src_ip, now):
    port_counts = defaultdict(int)
    for (_, p, _) in activity[src_ip]:
        port_counts[p] += 1
    for port, count in port_counts.items():
        if count >= SYN_FLOOD_THRESHOLD:
            if should_alert(src_ip, f"SYN_FLOOD_{port}", now):
                add_alert("Signature", src_ip, f"SYN flood detected — port {port} hit {count} times in {TIME_WINDOW}s")

def build_feature_vector(src_ip, now):
    recent = activity[src_ip]
    ports = [p for (_, p, _) in recent]
    sizes = [s for (_, _, s) in recent]

    count = len(recent)
    srv_count = len(set(ports))
    src_bytes = sum(sizes) if sizes else 0
    duration = (recent[-1][0] - recent[0][0]) if len(recent) > 1 else 0

    diff_srv_rate = srv_count / count if count > 0 else 0
    same_srv_rate = 1 - diff_srv_rate

    row = {col: 0 for col in model_columns}
    row['duration'] = duration
    row['src_bytes'] = src_bytes
    row['count'] = count
    row['srv_count'] = srv_count
    row['same_srv_rate'] = same_srv_rate
    row['diff_srv_rate'] = diff_srv_rate
    row['dst_host_count'] = count
    row['dst_host_srv_count'] = srv_count
    row['dst_host_same_srv_rate'] = same_srv_rate
    row['dst_host_diff_srv_rate'] = diff_srv_rate

    error_proxy = min(diff_srv_rate * 1.5, 1.0) if count >= 8 else 0
    row['serror_rate'] = error_proxy
    row['rerror_rate'] = error_proxy
    row['dst_host_serror_rate'] = error_proxy
    row['dst_host_rerror_rate'] = error_proxy
    row['dst_host_srv_serror_rate'] = error_proxy
    row['dst_host_srv_rerror_rate'] = error_proxy

    if 'protocol_type_tcp' in row:
        row['protocol_type_tcp'] = 1

    return pd.DataFrame([row])[model_columns]

def check_ml_anomaly(src_ip, now):
    if len(activity[src_ip]) < 5:
        return
    features = build_feature_vector(src_ip, now)
    prediction = model.predict(features)[0]
    confidence = model.predict_proba(features)[0].max()

    if prediction == 'attack' and confidence > 0.7:
        if should_alert(src_ip, "ML_ANOMALY", now):
            add_alert("ML", src_ip, f"Anomalous traffic pattern — confidence {confidence:.2f}")

def process_packet(packet):
    if IP in packet and TCP in packet:
        if packet[TCP].flags == "S":
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            size = len(packet)
            now = time.time()

            activity[src_ip].append((now, dst_port, size))
            clean_old_entries(src_ip, now)

            check_port_scan(src_ip, now)
            check_syn_flood(src_ip, now)
            check_ml_anomaly(src_ip, now)

def find_wsl_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip.startswith("172."):
                return iface
        except Exception:
            continue
    return None

def start_sniffing():
    iface = find_wsl_interface()
    sniff(prn=process_packet, store=False, iface=iface)

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts_log)

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(debug=False, port=5000)