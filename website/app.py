import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, render_template, request
from collections import defaultdict, deque
import time

from src.ddos_detector import detect_ddos
from src.firewall_blocker import block_ip

app = Flask(__name__)

WINDOW_SECONDS = 10
ATTACK_THRESHOLD = 50   # 🔥 sync with graph threshold

rate_history = deque(maxlen=20)
time_labels = deque(maxlen=20)

ip_windows = defaultdict(deque)
recent_requests = deque(maxlen=40)
alerts = deque(maxlen=20)
attack_logs = deque(maxlen=20)

active_alerts = set()
blocked_ips = set()   # 🔥 prevent duplicate firewall blocks


# =========================
# 🔹 GET CLIENT IP
# =========================
def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# =========================
# 🔹 CLEAN OLD REQUESTS
# =========================
def cleanup_old_hits(ip, now):
    q = ip_windows[ip]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()


# =========================
# 🔹 CORE ENGINE
# =========================
def build_snapshot():

    active = {ip: len(q) for ip, q in ip_windows.items() if q}
    sorted_active = sorted(active.items(), key=lambda x: x[1], reverse=True)

    top_ip, top_count = (sorted_active[0] if sorted_active else ("-", 0))

    # =========================
    # 🔥 FEATURE ENGINEERING
    # =========================
    total_requests = sum(active.values())
    packet_rate = total_requests / WINDOW_SECONDS if total_requests else 0

    rate_history.append(packet_rate)
    time_labels.append(time.strftime("%H:%M:%S"))

    features = {
        "packet_rate": packet_rate,
        "syn_ratio": 0,
        "udp_ratio": 0,
        "unique_ips": len(active)
    }

    # =========================
    # 🔥 ML DETECTION
    # =========================
    result = detect_ddos(features)

    is_attack = result["prediction"] == 1 or packet_rate > ATTACK_THRESHOLD

    if is_attack:
        status = "DDoS Detected"
        status_type = "danger"

        # 🔥 LOGGING
        log_entry = {
            "time": time.strftime("%H:%M:%S"),
            "ip": top_ip,
            "confidence": result["confidence"],
            "packet_rate": round(packet_rate, 2),
            "action": "Blocked" if top_ip not in ["127.0.0.1", "localhost"] else "Detected"
        }

        # prevent duplicate logs
        if not attack_logs or attack_logs[0]["ip"] != top_ip:
            attack_logs.appendleft(log_entry)

        # 🔥 FIREWALL (SAFE)
        if top_ip not in ["127.0.0.1", "localhost"] and top_ip not in blocked_ips:
            try:
                block_ip(top_ip)
                blocked_ips.add(top_ip)
                print(f"🔥 Blocked IP: {top_ip}")
            except Exception as e:
                print(f"Firewall error: {e}")

    else:
        status = "Normal Traffic"
        status_type = "normal"

    confidence = result["confidence"]

    # =========================
    # 🔹 UI DATA
    # =========================
    suspicious = [(ip, count) for ip, count in sorted_active if count > 0]

    return {
        "attack_logs": list(attack_logs),
        "status": status,
        "status_type": status_type,
        "confidence": confidence,
        "total_requests": total_requests,
        "unique_ips": len(active),
        "top_ip": top_ip,
        "top_ip_count": top_count,
        "suspicious_ips": suspicious[:5],
        "top_ips_labels": [ip for ip, _ in sorted_active[:5]],
        "top_ips_values": [count for _, count in sorted_active[:5]],
        "recent_requests": list(recent_requests),
        "alerts": list(alerts),
        "timestamp": time.strftime("%H:%M:%S"),
        "rate_history": list(rate_history),
        "time_labels": list(time_labels),
    }


# =========================
# 🔹 TRACK REQUESTS
# =========================
@app.before_request
def track_request():

    if request.path.startswith("/static") or request.path.startswith("/api") or request.path == "/favicon.ico":
        return

    ip = client_ip()
    now = time.time()

    ip_windows[ip].append(now)
    cleanup_old_hits(ip, now)

    recent_requests.appendleft({
        "time": time.strftime("%H:%M:%S"),
        "ip": ip,
        "path": request.path
    })

    # 🔥 ALERT SYSTEM
    current_count = len(ip_windows[ip])

    if current_count > 15 and ip not in active_alerts:
        active_alerts.add(ip)
        alerts.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "ip": ip,
            "message": f"High traffic from {ip}",
            "count": current_count
        })

    if current_count <= 15 and ip in active_alerts:
        active_alerts.remove(ip)


# =========================
# 🔹 ROUTES
# =========================
@app.route("/")
def home():
    return render_template("index.html", active_page="home")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html", active_page="dashboard", initial=build_snapshot())


@app.route("/api/metrics")
def api_metrics():
    return jsonify(build_snapshot())


# =========================
# 🔹 RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True)
