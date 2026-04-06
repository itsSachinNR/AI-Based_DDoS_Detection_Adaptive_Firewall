from __future__ import annotations

import math
import os
import sys
import time
from collections import defaultdict, deque
from threading import Lock, Timer

from flask import Flask, jsonify, render_template, request, g

# Make the project root visible so `src.*` imports work
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.ddos_detector import detect_ddos
from src.firewall_blocker import block_ip, unblock_ip

app = Flask(__name__, template_folder="templates", static_folder="static")

# ============================================================
# CONFIG
# ============================================================
WINDOW_SECONDS = 10
ATTACK_THRESHOLD = 50
BLOCK_SECONDS = 30
BLOCK_CONFIDENCE_THRESHOLD = 80.0

# ============================================================
# LIVE STATE
# ============================================================
rate_history = deque(maxlen=20)
time_labels = deque(maxlen=20)

ip_windows = defaultdict(deque)   # ip -> deque[timestamps]
recent_requests = deque(maxlen=60)
alerts = deque(maxlen=20)
attack_logs = deque(maxlen=20)

active_alerts = set()
blocked_ips = {}                  # ip -> expiry timestamp
block_timers = {}                 # ip -> Timer

state_lock = Lock()


# ============================================================
# HELPERS
# ============================================================
def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_local_or_invalid_ip(ip: str) -> bool:
    if not ip or ip in {"-", "localhost"}:
        return True
    if ip in {"127.0.0.1", "::1", "0.0.0.0"}:
        return True
    return False


def shannon_entropy_from_counts(counts: dict) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def cleanup_old_hits(ip, now):
    q = ip_windows[ip]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()

    if not q:
        ip_windows.pop(ip, None)


def purge_expired_block_records():
    now = time.time()
    expired = [ip for ip, expiry in blocked_ips.items() if now >= expiry]
    for ip in expired:
        blocked_ips.pop(ip, None)
        block_timers.pop(ip, None)


def schedule_unblock(ip: str, duration: int = BLOCK_SECONDS):
    def _unblock():
        try:
            unblock_ip(ip, announce=False)
            print(f"🔓 Unblocked IP: {ip}")
        except Exception as e:
            print(f"Firewall unblock error for {ip}: {e}")
        finally:
            with state_lock:
                blocked_ips.pop(ip, None)
                block_timers.pop(ip, None)

    with state_lock:
        existing = block_timers.get(ip)
        if existing is not None and existing.is_alive():
            return

        timer = Timer(duration, _unblock)
        timer.daemon = True
        block_timers[ip] = timer
        timer.start()


def should_block_ip(ip: str, confidence: float) -> bool:
    return not is_local_or_invalid_ip(ip) and confidence >= BLOCK_CONFIDENCE_THRESHOLD


# ============================================================
# SNAPSHOT BUILDER
# ============================================================
def build_snapshot():
    now = time.time()

    with state_lock:
        purge_expired_block_records()

        # Clean every IP bucket based on the current time
        for ip in list(ip_windows.keys()):
            cleanup_old_hits(ip, now)

        active = {ip: len(q) for ip, q in ip_windows.items() if q}
        sorted_active = sorted(active.items(), key=lambda x: x[1], reverse=True)

    top_ip, top_count = (sorted_active[0] if sorted_active else ("-", 0))
    total_requests = sum(active.values())

    # Real sliding-window rate
    packet_rate = total_requests / WINDOW_SECONDS if total_requests else 0

    # Keep chart history stable over time
    rate_history.append(packet_rate)
    time_labels.append(time.strftime("%H:%M:%S"))

    # Web traffic is application-layer telemetry; fill what we can.
    unique_ips = len(active)
    avg_packets_per_ip = total_requests / unique_ips if unique_ips else 0
    ip_concentration = top_count / total_requests if total_requests else 0
    source_ip_entropy = shannon_entropy_from_counts(active)
    packet_count = total_requests

    # Aligned to the richer ML schema
    features = {
        "packet_rate": packet_rate,
        "syn_ratio": 0.0,
        "udp_ratio": 0.0,
        "unique_ips": unique_ips,
        "tcp_ratio": 1.0 if total_requests else 0.0,
        "icmp_ratio": 0.0,
        "other_ratio": 0.0,
        "avg_packets_per_ip": avg_packets_per_ip,
        "ip_concentration": ip_concentration,
        "source_ip_entropy": source_ip_entropy,
        "port_entropy": 0.0,
        "unique_dst_ports": 1 if total_requests else 0,
        "top_ip_packets": top_count,
        "top_dst_port_packets": total_requests,
        "packet_size_mean": 0.0,
        "packet_size_std": 0.0,
        "packet_size_min": 0.0,
        "packet_size_max": 0.0,
        "avg_inter_arrival": 0.0,
        "inter_arrival_std": 0.0,
        "burstiness": 0.0,
        "byte_rate": 0.0,
        "avg_bytes_per_packet": 0.0,
        "packet_count": packet_count,
        "total_bytes": 0.0,
        "duration_seconds": WINDOW_SECONDS,
    }

    result = detect_ddos(features)
    confidence = result.get("confidence", 0.0)
    reasons = result.get("reasons", [])

    is_attack = result["prediction"] == 1
    status = "DDoS Detected" if is_attack else "Normal Traffic"
    status_type = "danger" if is_attack else "normal"

    if is_attack:
        log_entry = {
            "time": time.strftime("%H:%M:%S"),
            "ip": top_ip,
            "confidence": confidence,
            "packet_rate": round(packet_rate, 2),
            "action": "Blocked" if should_block_ip(top_ip, confidence) else "Detected",
            "reasons": reasons[:5],
            "rf_attack_probability": result.get("rf_attack_probability", 0),
            "anomaly_attack_probability": result.get("anomaly_attack_probability", 0),
            "model_name": result.get("model_name", "Hybrid ML"),
        }

        if not attack_logs or attack_logs[0]["ip"] != top_ip:
            attack_logs.appendleft(log_entry)

        if should_block_ip(top_ip, confidence):
            with state_lock:
                already_blocked = top_ip in blocked_ips

            if not already_blocked:
                try:
                    block_ip(top_ip, duration=BLOCK_SECONDS, auto_unblock=False)
                    with state_lock:
                        blocked_ips[top_ip] = time.time() + BLOCK_SECONDS
                    schedule_unblock(top_ip, BLOCK_SECONDS)
                    print(f"🔥 Blocked IP: {top_ip} for {BLOCK_SECONDS} seconds")
                except Exception as e:
                    print(f"Firewall error: {e}")

    suspicious = [(ip, count) for ip, count in sorted_active if count > 0]
    top_labels = [ip for ip, _ in sorted_active[:8]] or ["No traffic"]

    # Use normalized values in the Top Active IPs chart so it does not keep
    # visually climbing forever. The snapshot still shows the actual count.
    top_values = [round(count / WINDOW_SECONDS, 2) for _, count in sorted_active[:8]] or [0]

    with state_lock:
        blocked_list = list(blocked_ips.keys())

    return {
        "status": status,
        "status_type": status_type,
        "confidence": confidence,
        "prediction": int(result["prediction"]),
        "model_name": result.get("model_name", "Hybrid ML"),
        "reasons": reasons,
        "rf_attack_probability": result.get("rf_attack_probability", 0),
        "anomaly_attack_probability": result.get("anomaly_attack_probability", 0),
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "top_ip": top_ip,
        "top_ip_count": top_count,
        "suspicious_ips": suspicious[:5],
        "top_ips_labels": top_labels,
        "top_ips_values": top_values,
        "recent_requests": list(recent_requests),
        "alerts": list(alerts),
        "attack_logs": list(attack_logs),
        "blocked_ips": blocked_list,
        "timestamp": time.strftime("%H:%M:%S"),
        "rate_history": list(rate_history),
        "time_labels": list(time_labels),
        "window_seconds": WINDOW_SECONDS,
        "block_seconds": BLOCK_SECONDS,
    }


# ============================================================
# REQUEST TRACKING
# ============================================================
@app.before_request
def track_request():
    if (
        request.path.startswith("/static")
        or request.path.startswith("/api")
        or request.path == "/favicon.ico"
    ):
        return

    ip = client_ip()
    now = time.time()

    ip_windows[ip].append(now)
    cleanup_old_hits(ip, now)

    g.request_meta = {
        "time": time.strftime("%H:%M:%S"),
        "ip": ip,
        "method": request.method,
        "path": request.path,
        "status": "-",
        "flag": "clean",
    }

    current_count = len(ip_windows[ip])

    if current_count > 15 and ip not in active_alerts:
        active_alerts.add(ip)
        alerts.appendleft(
            {
                "time": time.strftime("%H:%M:%S"),
                "ip": ip,
                "message": f"High traffic from {ip}",
                "count": current_count,
            }
        )

    if current_count <= 15 and ip in active_alerts:
        active_alerts.remove(ip)


@app.after_request
def log_response(response):
    entry = getattr(g, "request_meta", None)
    if entry is not None:
        entry["status"] = response.status_code
        entry["flag"] = (
            "suspicious"
            if response.status_code >= 400 or entry["method"] in {"PUT", "DELETE", "PATCH"}
            else "clean"
        )
        recent_requests.appendleft(entry)
    return response


# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def home():
    return render_template("index.html", active_page="home")


@app.route("/dashboard")
def dashboard_page():
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        initial=build_snapshot(),
    )


@app.route("/api/metrics")
def api_metrics():
    return jsonify(build_snapshot())


@app.route("/api/refresh")
def api_refresh():
    return jsonify(build_snapshot())


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
