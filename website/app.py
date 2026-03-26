
from flask import Flask, jsonify, render_template, request
from collections import defaultdict, deque
import time

app = Flask(__name__)

WINDOW_SECONDS = 10
ATTACK_THRESHOLD = 20

ip_windows = defaultdict(deque)
recent_requests = deque(maxlen=40)
alerts = deque(maxlen=20)
active_alerts = set()


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def cleanup_old_hits(ip, now):
    q = ip_windows[ip]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()


def build_snapshot():
    active = {ip: len(q) for ip, q in ip_windows.items() if q}
    sorted_active = sorted(active.items(), key=lambda item: item[1], reverse=True)

    suspicious = [(ip, count) for ip, count in sorted_active if count >= ATTACK_THRESHOLD]
    top_ip, top_count = (sorted_active[0] if sorted_active else ("-", 0))

    return {
        "status": "DDoS Detected" if suspicious else "Normal Traffic",
        "status_type": "danger" if suspicious else "normal",
        "confidence": min(100, int((top_count / ATTACK_THRESHOLD) * 100)) if top_count else 0,
        "total_requests": sum(active.values()),
        "unique_ips": len(active),
        "top_ip": top_ip,
        "top_ip_count": top_count,
        "suspicious_ips": suspicious[:5],
        "top_ips_labels": [ip for ip, _ in sorted_active[:5]],
        "top_ips_values": [count for _, count in sorted_active[:5]],
        "recent_requests": list(recent_requests),
        "alerts": list(alerts),
        "timestamp": time.strftime("%H:%M:%S"),
    }


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

    current_count = len(ip_windows[ip])

    if current_count >= ATTACK_THRESHOLD and ip not in active_alerts:
        active_alerts.add(ip)
        alerts.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "ip": ip,
            "message": f"High request rate detected from {ip}",
            "count": current_count
        })

    if current_count < ATTACK_THRESHOLD and ip in active_alerts:
        active_alerts.remove(ip)


@app.route("/")
def home():
    return render_template(
        "index.html",
        active_page="home"
    )


@app.route("/dashboard")
def dashboard_page():
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        initial=build_snapshot()
    )


@app.route("/api/metrics")
def api_metrics():
    return jsonify(build_snapshot())


if __name__ == "__main__":
    app.run(debug=True)
