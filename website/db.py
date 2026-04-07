from __future__ import annotations

import json
import math
import random
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().with_name("ddos.db")

LIMIT_RECENT_REQUESTS = 300
LIMIT_ALERTS = 120
LIMIT_ATTACK_LOGS = 120
LIMIT_TRAFFIC_HISTORY = 240


# ============================================================
# CONNECTION / INIT
# ============================================================
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                ip TEXT NOT NULL,
                confidence REAL NOT NULL,
                packet_rate REAL NOT NULL,
                action TEXT NOT NULL,
                reasons TEXT NOT NULL,
                rf_attack_probability REAL DEFAULT 0,
                anomaly_attack_probability REAL DEFAULT 0,
                model_name TEXT DEFAULT 'Hybrid ML',
                created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                ip TEXT NOT NULL,
                message TEXT NOT NULL,
                count INTEGER NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS recent_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                flag TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rate REAL NOT NULL,
                label TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )


# ============================================================
# SMALL HELPERS
# ============================================================
def _trim_table(conn: sqlite3.Connection, table: str, id_column: str, keep_last: int) -> None:
    if keep_last <= 0:
        return

    rows = conn.execute(
        f"""
        SELECT {id_column}
        FROM {table}
        ORDER BY {id_column} DESC
        LIMIT -1 OFFSET ?
        """,
        (keep_last,),
    ).fetchall()

    if not rows:
        return

    ids = [row[id_column] for row in rows]
    placeholders = ",".join("?" for _ in ids)
    conn.execute(f"DELETE FROM {table} WHERE {id_column} IN ({placeholders})", ids)


def save_state(key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    now = time.time()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO app_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                updated_at=excluded.updated_at
            """,
            (key, payload, now),
        )


def load_state(key: str) -> Optional[Any]:
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
        if not row:
            return None

        try:
            return json.loads(row["value"])
        except Exception:
            return None


# ============================================================
# SAVE FUNCTIONS
# ============================================================
def save_attack_log(entry: Dict[str, Any]) -> None:
    reasons = entry.get("reasons", [])
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO attack_logs
            (time, ip, confidence, packet_rate, action, reasons,
             rf_attack_probability, anomaly_attack_probability, model_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("time", ""),
                entry.get("ip", "-"),
                float(entry.get("confidence", 0.0)),
                float(entry.get("packet_rate", 0.0)),
                entry.get("action", "Detected"),
                json.dumps(reasons, ensure_ascii=False),
                float(entry.get("rf_attack_probability", 0.0)),
                float(entry.get("anomaly_attack_probability", 0.0)),
                entry.get("model_name", "Hybrid ML"),
            ),
        )
        _trim_table(conn, "attack_logs", "id", LIMIT_ATTACK_LOGS)


def save_alert(entry: Dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO alerts (time, ip, message, count)
            VALUES (?, ?, ?, ?)
            """,
            (
                entry.get("time", ""),
                entry.get("ip", "-"),
                entry.get("message", ""),
                int(entry.get("count", 0)),
            ),
        )
        _trim_table(conn, "alerts", "id", LIMIT_ALERTS)


def save_recent_request(entry: Dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO recent_requests (time, ip, method, path, status, flag)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("time", ""),
                entry.get("ip", "-"),
                entry.get("method", "GET"),
                entry.get("path", "/"),
                str(entry.get("status", "-")),
                entry.get("flag", "clean"),
            ),
        )
        _trim_table(conn, "recent_requests", "id", LIMIT_RECENT_REQUESTS)


def save_traffic_point(timestamp: str, rate: float, label: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO traffic_history (timestamp, rate, label, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp, float(rate), label, time.time()),
        )
        _trim_table(conn, "traffic_history", "id", LIMIT_TRAFFIC_HISTORY)


def save_blocked_ip(ip: str, blocked_at: float, expires_at: float) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO blocked_ips (ip, blocked_at, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                blocked_at=excluded.blocked_at,
                expires_at=excluded.expires_at
            """,
            (ip, float(blocked_at), float(expires_at)),
        )


def delete_blocked_ip(ip: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def save_last_snapshot(snapshot: Dict[str, Any]) -> None:
    save_state("last_snapshot", snapshot)


# ============================================================
# LOAD FUNCTIONS
# ============================================================
def traffic_history_count() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM traffic_history").fetchone()
        return int(row["c"] if row else 0)


def load_attack_logs(limit: int = 20) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT time, ip, confidence, packet_rate, action, reasons,
                   rf_attack_probability, anomaly_attack_probability, model_name
            FROM attack_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    results: List[Dict[str, Any]] = []
    for row in rows:
        try:
            reasons = json.loads(row["reasons"]) if row["reasons"] else []
        except Exception:
            reasons = []

        results.append(
            {
                "time": row["time"],
                "ip": row["ip"],
                "confidence": float(row["confidence"]),
                "packet_rate": float(row["packet_rate"]),
                "action": row["action"],
                "reasons": reasons,
                "rf_attack_probability": float(row["rf_attack_probability"] or 0),
                "anomaly_attack_probability": float(row["anomaly_attack_probability"] or 0),
                "model_name": row["model_name"] or "Hybrid ML",
            }
        )

    return results


def load_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT time, ip, message, count
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "time": row["time"],
            "ip": row["ip"],
            "message": row["message"],
            "count": int(row["count"]),
        }
        for row in rows
    ]


def load_recent_requests(limit: int = 60) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT time, ip, method, path, status, flag
            FROM recent_requests
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "time": row["time"],
            "ip": row["ip"],
            "method": row["method"],
            "path": row["path"],
            "status": row["status"],
            "flag": row["flag"],
        }
        for row in rows
    ]


def load_traffic_history(hours: int = 24) -> List[Dict[str, Any]]:
    cutoff = time.time() - (hours * 3600)

    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, rate, label
            FROM traffic_history
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            (cutoff,),
        ).fetchall()

    return [
        {
            "timestamp": row["timestamp"],
            "rate": float(row["rate"]),
            "label": row["label"],
        }
        for row in rows
    ]


def load_blocked_ips() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT ip, blocked_at, expires_at
            FROM blocked_ips
            ORDER BY blocked_at DESC
            """
        ).fetchall()

    return [
        {
            "ip": row["ip"],
            "blocked_at": float(row["blocked_at"]),
            "expires_at": float(row["expires_at"]),
        }
        for row in rows
    ]


def load_last_snapshot() -> Optional[Dict[str, Any]]:
    value = load_state("last_snapshot")
    if isinstance(value, dict):
        return value
    return None


# ============================================================
# DEMO SEED
# ============================================================
def seed_demo_baseline(hours: int = 6, points_per_hour: int = 12) -> bool:
    """
    Demo-only fallback.
    Adds stored traffic, requests, alerts, attack logs, and a sample blocked IP
    so the dashboard is not empty when the local network is quiet.
    """
    if traffic_history_count() > 0:
        return False

    rng = random.Random(42)
    now = time.time()
    total_points = hours * points_per_hour
    step = 3600 / points_per_hour
    start_ts = now - (total_points * step)

    with get_connection() as conn:
        # Traffic history
        for i in range(total_points):
            ts = start_ts + (i * step)

            base = 18 + (8 * math.sin(i / 4.5)) + rng.uniform(-2.0, 2.0)
            spike = 0
            if i in {total_points // 3, (2 * total_points) // 3}:
                spike = 22 + rng.uniform(8, 15)

            rate = max(1.0, round(base + spike, 2))
            label = time.strftime("%H:%M:%S", time.localtime(ts))

            conn.execute(
                """
                INSERT INTO traffic_history (timestamp, rate, label, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (label, rate, "demo", ts),
            )

        # Recent request examples
        demo_requests = [
            {"time": "09:10:02", "ip": "192.168.1.24", "method": "GET", "path": "/", "status": 200, "flag": "clean"},
            {"time": "09:10:08", "ip": "192.168.1.31", "method": "GET", "path": "/dashboard", "status": 200, "flag": "clean"},
            {"time": "09:10:15", "ip": "192.168.1.24", "method": "POST", "path": "/api/metrics", "status": 200, "flag": "clean"},
            {"time": "09:10:22", "ip": "192.168.1.51", "method": "GET", "path": "/", "status": 200, "flag": "clean"},
            {"time": "09:10:31", "ip": "192.168.1.24", "method": "GET", "path": "/dashboard", "status": 200, "flag": "clean"},
            {"time": "09:10:40", "ip": "192.168.1.88", "method": "GET", "path": "/api/refresh", "status": 200, "flag": "clean"},
            {"time": "09:10:49", "ip": "192.168.1.24", "method": "GET", "path": "/", "status": 200, "flag": "clean"},
            {"time": "09:10:56", "ip": "192.168.1.99", "method": "GET", "path": "/dashboard", "status": 200, "flag": "clean"},
        ]
        for row in demo_requests:
            conn.execute(
                """
                INSERT INTO recent_requests (time, ip, method, path, status, flag, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (row["time"], row["ip"], row["method"], row["path"], str(row["status"]), row["flag"], now),
            )

        # Alerts
        demo_alerts = [
            {"time": "09:09:58", "ip": "192.168.1.24", "message": "High traffic from 192.168.1.24", "count": 16},
            {"time": "09:10:20", "ip": "192.168.1.51", "message": "High traffic from 192.168.1.51", "count": 18},
            {"time": "09:10:43", "ip": "192.168.1.99", "message": "High traffic from 192.168.1.99", "count": 21},
        ]
        for row in demo_alerts:
            conn.execute(
                """
                INSERT INTO alerts (time, ip, message, count, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (row["time"], row["ip"], row["message"], row["count"], now),
            )

        # Historical attack log entries
        demo_attacks = [
            {
                "time": "09:10:40",
                "ip": "192.168.1.99",
                "confidence": 78.4,
                "packet_rate": 41.2,
                "action": "Detected",
                "reasons": [
                    "Traffic concentrated on very few IPs",
                    "Low source-IP diversity",
                    "Extremely fast packet arrivals",
                ],
                "rf_attack_probability": 64.2,
                "anomaly_attack_probability": 59.7,
                "model_name": "Hybrid RF + IsolationForest",
            },
            {
                "time": "09:11:12",
                "ip": "192.168.1.51",
                "confidence": 82.1,
                "packet_rate": 52.6,
                "action": "Blocked",
                "reasons": [
                    "Very high packet rate",
                    "Low destination-port diversity",
                ],
                "rf_attack_probability": 72.8,
                "anomaly_attack_probability": 66.4,
                "model_name": "Hybrid RF + IsolationForest",
            },
        ]
        for item in demo_attacks:
            conn.execute(
                """
                INSERT INTO attack_logs
                (time, ip, confidence, packet_rate, action, reasons,
                 rf_attack_probability, anomaly_attack_probability, model_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["time"],
                    item["ip"],
                    item["confidence"],
                    item["packet_rate"],
                    item["action"],
                    json.dumps(item["reasons"], ensure_ascii=False),
                    item["rf_attack_probability"],
                    item["anomaly_attack_probability"],
                    item["model_name"],
                    now,
                ),
            )

        # Sample blocked IP visible on the dashboard
        conn.execute(
            """
            INSERT INTO blocked_ips (ip, blocked_at, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                blocked_at=excluded.blocked_at,
                expires_at=excluded.expires_at
            """,
            ("192.168.1.51", now, now + 3600),
        )

        _trim_table(conn, "recent_requests", "id", LIMIT_RECENT_REQUESTS)
        _trim_table(conn, "alerts", "id", LIMIT_ALERTS)
        _trim_table(conn, "attack_logs", "id", LIMIT_ATTACK_LOGS)
        _trim_table(conn, "traffic_history", "id", LIMIT_TRAFFIC_HISTORY)

    demo_snapshot = {
        "status": "Normal Traffic",
        "status_type": "normal",
        "confidence": 72.0,
        "prediction": 0,
        "model_name": "Hybrid ML",
        "reasons": ["Stored demo baseline"],
        "rf_attack_probability": 18.0,
        "anomaly_attack_probability": 24.0,
        "total_requests": 38,
        "unique_ips": 6,
        "top_ip": "192.168.1.24",
        "top_ip_count": 12,
        "suspicious_ips": [("192.168.1.24", 12), ("192.168.1.31", 8), ("192.168.1.51", 5)],
        "top_ips_labels": ["192.168.1.24", "192.168.1.31", "192.168.1.51"],
        "top_ips_values": [12, 8, 5],
        "recent_requests": demo_requests,
        "alerts": demo_alerts,
        "attack_logs": demo_attacks,
        "blocked_ips": ["192.168.1.51"],
        "timestamp": time.strftime("%H:%M:%S"),
        "window_seconds": 10,
        "block_seconds": 30,
    }

    save_last_snapshot(demo_snapshot)
    return True
