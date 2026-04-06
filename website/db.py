from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().with_name("ddos.db")

# Keep the DB from growing too much while still preserving history for the demo
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
            INSERT INTO traffic_history (timestamp, rate, label)
            VALUES (?, ?, ?)
            """,
            (timestamp, float(rate), label),
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


def load_traffic_history(limit: int = 20) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, rate, label
            FROM traffic_history
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,),
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
