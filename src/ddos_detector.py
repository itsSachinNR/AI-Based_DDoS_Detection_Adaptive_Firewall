import math
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest

# ============================================================
# FEATURE SET USED BY THE DETECTOR
# ============================================================
FEATURE_COLUMNS = [
    "packet_rate",
    "syn_ratio",
    "udp_ratio",
    "unique_ips",
    "tcp_ratio",
    "icmp_ratio",
    "other_ratio",
    "avg_packets_per_ip",
    "ip_concentration",
    "source_ip_entropy",
    "port_entropy",
    "unique_dst_ports",
    "top_dst_port_packets",
    "packet_size_mean",
    "packet_size_std",
    "packet_size_min",
    "packet_size_max",
    "avg_inter_arrival",
    "inter_arrival_std",
    "burstiness",
    "byte_rate",
    "avg_bytes_per_packet",
]

DEFAULT_FEATURE_VALUES = {feature: 0.0 for feature in FEATURE_COLUMNS}


def build_row(label, **kwargs):
    row = DEFAULT_FEATURE_VALUES.copy()
    row.update(kwargs)
    row["label"] = label
    return row


# ============================================================
# TRAINING DATA (demo-quality but much richer than before)
# 0 = normal, 1 = DDoS/attack-like
# ============================================================
training_rows = [
    # ---------------- NORMAL TRAFFIC ----------------
    build_row(
        0,
        packet_rate=18, syn_ratio=0.08, udp_ratio=0.05, unique_ips=15,
        tcp_ratio=0.72, icmp_ratio=0.03, other_ratio=0.25,
        avg_packets_per_ip=1.2, ip_concentration=0.08,
        source_ip_entropy=3.80, port_entropy=3.50, unique_dst_ports=12,
        top_dst_port_packets=7, packet_size_mean=620, packet_size_std=95,
        packet_size_min=64, packet_size_max=1500,
        avg_inter_arrival=0.018, inter_arrival_std=0.011, burstiness=0.61,
        byte_rate=11200, avg_bytes_per_packet=610
    ),
    build_row(
        0,
        packet_rate=28, syn_ratio=0.10, udp_ratio=0.06, unique_ips=22,
        tcp_ratio=0.78, icmp_ratio=0.02, other_ratio=0.20,
        avg_packets_per_ip=1.3, ip_concentration=0.07,
        source_ip_entropy=4.05, port_entropy=3.90, unique_dst_ports=16,
        top_dst_port_packets=9, packet_size_mean=640, packet_size_std=110,
        packet_size_min=64, packet_size_max=1460,
        avg_inter_arrival=0.014, inter_arrival_std=0.009, burstiness=0.64,
        byte_rate=17920, avg_bytes_per_packet=640
    ),
    build_row(
        0,
        packet_rate=45, syn_ratio=0.12, udp_ratio=0.08, unique_ips=30,
        tcp_ratio=0.76, icmp_ratio=0.03, other_ratio=0.21,
        avg_packets_per_ip=1.5, ip_concentration=0.06,
        source_ip_entropy=4.30, port_entropy=4.10, unique_dst_ports=20,
        top_dst_port_packets=11, packet_size_mean=580, packet_size_std=120,
        packet_size_min=60, packet_size_max=1500,
        avg_inter_arrival=0.010, inter_arrival_std=0.007, burstiness=0.70,
        byte_rate=26100, avg_bytes_per_packet=580
    ),
    build_row(
        0,
        packet_rate=60, syn_ratio=0.15, udp_ratio=0.10, unique_ips=40,
        tcp_ratio=0.70, icmp_ratio=0.03, other_ratio=0.27,
        avg_packets_per_ip=1.6, ip_concentration=0.05,
        source_ip_entropy=4.55, port_entropy=4.30, unique_dst_ports=24,
        top_dst_port_packets=13, packet_size_mean=700, packet_size_std=130,
        packet_size_min=64, packet_size_max=1500,
        avg_inter_arrival=0.008, inter_arrival_std=0.006, burstiness=0.75,
        byte_rate=42000, avg_bytes_per_packet=700
    ),
    build_row(
        0,
        packet_rate=35, syn_ratio=0.09, udp_ratio=0.04, unique_ips=18,
        tcp_ratio=0.81, icmp_ratio=0.01, other_ratio=0.18,
        avg_packets_per_ip=1.4, ip_concentration=0.09,
        source_ip_entropy=3.95, port_entropy=3.70, unique_dst_ports=10,
        top_dst_port_packets=8, packet_size_mean=500, packet_size_std=80,
        packet_size_min=64, packet_size_max=1200,
        avg_inter_arrival=0.015, inter_arrival_std=0.010, burstiness=0.66,
        byte_rate=17500, avg_bytes_per_packet=500
    ),
    build_row(
        0,
        packet_rate=22, syn_ratio=0.11, udp_ratio=0.05, unique_ips=12,
        tcp_ratio=0.75, icmp_ratio=0.02, other_ratio=0.23,
        avg_packets_per_ip=1.8, ip_concentration=0.12,
        source_ip_entropy=3.60, port_entropy=3.20, unique_dst_ports=9,
        top_dst_port_packets=6, packet_size_mean=550, packet_size_std=100,
        packet_size_min=64, packet_size_max=1460,
        avg_inter_arrival=0.020, inter_arrival_std=0.012, burstiness=0.60,
        byte_rate=12100, avg_bytes_per_packet=550
    ),

    # ---------------- ATTACK TRAFFIC ----------------
    build_row(
        1,
        packet_rate=950, syn_ratio=0.96, udp_ratio=0.02, unique_ips=2,
        tcp_ratio=0.97, icmp_ratio=0.00, other_ratio=0.03,
        avg_packets_per_ip=475.0, ip_concentration=0.92,
        source_ip_entropy=0.35, port_entropy=0.40, unique_dst_ports=2,
        top_dst_port_packets=880, packet_size_mean=74, packet_size_std=10,
        packet_size_min=54, packet_size_max=120,
        avg_inter_arrival=0.0008, inter_arrival_std=0.0020, burstiness=2.50,
        byte_rate=70300, avg_bytes_per_packet=74
    ),
    build_row(
        1,
        packet_rate=1500, syn_ratio=0.98, udp_ratio=0.01, unique_ips=1,
        tcp_ratio=0.99, icmp_ratio=0.00, other_ratio=0.01,
        avg_packets_per_ip=1500.0, ip_concentration=1.00,
        source_ip_entropy=0.00, port_entropy=0.10, unique_dst_ports=1,
        top_dst_port_packets=1500, packet_size_mean=60, packet_size_std=5,
        packet_size_min=54, packet_size_max=90,
        avg_inter_arrival=0.0005, inter_arrival_std=0.0015, burstiness=3.00,
        byte_rate=90000, avg_bytes_per_packet=60
    ),
    build_row(
        1,
        packet_rate=780, syn_ratio=0.91, udp_ratio=0.03, unique_ips=3,
        tcp_ratio=0.94, icmp_ratio=0.00, other_ratio=0.06,
        avg_packets_per_ip=260.0, ip_concentration=0.80,
        source_ip_entropy=0.70, port_entropy=0.55, unique_dst_ports=2,
        top_dst_port_packets=710, packet_size_mean=72, packet_size_std=12,
        packet_size_min=54, packet_size_max=110,
        avg_inter_arrival=0.0010, inter_arrival_std=0.0025, burstiness=2.50,
        byte_rate=56160, avg_bytes_per_packet=72
    ),
    build_row(
        1,
        packet_rate=1200, syn_ratio=0.20, udp_ratio=0.88, unique_ips=2,
        tcp_ratio=0.12, icmp_ratio=0.00, other_ratio=0.00,
        avg_packets_per_ip=600.0, ip_concentration=0.90,
        source_ip_entropy=0.20, port_entropy=0.30, unique_dst_ports=1,
        top_dst_port_packets=1180, packet_size_mean=140, packet_size_std=15,
        packet_size_min=90, packet_size_max=200,
        avg_inter_arrival=0.0007, inter_arrival_std=0.0018, burstiness=2.57,
        byte_rate=168000, avg_bytes_per_packet=140
    ),
    build_row(
        1,
        packet_rate=620, syn_ratio=0.85, udp_ratio=0.10, unique_ips=4,
        tcp_ratio=0.86, icmp_ratio=0.00, other_ratio=0.14,
        avg_packets_per_ip=155.0, ip_concentration=0.76,
        source_ip_entropy=0.95, port_entropy=0.60, unique_dst_ports=3,
        top_dst_port_packets=500, packet_size_mean=80, packet_size_std=14,
        packet_size_min=54, packet_size_max=140,
        avg_inter_arrival=0.0015, inter_arrival_std=0.0030, burstiness=2.00,
        byte_rate=49600, avg_bytes_per_packet=80
    ),
    build_row(
        1,
        packet_rate=1100, syn_ratio=0.55, udp_ratio=0.35, unique_ips=2,
        tcp_ratio=0.60, icmp_ratio=0.00, other_ratio=0.05,
        avg_packets_per_ip=550.0, ip_concentration=0.88,
        source_ip_entropy=0.28, port_entropy=0.20, unique_dst_ports=2,
        top_dst_port_packets=980, packet_size_mean=100, packet_size_std=20,
        packet_size_min=60, packet_size_max=160,
        avg_inter_arrival=0.0009, inter_arrival_std=0.0022, burstiness=2.44,
        byte_rate=110000, avg_bytes_per_packet=100
    ),
]

df = pd.DataFrame(training_rows)

X = df.drop("label", axis=1)
y = df["label"]

# ============================================================
# MODELS
# ============================================================
classifier = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced_subsample"
)
classifier.fit(X, y)

# Train anomaly detector on benign traffic only
normal_df = df[df["label"] == 0].drop("label", axis=1)

anomaly_model = IsolationForest(
    n_estimators=200,
    contamination=0.20,
    random_state=42
)
anomaly_model.fit(normal_df)


# ============================================================
# FEATURE PREPARATION
# ============================================================
def prepare_sample(features):
    """
    Convert the features dictionary into a one-row DataFrame
    matching the training columns.
    """
    row = {}
    for col in FEATURE_COLUMNS:
        value = features.get(col, DEFAULT_FEATURE_VALUES[col])

        if value is None or value == "":
            value = DEFAULT_FEATURE_VALUES[col]

        try:
            row[col] = float(value)
        except (TypeError, ValueError):
            row[col] = DEFAULT_FEATURE_VALUES[col]

    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def explain_signal(sample_row):
    """
    Simple rule-based explanation so the dashboard can show
    *why* the model is suspicious.
    """
    reasons = []

    if sample_row["packet_rate"] > 500:
        reasons.append("Very high packet rate")

    if sample_row["syn_ratio"] > 0.70:
        reasons.append("SYN-heavy traffic")

    if sample_row["udp_ratio"] > 0.60:
        reasons.append("UDP-heavy traffic")

    if sample_row["unique_ips"] <= 3:
        reasons.append("Traffic concentrated on very few IPs")

    if sample_row["ip_concentration"] > 0.60:
        reasons.append("One IP dominates the traffic")

    if sample_row["burstiness"] > 1.20:
        reasons.append("Burst-like packet arrival pattern")

    if sample_row["source_ip_entropy"] < 1.50:
        reasons.append("Low source-IP diversity")

    if sample_row["port_entropy"] < 1.50:
        reasons.append("Low destination-port diversity")

    return reasons


# ============================================================
# ML DETECTION FUNCTION
# ============================================================
def detect_ddos(features):
    """
    Input: features dictionary from feature_extraction.py
    Output: prediction + confidence + supporting signals
    """

    sample = prepare_sample(features)
    sample_row = sample.iloc[0]

    # Supervised prediction
    rf_prediction = int(classifier.predict(sample)[0])
    rf_probabilities = classifier.predict_proba(sample)[0]

    # Probability of class 1 (attack)
    class_index = list(classifier.classes_).index(1)
    rf_attack_prob = float(rf_probabilities[class_index])

    # Anomaly detection (higher = more anomalous)
    anomaly_score_raw = float(anomaly_model.decision_function(sample)[0])
    anomaly_attack_prob = 1.0 / (1.0 + math.exp(anomaly_score_raw * 5.0))

    # Hybrid attack score
    final_attack_prob = (0.75 * rf_attack_prob) + (0.25 * anomaly_attack_prob)

    # Final decision
    prediction = 1 if final_attack_prob >= 0.55 or (rf_prediction == 1 and anomaly_attack_prob >= 0.40) else 0

    if prediction == 1:
        confidence = round(final_attack_prob * 100, 2)
    else:
        confidence = round((1.0 - final_attack_prob) * 100, 2)

    reasons = explain_signal(sample_row)

    return {
        "prediction": int(prediction),                  # 0 = normal, 1 = attack
        "confidence": confidence,                       # final confidence %
        "rf_attack_probability": round(rf_attack_prob * 100, 2),
        "anomaly_attack_probability": round(anomaly_attack_prob * 100, 2),
        "reasons": reasons,
    }


# ============================================================
# OPTIONAL TEST
# ============================================================
if __name__ == "__main__":
    print("Reusable ML detector loaded successfully.")
    print(f"Training samples: {len(df)}")
    print("This module is ready to be imported by website/app.py or other files.")
