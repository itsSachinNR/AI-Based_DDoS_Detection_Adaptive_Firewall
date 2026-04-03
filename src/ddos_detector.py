from __future__ import annotations

import json
import math
import pickle
from functools import lru_cache
from pathlib import Path
from typing import Dict, Tuple, Any

import pandas as pd
from sklearn.pipeline import Pipeline

# ============================================================
# PATHS
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"

CLASSIFIER_PATH = MODELS_DIR / "ddos_classifier.pkl"
ANOMALY_PATH = MODELS_DIR / "ddos_anomaly.pkl"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.json"

# Keep this aligned with train_model.py
DEFAULT_FEATURE_COLUMNS = [
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

DEFAULT_FEATURE_VALUES = {feature: 0.0 for feature in DEFAULT_FEATURE_COLUMNS}


# ============================================================
# MODEL LOADING
# ============================================================
def _ensure_models_exist() -> None:
    """
    If the trained artifacts are missing, train them once.
    This keeps the detector usable even on first run.
    """
    if CLASSIFIER_PATH.exists() and ANOMALY_PATH.exists():
        return

    print("Model artifacts not found. Training a fresh model once...")
    from src.train_model import train_models
    train_models()


@lru_cache(maxsize=1)
def load_artifacts() -> Tuple[Pipeline, Pipeline, list]:
    """
    Load the saved classifier, anomaly model, and feature list.
    """
    _ensure_models_exist()

    if not CLASSIFIER_PATH.exists():
        raise FileNotFoundError(f"Missing classifier artifact: {CLASSIFIER_PATH}")
    if not ANOMALY_PATH.exists():
        raise FileNotFoundError(f"Missing anomaly artifact: {ANOMALY_PATH}")

    with open(CLASSIFIER_PATH, "rb") as f:
        classifier = pickle.load(f)

    with open(ANOMALY_PATH, "rb") as f:
        anomaly_model = pickle.load(f)

    if FEATURE_COLUMNS_PATH.exists():
        with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as f:
            feature_columns = json.load(f)
    else:
        feature_columns = DEFAULT_FEATURE_COLUMNS

    return classifier, anomaly_model, feature_columns


# ============================================================
# INPUT PREPARATION
# ============================================================
def prepare_sample(features: Dict[str, Any], feature_columns: list) -> pd.DataFrame:
    """
    Convert a feature dictionary into a one-row DataFrame
    in the exact order expected by the model.
    """
    row = {}

    for col in feature_columns:
        value = features.get(col, DEFAULT_FEATURE_VALUES.get(col, 0.0))

        if value is None or value == "":
            value = 0.0

        try:
            row[col] = float(value)
        except (TypeError, ValueError):
            row[col] = 0.0

    return pd.DataFrame([row], columns=feature_columns)


def explain_signal(sample_row: pd.Series) -> list:
    """
    Simple explainability layer for dashboard / debug output.
    """
    reasons = []

    if sample_row.get("packet_rate", 0) > 500:
        reasons.append("Very high packet rate")

    if sample_row.get("syn_ratio", 0) > 0.70:
        reasons.append("SYN-heavy traffic")

    if sample_row.get("udp_ratio", 0) > 0.60:
        reasons.append("UDP-heavy traffic")

    if sample_row.get("unique_ips", 0) <= 3:
        reasons.append("Traffic concentrated on very few IPs")

    if sample_row.get("ip_concentration", 0) > 0.60:
        reasons.append("One IP dominates the traffic")

    if sample_row.get("burstiness", 0) > 1.20:
        reasons.append("Burst-like packet arrival pattern")

    if sample_row.get("source_ip_entropy", 0) < 1.50:
        reasons.append("Low source-IP diversity")

    if sample_row.get("port_entropy", 0) < 1.50:
        reasons.append("Low destination-port diversity")

    if sample_row.get("packet_size_mean", 0) < 120:
        reasons.append("Very small packet size pattern")

    if sample_row.get("avg_inter_arrival", 0) < 0.002:
        reasons.append("Extremely fast packet arrivals")

    return reasons


def _safe_sigmoid(x: float) -> float:
    """
    Convert raw anomaly score into a 0..1 probability-like value.
    """
    return 1.0 / (1.0 + math.exp(x * 5.0))


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================
def detect_ddos(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Input:
        features dictionary from feature_extraction.py

    Output:
        {
            "prediction": 0 or 1,
            "confidence": float,
            "rf_attack_probability": float,
            "anomaly_attack_probability": float,
            "reasons": [ ... ]
        }
    """
    classifier, anomaly_model, feature_columns = load_artifacts()

    sample = prepare_sample(features, feature_columns)
    sample_row = sample.iloc[0]

    # --- Supervised model prediction ---
    rf_prediction = int(classifier.predict(sample)[0])
    rf_probabilities = classifier.predict_proba(sample)[0]

    # Probability for class 1 (attack)
    model_wrapper = classifier.named_steps["model"]
    classes = list(model_wrapper.classes_)
    attack_index = classes.index(1) if 1 in classes else 0
    rf_attack_prob = float(rf_probabilities[attack_index])

    # --- Anomaly model signal ---
    anomaly_score_raw = float(anomaly_model.decision_function(sample)[0])
    anomaly_attack_prob = _safe_sigmoid(anomaly_score_raw)

    # --- Hybrid decision ---
    # Weighted combination: supervised gets more weight
    final_attack_prob = (0.75 * rf_attack_prob) + (0.25 * anomaly_attack_prob)

    # Decision rule:
    # - attack if confidence is sufficiently high
    # - or if both models lean suspicious
    prediction = 1 if (
        final_attack_prob >= 0.55
        or (rf_prediction == 1 and anomaly_attack_prob >= 0.40)
    ) else 0

    confidence = round(
        final_attack_prob * 100, 2
    ) if prediction == 1 else round((1.0 - final_attack_prob) * 100, 2)

    reasons = explain_signal(sample_row)

    return {
        "prediction": int(prediction),                  # 0 = normal, 1 = attack
        "confidence": confidence,
        "rf_attack_probability": round(rf_attack_prob * 100, 2),
        "anomaly_attack_probability": round(anomaly_attack_prob * 100, 2),
        "reasons": reasons,
        "model_name": "Hybrid RF + IsolationForest",
    }


# ============================================================
# OPTIONAL MANUAL TEST
# ============================================================
if __name__ == "__main__":
    print("DDoS detector module loaded.")
    print("This file now loads saved models and performs hybrid inference.")
    print("Run train_model.py first if model artifacts are missing.")

    try:
        from feature_extraction import start_feature_extraction

        features = start_feature_extraction()
        result = detect_ddos(features)

        print("\n===== DETECTION RESULT =====")
        print(f"Prediction : {'DDoS Attack' if result['prediction'] == 1 else 'Normal Traffic'}")
        print(f"Confidence : {result['confidence']}%")
        print(f"RF Prob.   : {result['rf_attack_probability']}%")
        print(f"Anomaly    : {result['anomaly_attack_probability']}%")
        print(f"Reasons    : {', '.join(result['reasons']) if result['reasons'] else 'No strong indicators'}")
        print("============================")
    except Exception as e:
        print(f"Manual test failed: {e}")
