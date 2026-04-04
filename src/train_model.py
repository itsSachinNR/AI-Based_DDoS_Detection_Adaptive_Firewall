from __future__ import annotations

import json
import pickle
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# ============================================================
# PATHS
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# FEATURES
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
    "top_ip_packets",
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
    "packet_count",
    "total_bytes",
    "duration_seconds",
]

DEFAULT_FEATURE_VALUES = {col: 0.0 for col in FEATURE_COLUMNS}


# ============================================================
# UTILS
# ============================================================
def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def normalize_label(value) -> int:
    if pd.isna(value):
        return 0

    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "attack", "ddos", "malicious", "anomaly", "bot", "flood"}:
            return 1
        if v in {"0", "normal", "benign", "legit", "legitimate", "clean"}:
            return 0

    try:
        return int(float(value))
    except Exception:
        return 0


def ensure_numeric_frame(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    for col in FEATURE_COLUMNS:
        if col not in out.columns:
            out[col] = 0.0
        out[col] = pd.to_numeric(out[col], errors="coerce")

    if "label" not in out.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    out["label"] = out["label"].apply(normalize_label)
    out = out[FEATURE_COLUMNS + ["label"]]

    for col in FEATURE_COLUMNS:
        out[col] = out[col].fillna(out[col].median())
        out[col] = out[col].fillna(0.0)

    return out


def add_derived_fields(row: Dict, rng: random.Random) -> Dict:
    duration = float(row["duration_seconds"])
    packet_rate = float(row["packet_rate"])
    avg_bytes_per_packet = float(row["avg_bytes_per_packet"])
    ip_concentration = float(row["ip_concentration"])
    top_dst_port_share = float(row["_top_dst_port_share"])

    packet_count = max(1, int(round(packet_rate * duration)))
    total_bytes = max(1, int(round(packet_rate * avg_bytes_per_packet * duration)))
    top_ip_packets = max(1, int(round(packet_count * ip_concentration)))
    top_dst_port_packets = max(1, int(round(packet_count * top_dst_port_share)))
    top_dst_port_packets = min(top_dst_port_packets, packet_count)

    row["packet_count"] = packet_count
    row["total_bytes"] = total_bytes
    row["top_ip_packets"] = top_ip_packets
    row["top_dst_port_packets"] = top_dst_port_packets
    row["avg_packets_per_ip"] = round(packet_count / max(1, int(row["unique_ips"])), 3)
    row["byte_rate"] = round(total_bytes / duration, 3)
    row["avg_bytes_per_packet"] = round(total_bytes / packet_count, 3)

    row.pop("_top_dst_port_share", None)
    return row


# ============================================================
# SYNTHETIC DATA
# ============================================================
def make_normal_sample(rng: random.Random) -> Dict:
    profile = rng.choice(["browse", "api", "mixed"])
    duration_seconds = rng.uniform(8.0, 12.0)

    if profile == "browse":
        packet_rate = rng.uniform(8, 35)
        syn_ratio = rng.uniform(0.05, 0.16)
        udp_ratio = rng.uniform(0.02, 0.10)
        tcp_ratio = rng.uniform(0.65, 0.88)
        icmp_ratio = rng.uniform(0.00, 0.04)
        unique_ips = rng.randint(10, 40)
        ip_concentration = rng.uniform(0.03, 0.15)
        source_ip_entropy = rng.uniform(2.8, 5.6)
        port_entropy = rng.uniform(2.5, 5.0)
        unique_dst_ports = rng.randint(5, 25)
        top_dst_port_share = rng.uniform(0.05, 0.25)
        packet_size_mean = rng.uniform(350, 900)
        packet_size_std = rng.uniform(20, 180)
        packet_size_min = rng.randint(54, 90)
        packet_size_max = rng.randint(500, 1500)
        avg_inter_arrival = rng.uniform(0.004, 0.05)
        inter_arrival_std = rng.uniform(0.003, 0.03)
        burstiness = rng.uniform(0.2, 0.9)

    elif profile == "api":
        packet_rate = rng.uniform(15, 55)
        syn_ratio = rng.uniform(0.06, 0.14)
        udp_ratio = rng.uniform(0.03, 0.08)
        tcp_ratio = rng.uniform(0.70, 0.92)
        icmp_ratio = rng.uniform(0.00, 0.03)
        unique_ips = rng.randint(15, 50)
        ip_concentration = rng.uniform(0.03, 0.12)
        source_ip_entropy = rng.uniform(3.0, 5.8)
        port_entropy = rng.uniform(3.0, 5.1)
        unique_dst_ports = rng.randint(8, 28)
        top_dst_port_share = rng.uniform(0.05, 0.20)
        packet_size_mean = rng.uniform(250, 750)
        packet_size_std = rng.uniform(25, 120)
        packet_size_min = rng.randint(54, 90)
        packet_size_max = rng.randint(400, 1500)
        avg_inter_arrival = rng.uniform(0.003, 0.03)
        inter_arrival_std = rng.uniform(0.002, 0.02)
        burstiness = rng.uniform(0.25, 0.95)

    else:
        packet_rate = rng.uniform(20, 60)
        syn_ratio = rng.uniform(0.08, 0.18)
        udp_ratio = rng.uniform(0.04, 0.12)
        tcp_ratio = rng.uniform(0.60, 0.85)
        icmp_ratio = rng.uniform(0.00, 0.05)
        unique_ips = rng.randint(12, 45)
        ip_concentration = rng.uniform(0.04, 0.16)
        source_ip_entropy = rng.uniform(3.2, 5.7)
        port_entropy = rng.uniform(3.0, 5.2)
        unique_dst_ports = rng.randint(6, 30)
        top_dst_port_share = rng.uniform(0.06, 0.22)
        packet_size_mean = rng.uniform(300, 850)
        packet_size_std = rng.uniform(20, 150)
        packet_size_min = rng.randint(54, 90)
        packet_size_max = rng.randint(450, 1500)
        avg_inter_arrival = rng.uniform(0.003, 0.04)
        inter_arrival_std = rng.uniform(0.002, 0.025)
        burstiness = rng.uniform(0.25, 1.0)

    other_ratio = clamp(1.0 - (tcp_ratio + udp_ratio + icmp_ratio), 0.0, 0.35)

    return {
        "packet_rate": packet_rate,
        "syn_ratio": syn_ratio,
        "udp_ratio": udp_ratio,
        "unique_ips": unique_ips,
        "tcp_ratio": tcp_ratio,
        "icmp_ratio": icmp_ratio,
        "other_ratio": other_ratio,
        "ip_concentration": ip_concentration,
        "source_ip_entropy": source_ip_entropy,
        "port_entropy": port_entropy,
        "unique_dst_ports": unique_dst_ports,
        "packet_size_mean": packet_size_mean,
        "packet_size_std": packet_size_std,
        "packet_size_min": packet_size_min,
        "packet_size_max": packet_size_max,
        "avg_inter_arrival": avg_inter_arrival,
        "inter_arrival_std": inter_arrival_std,
        "burstiness": burstiness,
        "avg_bytes_per_packet": packet_size_mean * rng.uniform(0.96, 1.04),
        "duration_seconds": duration_seconds,
        "_top_dst_port_share": top_dst_port_share,
    }


def make_attack_sample(rng: random.Random) -> Dict:
    profile = rng.choice(["syn", "udp", "mixed"])
    duration_seconds = rng.uniform(8.0, 12.0)

    if profile == "syn":
        packet_rate = rng.uniform(500, 2500)
        syn_ratio = rng.uniform(0.80, 0.99)
        udp_ratio = rng.uniform(0.00, 0.05)
        tcp_ratio = rng.uniform(0.85, 0.99)
        icmp_ratio = rng.uniform(0.00, 0.01)
        unique_ips = rng.randint(1, 5)
        ip_concentration = rng.uniform(0.70, 1.00)
        source_ip_entropy = rng.uniform(0.00, 0.90)
        port_entropy = rng.uniform(0.00, 0.90)
        unique_dst_ports = rng.randint(1, 3)
        top_dst_port_share = rng.uniform(0.45, 0.98)
        packet_size_mean = rng.uniform(54, 110)
        packet_size_std = rng.uniform(2, 20)
        packet_size_min = rng.randint(40, 60)
        packet_size_max = rng.randint(80, 160)
        avg_inter_arrival = rng.uniform(0.0001, 0.004)
        inter_arrival_std = rng.uniform(0.001, 0.010)
        burstiness = rng.uniform(1.5, 4.0)

    elif profile == "udp":
        packet_rate = rng.uniform(400, 3000)
        syn_ratio = rng.uniform(0.00, 0.12)
        udp_ratio = rng.uniform(0.75, 0.99)
        tcp_ratio = rng.uniform(0.05, 0.25)
        icmp_ratio = rng.uniform(0.00, 0.02)
        unique_ips = rng.randint(1, 8)
        ip_concentration = rng.uniform(0.65, 0.98)
        source_ip_entropy = rng.uniform(0.00, 1.10)
        port_entropy = rng.uniform(0.00, 1.00)
        unique_dst_ports = rng.randint(1, 4)
        top_dst_port_share = rng.uniform(0.50, 0.99)
        packet_size_mean = rng.uniform(60, 220)
        packet_size_std = rng.uniform(5, 35)
        packet_size_min = rng.randint(42, 70)
        packet_size_max = rng.randint(100, 300)
        avg_inter_arrival = rng.uniform(0.0001, 0.003)
        inter_arrival_std = rng.uniform(0.001, 0.012)
        burstiness = rng.uniform(1.5, 4.5)

    else:
        packet_rate = rng.uniform(450, 1800)
        syn_ratio = rng.uniform(0.25, 0.70)
        udp_ratio = rng.uniform(0.20, 0.65)
        tcp_ratio = rng.uniform(0.25, 0.70)
        icmp_ratio = rng.uniform(0.00, 0.02)
        unique_ips = rng.randint(2, 8)
        ip_concentration = rng.uniform(0.65, 0.95)
        source_ip_entropy = rng.uniform(0.10, 1.50)
        port_entropy = rng.uniform(0.10, 1.20)
        unique_dst_ports = rng.randint(1, 5)
        top_dst_port_share = rng.uniform(0.40, 0.95)
        packet_size_mean = rng.uniform(54, 180)
        packet_size_std = rng.uniform(5, 40)
        packet_size_min = rng.randint(40, 70)
        packet_size_max = rng.randint(120, 300)
        avg_inter_arrival = rng.uniform(0.0001, 0.004)
        inter_arrival_std = rng.uniform(0.001, 0.015)
        burstiness = rng.uniform(1.5, 4.0)

    other_ratio = clamp(1.0 - (tcp_ratio + udp_ratio + icmp_ratio), 0.0, 0.20)

    return {
        "packet_rate": packet_rate,
        "syn_ratio": syn_ratio,
        "udp_ratio": udp_ratio,
        "unique_ips": unique_ips,
        "tcp_ratio": tcp_ratio,
        "icmp_ratio": icmp_ratio,
        "other_ratio": other_ratio,
        "ip_concentration": ip_concentration,
        "source_ip_entropy": source_ip_entropy,
        "port_entropy": port_entropy,
        "unique_dst_ports": unique_dst_ports,
        "packet_size_mean": packet_size_mean,
        "packet_size_std": packet_size_std,
        "packet_size_min": packet_size_min,
        "packet_size_max": packet_size_max,
        "avg_inter_arrival": avg_inter_arrival,
        "inter_arrival_std": inter_arrival_std,
        "burstiness": burstiness,
        "avg_bytes_per_packet": packet_size_mean * rng.uniform(0.96, 1.04),
        "duration_seconds": duration_seconds,
        "_top_dst_port_share": top_dst_port_share,
    }


def generate_synthetic_dataset(n_normal: int = 1200, n_attack: int = 1200, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    rows: List[Dict] = []

    for _ in range(n_normal):
        row = make_normal_sample(rng)
        row = add_derived_fields(row, rng)
        row["label"] = 0
        rows.append(row)

    for _ in range(n_attack):
        row = make_attack_sample(rng)
        row = add_derived_fields(row, rng)
        row["label"] = 1
        rows.append(row)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return ensure_numeric_frame(df)


# ============================================================
# DATA LOADING
# ============================================================
def load_real_dataset() -> Tuple[pd.DataFrame | None, str]:
    candidates = [
        DATA_DIR / "ddos_dataset.csv",
        DATA_DIR / "training_data.csv",
        DATA_DIR / "traffic_features.csv",
        DATA_DIR / "network_traffic.csv",
    ]

    for path in candidates:
        if path.exists():
            df = pd.read_csv(path)
            if "label" not in df.columns:
                raise ValueError(f"{path} exists but has no 'label' column.")
            return ensure_numeric_frame(df), str(path)

    return None, "synthetic_dataset_generated"


# ============================================================
# MODELS
# ============================================================
def build_supervised_model() -> Pipeline:
    rf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced_subsample",
        n_jobs=-1,
        min_samples_leaf=2,
    )

    et = ExtraTreesClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced_subsample",
        n_jobs=-1,
        min_samples_leaf=2,
    )

    gb = GradientBoostingClassifier(
        n_estimators=180,
        learning_rate=0.05,
        subsample=0.9,
        random_state=42,
    )

    ensemble = VotingClassifier(
        estimators=[
            ("rf", rf),
            ("et", et),
            ("gb", gb),
        ],
        voting="soft",
        weights=[4, 3, 2],
        n_jobs=-1,
    )

    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("model", ensemble),
        ]
    )


def build_anomaly_model() -> Pipeline:
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", IsolationForest(
                n_estimators=250,
                contamination=0.08,
                random_state=42,
                n_jobs=-1,
            )),
        ]
    )


# ============================================================
# EVALUATION / SAVE
# ============================================================
def evaluate_classifier(model: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> Dict:
    y_pred = model.predict(X_test)

    proba = model.predict_proba(X_test)
    model_wrapper = model.named_steps["model"]
    classes = list(model_wrapper.classes_)
    attack_index = classes.index(1) if 1 in classes else 0
    y_score = proba[:, attack_index]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_score), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, digits=4, zero_division=0),
    }
    return metrics


def save_artifacts(
    classifier: Pipeline,
    anomaly_model: Pipeline,
    feature_columns: List[str],
    metrics: Dict,
    dataset_source: str,
    training_rows: int,
) -> None:
    classifier_path = MODELS_DIR / "ddos_classifier.pkl"
    anomaly_path = MODELS_DIR / "ddos_anomaly.pkl"
    metadata_path = MODELS_DIR / "ddos_metadata.json"
    metrics_path = MODELS_DIR / "ddos_metrics.json"
    feature_path = MODELS_DIR / "feature_columns.json"

    with open(classifier_path, "wb") as f:
        pickle.dump(classifier, f)

    with open(anomaly_path, "wb") as f:
        pickle.dump(anomaly_model, f)

    with open(feature_path, "w", encoding="utf-8") as f:
        json.dump(feature_columns, f, indent=2)

    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_source": dataset_source,
        "training_rows": training_rows,
        "feature_count": len(feature_columns),
        "classifier_file": classifier_path.name,
        "anomaly_file": anomaly_path.name,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved classifier to: {classifier_path}")
    print(f"Saved anomaly model to: {anomaly_path}")
    print(f"Saved feature list to: {feature_path}")
    print(f"Saved metadata to: {metadata_path}")
    print(f"Saved metrics to: {metrics_path}")


def print_feature_importances(classifier: Pipeline) -> None:
    try:
        rf = classifier.named_steps["model"].named_estimators_["rf"]
        importances = pd.Series(rf.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
        print("\nTop feature importances (Random Forest branch):")
        for name, value in importances.head(10).items():
            print(f"  {name:24s} {value:.4f}")
    except Exception as e:
        print(f"\nCould not extract feature importances: {e}")


def train_models() -> Tuple[Pipeline, Pipeline, Dict]:
    real_df, source = load_real_dataset()

    if real_df is not None:
        df = real_df.copy()
        print(f"Loaded real dataset from: {source}")
    else:
        print("No real CSV dataset found. Generating synthetic training data...")
        df = generate_synthetic_dataset(n_normal=1200, n_attack=1200, seed=42)
        source = "synthetic_dataset_generated"

    training_csv = DATA_DIR / "training_data_used.csv"
    df.to_csv(training_csv, index=False)
    print(f"Training data saved to: {training_csv}")

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].astype(int).copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    classifier = build_supervised_model()
    classifier.fit(X_train, y_train)

    normal_train = X_train[y_train == 0]
    anomaly_model = build_anomaly_model()
    anomaly_model.fit(normal_train)

    metrics = evaluate_classifier(classifier, X_test, y_test)

    print("\n==================== EVALUATION ====================")
    print(f"Accuracy : {metrics['accuracy']}")
    print(f"Precision: {metrics['precision']}")
    print(f"Recall   : {metrics['recall']}")
    print(f"F1 Score : {metrics['f1']}")
    print(f"ROC AUC  : {metrics['roc_auc']}")
    print("\nConfusion Matrix:")
    print(pd.DataFrame(metrics["confusion_matrix"], index=["Actual 0", "Actual 1"], columns=["Pred 0", "Pred 1"]))
    print("\nClassification Report:")
    print(metrics["classification_report"])
    print("====================================================")

    print_feature_importances(classifier)

    save_artifacts(
        classifier=classifier,
        anomaly_model=anomaly_model,
        feature_columns=FEATURE_COLUMNS,
        metrics=metrics,
        dataset_source=source,
        training_rows=len(df),
    )

    return classifier, anomaly_model, metrics


if __name__ == "__main__":
    train_models()
    print("\nTraining complete. Model artifacts are now in /models.")
