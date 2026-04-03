from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

import pandas as pd
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

# Make sure project root is importable when running:
# python src/evaluate_model.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.train_model import (
    FEATURE_COLUMNS,
    generate_synthetic_dataset,
    load_real_dataset,
)
from src.ddos_detector import load_artifacts, detect_ddos

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42


def load_evaluation_dataset() -> Tuple[pd.DataFrame, str]:
    """
    Use the same dataset source as training.
    If a real CSV exists in /data, it is preferred.
    Otherwise, synthetic data is generated.
    """
    real_df, source = load_real_dataset()

    if real_df is not None:
        df = real_df.copy()
        return df, source

    df = generate_synthetic_dataset(n_normal=1200, n_attack=1200, seed=RANDOM_STATE)
    return df, "synthetic_dataset_generated"


def get_test_split(df: pd.DataFrame):
    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].astype(int).copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    return X_train, X_test, y_train, y_test


def sigmoid_from_score(score: float) -> float:
    """
    Convert anomaly score to a 0..1 attack probability-like value.
    Higher = more attack-like.
    """
    return 1.0 / (1.0 + math.exp(score * 5.0))


def evaluate_classifier(classifier, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    y_pred = classifier.predict(X_test)

    proba = classifier.predict_proba(X_test)
    model_wrapper = classifier.named_steps["model"]
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
        "classification_report": classification_report(
            y_test, y_pred, digits=4, zero_division=0
        ),
    }
    return metrics


def evaluate_anomaly_model(anomaly_model, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    """
    IsolationForest: +1 = normal, -1 = anomaly.
    Convert to 0/1 labels where 1 = attack.
    """
    raw_pred = anomaly_model.predict(X_test)
    y_pred = [1 if v == -1 else 0 for v in raw_pred]

    anomaly_scores = anomaly_model.decision_function(X_test)
    y_score = [sigmoid_from_score(float(s)) for s in anomaly_scores]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_score), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(
            y_test, y_pred, digits=4, zero_division=0
        ),
    }
    return metrics


def evaluate_hybrid_detector(X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    """
    Use the exact runtime detector logic on every test row.
    This is the best proof that your production detector works.
    """
    y_pred = []
    y_score = []
    reasons_sample = []

    for _, row in X_test.iterrows():
        features = row.to_dict()
        result = detect_ddos(features)

        # Reconstruct the same hybrid score used inside the detector
        rf_prob = float(result["rf_attack_probability"]) / 100.0
        an_prob = float(result["anomaly_attack_probability"]) / 100.0
        hybrid_prob = (0.75 * rf_prob) + (0.25 * an_prob)

        y_pred.append(int(result["prediction"]))
        y_score.append(hybrid_prob)

        if not reasons_sample and result.get("reasons"):
            reasons_sample = result["reasons"][:5]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_score), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(
            y_test, y_pred, digits=4, zero_division=0
        ),
        "sample_reasons": reasons_sample,
    }
    return metrics


def save_results(
    dataset_source: str,
    rows: int,
    classifier_metrics: Dict[str, Any],
    anomaly_metrics: Dict[str, Any],
    hybrid_metrics: Dict[str, Any],
) -> None:
    out = {
        "dataset_source": dataset_source,
        "rows": rows,
        "feature_count": len(FEATURE_COLUMNS),
        "classifier_metrics": classifier_metrics,
        "anomaly_metrics": anomaly_metrics,
        "hybrid_metrics": hybrid_metrics,
    }

    metrics_path = MODELS_DIR / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"\nSaved evaluation summary to: {metrics_path}")


def print_block(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    # Load models saved by train_model.py
    classifier, anomaly_model, feature_columns = load_artifacts()

    # Load the same dataset source used for training
    df, dataset_source = load_evaluation_dataset()

    # Respect the exact feature ordering
    df = df[feature_columns + ["label"]].copy()

    _, X_test, _, y_test = get_test_split(df)

    print_block("DATASET INFO")
    print(f"Dataset source : {dataset_source}")
    print(f"Total rows     : {len(df)}")
    print(f"Feature count  : {len(feature_columns)}")
    print(f"Test rows      : {len(X_test)}")
    print(f"Class balance  :")
    print(df["label"].value_counts().sort_index().to_string())

    print_block("CLASSIFIER EVALUATION (RandomForest / ExtraTrees / GradientBoosting Ensemble)")
    classifier_metrics = evaluate_classifier(classifier, X_test, y_test)
    print(f"Accuracy : {classifier_metrics['accuracy']}")
    print(f"Precision: {classifier_metrics['precision']}")
    print(f"Recall   : {classifier_metrics['recall']}")
    print(f"F1 Score : {classifier_metrics['f1']}")
    print(f"ROC-AUC  : {classifier_metrics['roc_auc']}")
    print("\nConfusion Matrix:")
    print(pd.DataFrame(
        classifier_metrics["confusion_matrix"],
        index=["Actual 0", "Actual 1"],
        columns=["Pred 0", "Pred 1"]
    ))
    print("\nClassification Report:")
    print(classifier_metrics["classification_report"])

    print_block("ANOMALY MODEL EVALUATION (IsolationForest)")
    anomaly_metrics = evaluate_anomaly_model(anomaly_model, X_test, y_test)
    print(f"Accuracy : {anomaly_metrics['accuracy']}")
    print(f"Precision: {anomaly_metrics['precision']}")
    print(f"Recall   : {anomaly_metrics['recall']}")
    print(f"F1 Score : {anomaly_metrics['f1']}")
    print(f"ROC-AUC  : {anomaly_metrics['roc_auc']}")
    print("\nConfusion Matrix:")
    print(pd.DataFrame(
        anomaly_metrics["confusion_matrix"],
        index=["Actual 0", "Actual 1"],
        columns=["Pred 0", "Pred 1"]
    ))
    print("\nClassification Report:")
    print(anomaly_metrics["classification_report"])

    print_block("HYBRID DETECTOR EVALUATION (Runtime Logic)")
    hybrid_metrics = evaluate_hybrid_detector(X_test, y_test)
    print(f"Accuracy : {hybrid_metrics['accuracy']}")
    print(f"Precision: {hybrid_metrics['precision']}")
    print(f"Recall   : {hybrid_metrics['recall']}")
    print(f"F1 Score : {hybrid_metrics['f1']}")
    print(f"ROC-AUC  : {hybrid_metrics['roc_auc']}")
    print("\nConfusion Matrix:")
    print(pd.DataFrame(
        hybrid_metrics["confusion_matrix"],
        index=["Actual 0", "Actual 1"],
        columns=["Pred 0", "Pred 1"]
    ))
    print("\nClassification Report:")
    print(hybrid_metrics["classification_report"])

    if hybrid_metrics.get("sample_reasons"):
        print("\nExample reasons from hybrid detector:")
        for r in hybrid_metrics["sample_reasons"]:
            print(f" - {r}")

    save_results(
        dataset_source=dataset_source,
        rows=len(df),
        classifier_metrics=classifier_metrics,
        anomaly_metrics=anomaly_metrics,
        hybrid_metrics=hybrid_metrics,
    )

    print("\nDone.")
    print("Use the HYBRID DETECTOR metrics in your presentation — that is your strongest story.")


if __name__ == "__main__":
    main()
