import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# =========================
# TRAIN MODEL (runs once)
# =========================

data = {
    "packet_rate": [10, 20, 30, 800, 900, 1200],
    "syn_ratio": [0.1, 0.2, 0.15, 0.85, 0.9, 0.95],
    "udp_ratio": [0.05, 0.1, 0.08, 0.02, 0.01, 0.03],
    "unique_ips": [3, 4, 5, 40, 50, 60],
    "label": [0, 0, 0, 1, 1, 1]
}

df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)


# =========================
# ML DETECTION FUNCTION 🔥
# =========================

def detect_ddos(features):
    """
    Input: features dictionary
    Output: prediction + confidence
    """

    sample = pd.DataFrame([{
        "packet_rate": features["packet_rate"],
        "syn_ratio": features["syn_ratio"],
        "udp_ratio": features["udp_ratio"],
        "unique_ips": features["unique_ips"]
    }])

    prediction = model.predict(sample)[0]
    probabilities = model.predict_proba(sample)[0]

    confidence = round(max(probabilities) * 100, 2)

    return {
        "prediction": int(prediction),
        "confidence": confidence
    }


# =========================
# OPTIONAL TEST (manual run)
# =========================

if __name__ == "__main__":
    print("This file is now a reusable ML module.")
