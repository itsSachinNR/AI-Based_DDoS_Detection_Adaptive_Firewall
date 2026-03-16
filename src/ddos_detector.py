import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from feature_extraction import start_feature_extraction

# Training dataset
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

print("Model trained successfully")

# Capture live features
features = start_feature_extraction()


sample = pd.DataFrame([features])

prediction = model.predict(sample)

if prediction[0] == 1:
    print("⚠️ DDoS ATTACK DETECTED")
else:
    print("Normal Traffic")
