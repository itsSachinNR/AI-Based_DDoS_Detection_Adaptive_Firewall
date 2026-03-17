import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from feature_extraction import start_feature_extraction
from firewall_blocker import block_ip   # 🔥 NEW

# Training dataset
data = {
    "packet_rate": [10, 20, 30, 800, 900, 1200],
    "syn_ratio": [0.1, 0.2, 0.15, 0.85, 0.9, 0.95],
    "udp_ratio": [0.05, 0.1, 0.08, 0.02, 0.01, 0.03],
    "unique_ips": [3, 4, 5, 40, 50, 60],
    "label": [0, 0, 0, 1, 1, 1]
}

df = pd.DataFrame(data)

# Features for ML
X = df.drop("label", axis=1)
y = df["label"]

# Train model
model = RandomForestClassifier()
model.fit(X, y)

print("Model trained successfully\n")

# Capture live features
features = start_feature_extraction()

# 🔥 Only pass ML features (not top_ip)
sample = pd.DataFrame([{
    "packet_rate": features["packet_rate"],
    "syn_ratio": features["syn_ratio"],
    "udp_ratio": features["udp_ratio"],
    "unique_ips": features["unique_ips"]
}])

prediction = model.predict(sample)

print("\n===== Traffic Classification =====")

if prediction[0] == 1:
    print("⚠️ DDoS ATTACK DETECTED")

    attacker_ip = features["top_ip"]
    print(f"Attacker IP: {attacker_ip}")

    # Prevent self-block
    if attacker_ip != "10.0.2.15":
        block_ip(attacker_ip)
    else:
        print("⚠️ Skipping block (local test IP)")

else:
    print("Normal Traffic")

print("=================================")
