# 🚀 AI-Based DDoS Detection & Adaptive Firewall System

This project is a real-time cybersecurity system that detects Distributed Denial of Service (DDoS) attacks using network traffic analysis and machine learning.

---

## 🔥 Features Implemented

- 📡 Real-time packet capture using Scapy
- 📊 Feature extraction (packet rate, SYN ratio, UDP ratio)
- 🤖 Machine Learning-based DDoS detection (RandomForest)
- 🕵️ Attacker IP identification (most active source)
- 🔐 Basic adaptive firewall using iptables (auto-blocking capability)

---

## 🧠 How It Works
```
Network Traffic
↓
Packet Capture
↓
Feature Extraction
↓
Machine Learning Model
↓
Attack Detection
↓
Attacker Identification
↓
Firewall Blocking (iptables)
```


---

## 🛠️ Technologies Used

- Python
- Scapy
- Pandas
- Scikit-learn
- Linux (iptables)

---

## 📂 Project Structure
```
ddos_project
│
├── src
│ ├── packet_capture.py
│ ├── feature_extraction.py
│ ├── ddos_detector.py
│ ├── firewall_blocker.py
│
├── docs
├── data
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## ⚙️ How to Run

```bash
cd ddos_project
source venv/bin/activate
sudo python src/ddos_detector.py
```
```
===== Extracted Features =====
packet_rate: 3800+
syn_ratio: 0.97
unique_ips: 2
top_ip: 10.0.2.15
==============================

⚠ DDoS ATTACK DETECTED
Attacker IP: 10.0.2.15
```

---

 ⚠️ Disclaimer

This project is for educational purposes only. Do not use it on networks without permission.

👨‍💻 Author : Sachin NR
