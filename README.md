# 🛡️ AI-Based DDoS Detection & Adaptive Firewall System

## 🚀 Overview

This project is a **real-time AI-powered cybersecurity system** designed to detect and mitigate Distributed Denial of Service (DDoS) attacks.

It integrates **network traffic monitoring, machine learning-based anomaly detection, automated firewall response, and a live visualization dashboard** into a unified system.

---

## 🎯 Problem Statement

Traditional DDoS detection systems rely on **static thresholds and delayed analysis**, making them ineffective against modern, dynamic, and automated attacks.

There is a need for:
- ⚡ Real-time detection  
- 🧠 Intelligent anomaly recognition  
- 🔥 Automated response mechanisms  

---

## 💡 Proposed Solution

Our system provides an **end-to-end pipeline** that:

- Captures real-time traffic (network + web)
- Extracts behavioral traffic features
- Detects anomalies using Machine Learning
- Identifies attacker IPs
- Automatically blocks malicious traffic using firewall rules
- Visualizes all activity through a live dashboard

---

## 🏗️ System Architecture
```
Network / Web Traffic
        ↓
Packet Capture Module (Scapy / Flask)
        ↓
Feature Extraction Engine
        ↓
Machine Learning Detection Model (Random Forest)
        ↓
Threat Classification Engine
        ↓
Adaptive Firewall (iptables)
        ↓
Real-Time Monitoring Dashboard
```


---

## ⚙️ Key Features

### 🔍 Real-Time Traffic Monitoring
- Captures live network packets and HTTP requests
- Tracks request rate, IP distribution, and traffic patterns

### 🧠 AI-Based DDoS Detection
- Uses **Random Forest Classifier**
- Detects anomalies based on traffic behavior
- Provides **confidence score** for predictions

### 🔥 Adaptive Firewall Response
- Automatically blocks attacker IPs using `iptables`
- Prevents further malicious requests in real-time

### 📊 Interactive Dashboard
- Live traffic visualization (Chart.js graphs)
- Real-time attack status (Normal / DDoS)
- Top attacker identification
- Confidence-based alerts

### 📜 Attack Logging System
- Logs attack events with:
  - Timestamp
  - Attacker IP
  - Packet rate
  - Confidence score
  - Action taken (Blocked / Detected)

---

## 🛠️ Tech Stack

### Backend
- Python
- Flask

### Machine Learning
- Scikit-learn (Random Forest)

### Networking
- Scapy (packet capture & analysis)

### Frontend
- HTML, CSS, JavaScript
- Chart.js (real-time visualization)

### Security
- Linux iptables (firewall automation)

---

## 📂 Project Structure
```
ddos_project/
│
├── src/
│ ├── packet_capture.py # Packet capture module
│ ├── feature_extraction.py # Feature engineering
│ ├── ddos_detector.py # ML detection engine
│ ├── firewall_blocker.py # Firewall automation
│
├── website/
│ ├── app.py # Flask backend
│ ├── templates/ # HTML dashboard
│ └── static/ # CSS & assets
│
├── data/
├── docs/
├── README.md
├── requirements.txt
└── venv/
```


---

## ⚡ How It Works

1. Traffic is captured from network interfaces or web requests  
2. Key features are extracted:
   - Packet rate
   - SYN ratio
   - UDP ratio
   - Unique IP count  
3. ML model classifies traffic:
   - Normal Traffic  
   - DDoS Attack  
4. If attack detected:
   - Attacker IP is identified  
   - Firewall blocks the IP  
5. Dashboard updates in real-time  

---

## 🧪 Running the Project

### 1️⃣ Activate Virtual Environment

```bash
cd ddos_project
source venv/bin/activate
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run Website Dashboard
```bash
python website/app.py
```

### 4️⃣ Open Dashboard
```bash
http://127.0.0.1:5000/dashboard
```

---

### 📊 Demo Highlights
- 🟢 Normal traffic monitoring
- 🔴 Real-time DDoS detection
- 📈 Live packet rate graph
- 🚨 Attack logs with timestamps
- 🔥 Automatic attacker IP blocking

---

### 🔮 Future Enhancements
- Deep Learning models (LSTM / Autoencoders)
- Distributed DDoS detection system
- Cloud deployment (AWS / Azure)
- Adaptive threshold learning
- Integration with SIEM tools

---
  
### 🧠 Key Innovation

Combines AI-based detection, real-time monitoring, and automated defense into a single intelligent cybersecurity system.

---

### ⚠️ Disclaimer

This project is intended for educational and research purposes only.
Do not deploy or test on networks without proper authorization.

---

### 👨‍💻 Author

Sachin NR

