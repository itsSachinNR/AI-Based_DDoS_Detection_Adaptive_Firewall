# 🛡️ AI-Based DDoS Detection & Adaptive Firewall System

A real-time cybersecurity system that detects Distributed Denial of Service (DDoS) attacks using network traffic analysis, machine learning, and an adaptive firewall response layer. The project also includes a Flask-based monitoring website and a live dashboard for visualizing traffic, alerts, attack logs, and firewall actions.

---

## 🚀 Overview

This project is designed to detect and respond to traffic floods in real time.

It combines:
- Packet capture
- Feature extraction
- Machine learning detection
- IP-based firewall blocking
- Live dashboard monitoring
- Attack logging and auto-unblock support

The system is built for local lab testing, demo environments, and hackathon presentation

---

## 🎯 Problem Statement

Traditional security systems often rely on static rules or delayed manual analysis. That makes them weak against fast traffic floods and automated attacks.

⚡This project addresses:
- Real-time detection delay
- Attack source identification
- Manual mitigation overhead
- Lack of visual monitoring
- Poor response automation

---

## 💡 Proposed Solution

The system monitors live traffic, converts it into behavioral features, classifies it using a machine learning model, and automatically responds using firewall rules.

If malicious activity is detected:
- the suspicious IP is identified,
- the IP is blocked using `iptables`,
- the dashboard is updated,
- the event is logged for review,
- and the block can auto-expire after a short duration.


---

## 🏗️ System Architecture
```
Network / Web Traffic
        ↓
Packet Capture Module
        ↓
Feature Extraction Engine
        ↓
Machine Learning Detection Model
        ↓
Threat Classification Engine
        ↓
Adaptive Firewall (iptables)
        ↓
Auto-Unblock / Logging
        ↓
Real-Time Monitoring Dashboard
```


---

## ⚙️ Key Features

### 🔍 Real-Time Traffic Monitoring
- Captures live network traffic
- Monitors web requests in the Flask app
- Tracks request bursts and source IPs

### 🧠 Feature Extraction
- Packet rate
- SYN ratio
- UDP ratio
- Unique IP count
- Top source IP
- Packets from top source

### ⚡ Machine Learning-Based Detection
- Uses a trained classifier
- Classifies traffic as normal or attack
- Returns a confidence score
- Uses a hybrid inference approach for stronger decisions


### 🔥 Adaptive Firewall Response
- Blocks suspicious IPs using `iptables`
- Supports automatic unblocking after a short timer
- Prevents duplicate blocking rules
- Safer for repeated demo testing


### 📊 Interactive Dashboard & Visualization
- Live status banner
- Traffic graphs
- Attacker snapshot
- Recent request table
- Attack logs panel
- Alerts panel
- Auto-refresh updates

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
- Pandas
- Scikit-learn
- Random Forest
- Isolation Forest

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
│   ├── packet_capture.py
│   ├── feature_extraction.py
│   ├── train_model.py
│   ├── evaluate_model.py
│   ├── ddos_detector.py
│   ├── firewall_blocker.py
│   └── __init__.py
│
├── website/
│   ├── app.py
│   ├── templates/
│   │   ├── index.html
│   │   └── dashboard.html
│   └── static/
│       ├── style.css
│       └── script.js
│
├── data/
├── models/
├── docs/
├── README.md
├── requirements.txt
└── venv/
```


---

## ⚡ How It Works

1. Traffic is captured from network interfaces or web requests  
2. Features are extracted from the captured traffic.
3. The machine learning model predicts whether the traffic is normal or malicious.
4. If attack-like behavior is detected:
   - the top source IP is identified,
   - the firewall blocks the IP,
   - logs are stored,
   - the dashboard updates.  
5. The block can automatically expire after a short time for safe testing.
  

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

### 3️⃣ Train the model

```bash
python src/train_model.py
```

### 4️⃣ Evaluate the model

```bash
python src/evaluate_model.py
```

### 5️⃣ Run the website and dashboard

```bash
python website/app.py
```

### 6️⃣ Open the pages

```text
Home page: http://127.0.0.1:5000/
Dashboard: http://127.0.0.1:5000/dashboard
```
---

## 🖥️ Local Network Demo

For demo purposes, the Flask app can be hosted on your local network and accessed from another device on the same Wi-Fi or hotspot.

### Example setup

* One laptop runs the server
* Another laptop generates traffic
* The dashboard shows live detection and response

### Server run mode

Use host binding that accepts LAN access:

```bash
python website/app.py
```

Inside `app.py`, you can later change the host to:

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```



---

### 📊 Demo Highlights
- 🟢 Live traffic monitoring
- 🔴 Attack detection in real time
- 🔍 Confidence-based classification
- 🚨 Attacker IP identification
- 🔥 Firewall blocking and auto-unblock
- 📈 Live graph updates
- 📜 Attack logs with timestamps
- 📊 Clean dashboard for presentation

---

### 🔮 Future Enhancements
- Better training dataset for higher accuracy
- Deep learning-based anomaly detection
- Multi-node attack simulation
- Role-based login for admin dashboard
- More detailed traffic analytics
- SIEM integration
- Alert export as CSV / PDF

---
  
### 🧠 Key Innovation

This project combines:

- AI-based traffic analysis
- Real-time web monitoring
- Automatic mitigation
- Visual security telemetry

That makes it more than a simple detector — it becomes a compact intelligent defense system.



---

### ⚠️ Disclaimer

This project is intended for educational, research, and hackathon demonstration purposes only.
Do not test it on any network, device, or system without proper authorization.

---

### 👨‍💻 Author

Sachin NR

