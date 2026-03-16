# AI-Based DDoS Detection & Adaptive Firewall System

This project is a prototype cybersecurity system that detects Distributed Denial of Service (DDoS) attacks using network traffic analysis and machine learning.

## Features

- Real-time packet capture using Scapy
- Traffic analysis and statistics
- Detection of abnormal packet activity
- Identification of potential DDoS attacks

## Technologies Used

- Python
- Scapy
- Pandas
- Scikit-learn
- Flask

## Project Structure

```
ddos_project
│
├── src
│   └── packet_capture.py
│
├── docs
│
├── data
│
├── README.md
├── requirements.txt
└── .gitignore
```


## How It Works

1. Captures network packets using Scapy
2. Extracts traffic features
3. Detects abnormal traffic patterns
4. Identifies possible DDoS attacks

## Future Improvements

- Machine learning-based detection
- Adaptive firewall integration
- Real-time dashboard visualization
