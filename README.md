# UEBA Insider Threat Detection System

MSc Cyber Security Project — Security Operations Center (SOC)

## Overview
Real-time insider threat detection using behavioural analytics,
anomaly detection, and explainable AI.

## Tech Stack
- Wazuh SIEM
- Sysmon
- Python (scikit-learn, Flask, SHAP)
- OpenSearch
- Kali Linux (attack simulation)
- MITRE ATT&CK Framework

## Setup
1. Clone the repo
2. Copy config.example.py to config.py
3. Add your credentials to config.py
4. Install dependencies: pip install -r requirements.txt
5. Run: python3 dashboard.py

## Architecture
- log_fetcher.py — fetches alerts from OpenSearch
- feature_engineering.py — extracts behavioural features
- anomaly_detector.py — Isolation Forest detection
- explainer.py — SHAP explainability
- dashboard.py — Flask web dashboard
