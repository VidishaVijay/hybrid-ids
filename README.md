# Hybrid Intrusion Detection System (IDS)

A hybrid Network Intrusion Detection System combining signature-based rule matching with machine learning-based anomaly detection, built to identify both known attack patterns and previously unseen anomalous traffic in real time.

## Overview

Traditional signature-based IDS tools catch known attack patterns reliably but miss novel threats. Pure anomaly-detection systems catch unknown threats but often generate more false positives. This project combines both approaches into a single pipeline with a live monitoring dashboard:

- **Signature-based detection**: Real-time rule matching for known attack patterns (port scans, SYN floods)
- **ML-based anomaly detection**: A Gradient Boosting classifier trained on the NSL-KDD dataset, flagging suspicious traffic that doesn't match any predefined rule
- **Live dashboard**: A Flask web interface displaying alerts from both engines in real time

## Architecture
```
                Network Traffic
                       |
                       v
              Packet Sniffer (Scapy)
                       |
        +--------------+--------------+
        |                             |
        v                             v
 Signature Engine              ML Anomaly Engine
   (rule-based)               (Gradient Boosting)
        |                             |
        +--------------+--------------+
                       |
                       v
              Alert Dashboard (Flask)
​

## Detection Capabilities

**Signature-based (rule engine):**
- Port scan detection — flags a source hitting multiple destination ports within a short time window
- SYN flood detection — flags excessive connection attempts to a single port from one source

**ML-based (anomaly detection):**
- Trained on the NSL-KDD intrusion detection dataset (125,973 labeled network connections)
- Gradient Boosting Classifier, achieving:
  - **81% overall accuracy**
  - **97% precision** on attack detection (very low false-positive rate)
  - **69% recall** on attack detection

## Tech Stack

- **Python** — core language
- **Scapy** — live packet capture
- **Scikit-learn** — machine learning model (Gradient Boosting)
- **Pandas** — data processing and feature engineering
- **Flask** — real-time alert dashboard

## Project Structure

hybrid-ids/
├── data/
│   ├── raw/               # Captured traffic + NSL-KDD dataset
│   └── processed/          # Cleaned/feature-engineered data
├── src/
│   ├── sniffer.py           # Packet capture module
│   ├── detector.py          # Signature-based detection engine
│   ├── hybrid_detector.py   # Combined signature + ML detection pipeline
│   ├── dashboard.py         # Flask app serving the live dashboard
│   └── templates/
│       └── dashboard.html   # Dashboard frontend
├── models/                 # Trained ML models (Gradient Boosting classifier)
├── notebooks/
│   └── ml_model.ipynb       # ML training and evaluation
├── docs/                   # Architecture notes, demo recording
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv ids_env
ids_env\Scripts\activate      # Windows
source ids_env/bin/activate   # Mac/Linux

pip install -r requirements.txt
```

## Usage

### Run the full hybrid system with live dashboard
```bash
python src/dashboard.py
```
Open `http://localhost:5000` in your browser to view real-time detection alerts from both the signature-based and ML-based engines.

### Run signature-based detection only (terminal output)
```bash
python src/detector.py
```

### Train / evaluate the ML model
Open `notebooks/ml_model.ipynb` and run all cells to reproduce training and evaluation.

## Demo

A recorded walkthrough of the system detecting a live port scan — showing both the signature engine and ML engine independently flagging the same attack in real time on the dashboard — is available here: **[https://drive.google.com/drive/u/1/folders/1o0rLQXGEJCdHt103L7k6u6a78sWGw3LN]**

## Design Notes

- **Why hybrid?** Signature-based detection is fast and precise for known threats, but blind to novel attacks. ML-based detection generalizes better to unseen patterns, at the cost of some false positives. Combining both gives broader coverage than either alone.
- **Model choice**: Gradient Boosting outperformed Random Forest on this dataset (81% vs 78% accuracy, better recall on attack traffic) and was selected as the final model.
- **Recall vs precision tradeoff**: The model prioritizes precision (97%) — minimizing false alarms — which is critical in production environments where alert fatigue is a real operational cost. Some recall is traded off as a result; a portion of missed attacks in testing reflects attack types absent from the training data entirely, a realistic challenge in intrusion detection since attacker behavior constantly evolves.
- **Complementary detection coverage**: Testing showed the ML engine's live feature approximation is particularly effective at catching scan-like anomalies (high port diversity from a single source), while the signature engine reliably catches flood-pattern attacks (high volume to a single port) that don't strongly resemble the ML model's training distribution. This is direct evidence for the hybrid design's core premise — no single detection method covers every attack pattern, and combining approaches provides broader coverage than either alone.

## Roadmap

- [x] Packet capture engine
- [x] Signature-based detection (port scan, SYN flood)
- [x] ML-based anomaly detection model
- [x] Hybrid detection pipeline (combining both engines)
- [x] Real-time alert dashboard
- [ ] Multi-class attack classification (currently binary: normal/attack)
- [ ] Persistent alert logging to file/database

