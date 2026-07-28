# Hybrid Intrusion Detection System (IDS)

A hybrid Network Intrusion Detection System combining signature-based rule matching with machine learning-based anomaly detection, built to identify both known attack patterns and previously unseen anomalous traffic.

## Overview

Traditional signature-based IDS tools catch known attack patterns reliably but miss novel threats. Pure anomaly-detection systems catch unknown threats but often generate more false positives. This project combines both approaches:

- **Signature-based detection**: Real-time rule matching for known attack patterns (port scans, SYN floods)
- **ML-based anomaly detection**: A Gradient Boosting classifier trained on the NSL-KDD dataset, capable of flagging suspicious traffic that doesn't match any predefined rule

## Architecture
Network Traffic
│
▼
Packet Sniffer (Scapy)
│
├──────────────┬──────────────┐
▼ ▼
Signature Engine ML Anomaly Engine
(rule-based) (Gradient Boosting)
│ │
└──────────────┬──────────────┘
▼
Alert Dashboard

## Detection Capabilities

**Signature-based (rule engine):**
- Port scan detection (multiple destination ports from one source in a short window)
- SYN flood detection (excessive connection attempts to a single port)

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
- **Pandas** — data processing
- **Flask** — real-time alert dashboard *(in progress)*

## Project Structure
hybrid-ids/
├── data/
│ ├── raw/ # Captured traffic + NSL-KDD dataset
│ └── processed/ # Cleaned/feature-engineered data
├── src/
│ ├── sniffer.py # Packet capture module
│ └── detector.py # Signature-based detection engine
├── models/ # Trained ML models
├── notebooks/
│ └── ml_model.ipynb # ML training and evaluation
├── docs/ # Architecture notes, diagrams
└── README.md

## Setup

```bash
python3 -m venv ids_env
ids_env\Scripts\activate      # Windows
source ids_env/bin/activate   # Mac/Linux

pip install -r requirements.txt
```

## Usage

### Run the signature-based detector
```bash
python src/detector.py
```
Monitors live traffic and prints alerts when port scan or SYN flood patterns are detected.

### Train / evaluate the ML model
Open `notebooks/ml_model.ipynb` and run all cells to reproduce training and evaluation.

## Design Notes

- **Why hybrid?** Signature-based detection is fast and precise for known threats, but blind to novel attacks. ML-based detection generalizes better to unseen patterns, at the cost of some false positives. Combining both gives broader coverage than either alone.
- **Model choice**: Gradient Boosting outperformed Random Forest on this dataset (81% vs 78% accuracy, better recall on attack traffic) and was selected as the final model.
- **Recall vs precision tradeoff**: The model prioritizes precision (97%) — minimizing false alarms — which is critical in production environments where alert fatigue is a real operational cost. Some recall is traded off as a result; a chunk of missed attacks in testing reflects attack types absent from the training data entirely, which is a realistic challenge in intrusion detection since attacker behavior constantly evolves.
- **Complementary detection coverage**: Testing showed the ML engine's live feature approximation is particularly effective at catching scan-like anomalies (high port diversity from a single source), while the signature engine reliably catches flood-pattern attacks (high volume to a single port) that don't strongly resemble the ML model's training distribution. This is direct evidence for the hybrid design's core premise — no single detection method covers every attack pattern, and combining approaches provides broader coverage than either alone.

## Roadmap

- [x] Packet capture engine
- [x] Signature-based detection (port scan, SYN flood)
- [x] ML-based anomaly detection model
- [ ] Hybrid detection pipeline (combining both engines)
- [ ] Real-time alert dashboard
- [ ] Final documentation and demo