# Hybrid Intrusion Detection System (IDS)

A hybrid Network Intrusion Detection System combining signature-based 
rule matching with machine learning-based anomaly detection.

## Project Status: In Progress (Day 1/7)

## Setup
\```bash
python3 -m venv ids_env
ids_env\Scripts\activate
pip install -r requirements.txt
\```

## Usage
### Packet Capture
\```bash
python src/sniffer.py
\```
Captures live traffic and logs to `data/raw/captured_packets.csv`

## Project Structure
\```
hybrid-ids/
├── data/
│   ├── raw/
│   └── processed/
├── src/
├── models/
├── logs/
├── docs/
├── notebooks/
\```

## Roadmap
- [x] Day 1: Environment setup + packet capture
- [ ] Day 2: Attack traffic generation
- [ ] Day 3: Signature-based detection module
- [ ] Day 4: ML anomaly detection model
- [ ] Day 5: Hybrid pipeline integration
- [ ] Day 6: Real-time dashboard
- [ ] Day 7: Documentation + final polish