# Network Intrusion Detection System (ML-Powered)

A machine-learning system that inspects network connection records and flags
intrusions in real time, served through an interactive web dashboard. Built on
the NSL-KDD benchmark dataset using a Random Forest classifier.

> Final-year project for a Network Systems Engineering degree — bridging
> networking, machine learning, and full-stack development.

## What it does

The system learns the difference between normal traffic and network attacks
(denial-of-service, port scans, remote intrusions, privilege escalation), then
scans incoming connections and raises alerts on anything suspicious — with a
tunable sensitivity control for trading off detection rate against false alarms.

## Pipeline

The project runs in two phases: an offline **training** phase that turns a
labelled dataset into a trained model, and a live **detection** phase that
reuses that model to classify traffic.

`raw dataset → preprocessing → trained model → dashboard inference → alerts`

## Dataset

[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) — a refined version of the
classic KDD intrusion-detection benchmark.

- 125,973 labelled training connections, 22,544 test connections
- 41 features per connection (protocol, service, byte counts, flag states, etc.)
- The test set deliberately contains attack types absent from training, to
  measure detection of *novel* attacks

## Results

| Metric | Value |
|---|---|
| Features after one-hot encoding | 122 |
| Overall test accuracy | 77.9% |
| Attack precision | 97% |
| Attack recall (default threshold 0.5) | 63% |
| Attack recall (tuned threshold 0.3) | 72% |
| False-alarm rate (tuned) | ~3% |

The model reaches near-perfect accuracy on familiar traffic but ~78% on the
held-out set — expected, because that set contains unseen attack families. I
tuned the decision threshold from 0.5 to 0.3, lifting attack detection from
63% to 72% while keeping false alarms near 3%, reflecting the security reality
that a missed attack costs more than a false alarm.

## Tech stack

Python · pandas · scikit-learn (Random Forest) · Streamlit · joblib

## How to run

```bash
# 1. Clone and enter the project
git clone <your-repo-url>
cd ml-ids

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\Activate.ps1      # Windows
# source venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Build the model (run once, in order)
python preprocess.py
python train.py

# 5. Launch the dashboard
streamlit run dashboard.py
```

## Project structure
ml-ids/
├── data/                  # NSL-KDD dataset files
├── explore.py             # initial data exploration
├── preprocess.py          # cleaning + feature encoding
├── train.py               # model training + evaluation
├── evaluate_thresholds.py # decision-threshold tuning experiment
├── dashboard.py           # interactive Streamlit IDS dashboard
├── requirements.txt
└── README.md

## Possible improvements

- Multi-class detection (identify *which* attack family, not just attack/normal)
- Live packet capture with Scapy to classify real traffic, not dataset records
- Compare Random Forest against gradient boosting (XGBoost) and a neural network

## Author

Isuka Amaneth — [LinkedIn](www.linkedin.com/in/isuka-amaneth-87725629b) · [GitHub]([your-link](https://github.com/isuka-amaneth))"# Live_Network_Traffic_Monitor" 
