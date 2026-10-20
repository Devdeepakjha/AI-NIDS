# AI-Based Client–Server Network Intrusion Detection & Intelligent Traffic Monitoring System (AI-NIDS)

> **College Computer Networks + AI/ML Capstone Project**  
> End-to-end socket-level network telemetry, bidirectional TCP flow reconstruction, strict 42-feature semantic validation, and offline UNSW-NB15 ML intrusion classification with a real-time web console.

---

## System Status & Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Basic TCP Client ↔ Server Sockets | ✅ Complete |
| **2** | Structured JSON Protocol & NDJSON Framing (`shared/protocol.py`) | ✅ Complete |
| **3** | Controlled Traffic Generator (10/100/500 rps) & In-Memory Monitoring | ✅ Complete |
| **4** | Real-time Network Feature Extraction & CSV Dataset Logging | ✅ Complete |
| **5** | Machine Learning Pipeline (XGBoost on UNSW-NB15, 91.1% Accuracy, F1=0.922) | ✅ Complete |
| **6** | Flow Tracking & Strict 42-Feature Gate (Zero-fabrication semantic safety) | ✅ Complete |
| **6.6** | Live Packet Sniffing (Scapy loopback) & Bidirectional Flow Reassembly | ✅ Complete |
| **7** | Live Telemetry & Web Dashboard (Flask + SSE Event Streaming on Port 5055) | ✅ Complete (35/35 Tests Passed) |
| **8** | Attack Simulation & Extended Security Hardening | 🔲 Planned |

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         PC 1 (Client Machine)            |
                      |   client/client.py (Interactive Menu)   |
                      +--------------------+---------------------+
                                           |
                              TCP Sockets  |  NDJSON Requests
                             (Port 5000)   |  (Normal / Med / High)
                                           v
+-----------------------------------------------------------------------------------------+
|                                 PC 2 (Server Machine)                                   |
|                                                                                         |
|  +------------------------+      +-------------------------+      +------------------+  |
|  |   server/server.py     | ---> |   ml/flow_tracker.py    | ---> |  ml/predict.py   |  |
|  | TCP Listener (Port 5000)|      | Bidirectional Flow Track|      | XGBoost Classifier| |
|  +------------------------+      +-------------------------+      +------------------+  |
|              |                                                               |          |
|              v                                                               v          |
|  +------------------------+      +-------------------------+      +------------------+  |
|  | data/network_traffic.csv|     |   ml/feature_gate.py    |      | models/          |  |
|  | Traffic Observation Log|      | Strict 42-Feature Gate  |      | intrusion_model  |  |
|  +------------------------+      +-------------------------+      +------------------+  |
|                                              |                                          |
|                                              v                                          |
|  +-----------------------------------------------------------------------------------+  |
|  |                        server/dashboard_server.py (Port 5055)                     |  |
|  |     Flask Backend + Server-Sent Events (SSE) Stream + Live Packet Sniffer         |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
                                           |
                                      HTTP / SSE
                                           v
                      +------------------------------------------+
                      |          Web Browser Console             |
                      |         http://127.0.0.1:5055/           |
                      |  - Live Packet & Flow Telemetry          |
                      |  - Feature Provenance (42 Features)      |
                      |  - Real-time Event Stream                |
                      |  - Authoritative Vector Demo             |
                      +------------------------------------------+
```

---

## Hassle-Free Quick Start (1-Click Launcher)

A unified launcher (`launch.py`) is provided to run everything quickly without juggling multiple windows:

### 1. Launch Complete System (TCP Server + Live Web Console)
```bash
python launch.py --all
```
* Starts the TCP Socket Server on `0.0.0.0:5000`.
* Starts the Flask Web Dashboard on `127.0.0.1:5055`.
* Automatically opens `http://127.0.0.1:5055/` in your default browser.

### 2. Launch Client Interactive Console (in a separate terminal)
```bash
python launch.py --client
```
Presents the client options:
* `[1]` Send Single Request
* `[2]` Send Multiple Requests (5 sequential)
* `[3]` Normal Traffic Generator (~10 req/sec)
* `[4]` Medium Traffic Generator (~100 req/sec)
* `[5]` High Traffic Generator (~500 req/sec target)
* `[6]` Start Dataset Collection Session
* `[7]` Stop Dataset Collection Session
* `[8]` View Connection Info

### 3. Run Acceptance Test Suite
```bash
python launch.py --test
```
Executes all 35 Phase 7 freeze and regression tests (`tests/test_phase7_cases.py`).

---

## Deployment Modes

### Mode A: Local Single-Machine Deployment (Dev & Demonstration)
Ideal for testing and live demonstration on a single computer:
1. Terminal 1: Run `python launch.py --all`
2. Browser: Navigate to `http://127.0.0.1:5055/`
3. Terminal 2: Run `python launch.py --client` to generate live network traffic.
4. On the Web Console: Click **"Run Authoritative Vector Demonstration"** to see instant verified model inference.

### Mode B: Two-PC LAN Deployment (Hardware Demonstration)
As required by the Computer Networks course specification:
1. **Find Server IP (on PC 2)**:
   ```cmd
   ipconfig
   ```
   Note the IPv4 address (e.g. `192.168.1.15`).
2. **Configure Windows Firewall (on PC 2 as Administrator)**:
   ```powershell
   netsh advfirewall firewall add rule name="AI_NIDS_5000" dir=in action=allow protocol=TCP localport=5000
   netsh advfirewall firewall add rule name="AI_NIDS_5055" dir=in action=allow protocol=TCP localport=5055
   ```
3. **Start Server (on PC 2)**:
   ```bash
   python launch.py --all
   ```
4. **Configure Client (on PC 1)**:
   In `client/config.py`, set:
   ```python
   SERVER_IP = "192.168.1.15"  # Server PC's LAN IP
   ```
5. **Run Client (on PC 1)**:
   ```bash
   python launch.py --client
   ```

---

## Key Computer Networks Concepts Covered

* **Transport Layer (TCP)**: Sockets, 3-way handshake, connection-oriented delivery, ephemeral ports, graceful teardown.
* **Application-Layer Protocol**: Custom JSON-based protocol with newline-delimited framing (NDJSON) preventing TCP segmentation and merging issues.
* **Traffic Observation & Telemetry**: Inter-request pacing, target vs actual rate calculation, packet-level telemetry via Scapy, bidirectional flow state tracking.
* **Network Security & ML**: Strict feature provenance (42 UNSW-NB15 features), zero-fabrication gate, offline XGBoost classifier, real-time intrusion monitoring.

---

## Repository Structure

```
CN Project/
├── README.md                      # Comprehensive project documentation
├── requirements.txt               # Dependencies (pandas, scikit-learn, xgboost, flask, scapy)
├── launch.py                      # Unified 1-click launcher
├── .gitignore                     # Git ignore rules for Python, cache, and test files
│
├── client/
│   ├── client.py                  # Interactive client & traffic generator
│   └── config.py                  # Client configuration (server IP, port, rates)
│
├── server/
│   ├── server.py                  # Core TCP server socket listener (port 5000)
│   ├── dashboard_server.py        # Flask + SSE telemetry server (port 5055)
│   ├── monitor.py                 # In-memory traffic monitor & rate counter
│   ├── dataset_writer.py          # Phase 4 CSV dataset writer
│   ├── detection_logger.py        # Event logger for intrusion predictions
│   └── config.py                  # Server configuration
│
├── shared/
│   └── protocol.py                # Single source of truth for request/response protocol
│
├── dashboard/
│   ├── index.html                 # Modern web console interface
│   ├── style.css                  # Console design system (dark mode, glassmorphism)
│   └── app.js                     # SSE client & dynamic telemetry updates
│
├── ml/
│   ├── predict.py                 # IntrusionPredictor loading XGBoost model
│   ├── flow_tracker.py            # Real-time TCP bidirectional flow tracking
│   ├── feature_gate.py            # Strict 42-feature validation gate
│   ├── unsw_feature_extractor.py  # Feature extractor mapping flows to UNSW-NB15
│   ├── live_inference.py          # End-to-end live inference pipeline
│   ├── packet_capture.py          # Scapy loopback packet sniffer
│   ├── preprocessing.py           # Preprocessing pipeline
│   ├── train.py                   # Model training script
│   └── download_dataset.py        # Automatic UNSW-NB15 dataset downloader
│
├── models/
│   ├── intrusion_model.json       # Trained XGBoost model artifact
│   ├── preprocessor.pkl           # ColumnTransformer & preprocessor
│   ├── feature_schema.json        # 42-feature schema & metadata
│   └── training_metadata.json     # Training metrics (Accuracy 91.1%, F1 0.922)
│
└── tests/                         # Full automated regression & freeze test suite
    ├── test_protocol.py           # Phase 2 protocol unit tests (10/10 PASS)
    ├── test_phase7_cases.py       # Phase 7 final acceptance test suite (35/35 PASS)
    └── ...
```

---

## Pushing to GitHub

To push this repository to your GitHub account:
1. Create a new repository on GitHub (e.g. `AI-NIDS` or `Computer-Networks-Project`).
2. Run the following commands in the project root:
```bash
git remote add origin https://github.com/Devdeepakjha/<YOUR_REPO_NAME>.git
git branch -M main
git push -u origin main
```
