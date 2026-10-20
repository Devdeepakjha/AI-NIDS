# AI-Based Client–Server Network Intrusion Detection & Intelligent Traffic Monitoring System (AI-NIDS)

> **College Computer Networks + AI/ML Capstone Project**  
> End-to-end socket-level network telemetry, bidirectional TCP flow reconstruction, strict 42-feature semantic validation, offline UNSW-NB15 ML intrusion classification, and a real-time web console deployable locally or to the public cloud.

---

## System Status & Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Basic TCP Client ↔ Server Sockets | ✅ Complete |
| **2** | Structured JSON Protocol & NDJSON Framing (`shared/protocol.py`) | ✅ Complete (10/10 Tests Passed) |
| **3** | Controlled Traffic Generator (10/100/500 rps) & In-Memory Monitoring | ✅ Complete |
| **4** | Real-time Network Feature Extraction & CSV Dataset Logging | ✅ Complete |
| **5** | Machine Learning Pipeline (XGBoost on UNSW-NB15, 91.1% Accuracy, F1=0.922) | ✅ Complete |
| **6** | Flow Tracking & Strict 42-Feature Gate (Zero-fabrication semantic safety) | ✅ Complete |
| **6.6** | Live Packet Sniffing (Scapy loopback) & Bidirectional Flow Reassembly | ✅ Complete |
| **7** | Live Telemetry & Web Dashboard (Flask + SSE Event Streaming on Port 5055) | ✅ Complete (35/35 Tests Passed) |
| **Cloud** | Authenticated Ingestion Endpoint (`POST /api/ingest`) & WSGI Cloud Deployment | ✅ Complete (7/7 Tests Passed) |
| **8** | Attack Simulation & Extended Security Hardening | 🔲 Planned |

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         Demo PC (Client Machine)         |
                      |   client/client.py (Interactive Menu)   |
                      +--------------------+---------------------+
                                           |
                              TCP Sockets  |  NDJSON Requests
                             (Port 5000)   |  (Normal / Med / High)
                                           v
+-----------------------------------------------------------------------------------------+
|                                 Demo PC (Server Machine)                                |
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
|  |                     ml/live_inference.py -> CloudEventForwarder                   |  |
|  |             Non-blocking HTTPS POST to Public Cloud Dashboard (/api/ingest)       |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
                                           |
                              HTTPS POST   |  Authenticated Telemetry
                                           v
+-----------------------------------------------------------------------------------------+
|                       Public Cloud Dashboard (Render / Railway)                         |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  |                     server/dashboard_server.py (Cloud Receiver)                   |  |
|  |  - Ingestion: POST /api/ingest (Authenticated with secret key)                    |  |
|  |  - Web UI: GET / (Dashboard Console)                                              |  |
|  |  - Live Stream: GET /api/events (Server-Sent Events)                              |  |
|  |  - Model Demo: POST /api/demo-authoritative (Frozen XGBoost verification)          |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
                                           |
                                      HTTP / SSE
                                           v
                      +------------------------------------------+
                      |          Web Browser Console             |
                      |    https://<your-app>.onrender.com       |
                      |  - Live Packet & Flow Telemetry          |
                      |  - Feature Provenance (42 Features)      |
                      |  - Real-time Event Stream                |
                      |  - Offline Authoritative Model Benchmark |
                      +------------------------------------------+
```

---

## Hassle-Free Quick Start (Unified Launcher)

A single entrypoint ([launch.py](file:///c:/Users/Deepak%20Jha/Downloads/CN%20Project/CN%20Project/launch.py)) runs any mode easily:

```bash
# Option 1: Full Local System (Server on 5000 + Local Dashboard on 5055)
python launch.py --all

# Option 2: Full Local System with Cloud Forwarding to your Deployed Dashboard
python launch.py --all --cloud-url https://<YOUR_CLOUD_URL> --cloud-secret <SECRET>

# Option 3: Client Interactive Menu (Traffic Generator)
python launch.py --client

# Option 4: Standalone Cloud Dashboard (Receiver Mode)
python launch.py --cloud-dashboard

# Option 5: Run Automated Verification Tests
python launch.py --test
```

---

## Deployment Modes

### Mode 1: Local Single-Machine Deployment (Dev & Offline Demo)
Ideal for testing on a single computer without an internet connection:
1. **Terminal 1**: Run `python launch.py --all`
   * Opens `http://127.0.0.1:5055/` automatically in your browser.
2. **Terminal 2**: Run `python launch.py --client`
   * Select options `[1]` to `[5]` to generate TCP traffic and observe live telemetry updates.
3. **On the Web Dashboard**: Click **"Run Authoritative Model Pipeline"** to verify the frozen XGBoost model on a genuine UNSW-NB15 vector.

### Mode 2: Two-PC LAN Deployment (Hardware Demonstration)
For demonstration with two computers on the same Wi-Fi / Ethernet LAN:
1. **PC 2 (Server)**: Run `ipconfig` to get your LAN IP (e.g., `192.168.1.15`).
2. **PC 2 (Firewall)**: Allow ports 5000 and 5055 in Windows Firewall (PowerShell as Admin):
   ```powershell
   netsh advfirewall firewall add rule name="AI_NIDS_5000" dir=in action=allow protocol=TCP localport=5000
   netsh advfirewall firewall add rule name="AI_NIDS_5055" dir=in action=allow protocol=TCP localport=5055
   ```
3. **PC 2**: Run `python launch.py --all`.
4. **PC 1 (Client)**: Set `SERVER_IP = "192.168.1.15"` in `client/config.py`, then run `python launch.py --client`.

### Mode 3: Public Cloud Deployment (Public HTTPS Web Dashboard)
Deploy the web dashboard online so professors or reviewers can view your live telemetry console from any browser at a public HTTPS URL.

#### Why Render is Recommended
* Free tier supports Python Web Services directly connected to GitHub.
* Automatic SSL/HTTPS certificates included.
* Native support for Gunicorn and Flask Server-Sent Events (SSE).
* Seamless integration with environment variables (`AI_NIDS_INGESTION_SECRET`).
* *Note on Packet Capture in Cloud*: Cloud containers run on virtual networks where raw packet capture (Scapy/Npcap) is restricted. Our architecture solves this cleanly by running the actual packet capture and inference on the Demo PC and securely forwarding completed events to the Cloud Dashboard via authenticated HTTPS.

#### Step-by-Step Cloud Deployment Guide

1. **Push your code to GitHub**:
   ```bash
   git remote add origin https://github.com/Devdeepakjha/AI-NIDS.git
   git branch -M main
   git push -u origin main
   ```

2. **Create Web Service on [Render.com](https://render.com)**:
   * Sign in to Render (using your GitHub account).
   * Click **New +** > **Web Service**.
   * Select your repository: **`Devdeepakjha/AI-NIDS`**.
   * Fill in the settings:
     * **Name**: `ai-nids-dashboard` (or preferred name)
     * **Language**: `Python 3`
     * **Region**: Oregon (US West) or closest region
     * **Branch**: `main`
     * **Build Command**: `pip install -r requirements.txt`
     * **Start Command**: `gunicorn server.dashboard_server:app --worker-class gthread --workers 1 --threads 8 --timeout 120`
     * **Instance Type**: `Free`
   * Under **Environment Variables**, add:
     * `AI_NIDS_INGESTION_SECRET`: `your-secure-secret-key-2026` (any passphrase of your choice)
   * Click **Create Web Service**.

3. **Get your Public URL**:
   * Once built (takes ~2 minutes), Render will display your public HTTPS URL:
     `https://ai-nids-dashboard.onrender.com`

4. **Connect your Demo PC to the Cloud Dashboard**:
   * On your local Demo PC, start the project with your cloud URL and secret:
     ```bash
     python launch.py --all --cloud-url https://ai-nids-dashboard.onrender.com --cloud-secret your-secure-secret-key-2026
     ```
   * Open `https://ai-nids-dashboard.onrender.com` in any browser.
   * Run the client in another terminal: `python launch.py --client`.
   * Real packet detections and telemetry events from your Demo PC will immediately appear live on your public HTTPS cloud dashboard!

5. **Switching back to Local Mode**:
   * Simply run `python launch.py --all` without the `--cloud-url` flag. The system automatically stays 100% local.

---

## Security & Architecture Integrity Guarantees

* **Zero Fabrication Policy**: The strict 42-feature gate ([ml/feature_gate.py](file:///c:/Users/Deepak%20Jha/Downloads/CN%20Project/CN%20Project/ml/feature_gate.py)) verifies semantic availability for every UNSW-NB15 feature. Incomplete live flows are safely refused with `INVALID_FEATURE_VECTOR` rather than filled with fake data.
* **Non-Blocking Forwarding**: The background worker ([CloudEventForwarder](file:///c:/Users/Deepak%20Jha/Downloads/CN%20Project/CN%20Project/ml/live_inference.py)) uses a thread-safe queue. Local packet capture and socket processing never block on internet delivery.
* **No Sensitive Data Leaks**: Forwarded event payloads contain only connection metadata (IPs, ports, packet counts, inference verdict). No passwords, raw packet payloads, or internal filesystem paths are ever sent.
* **Authentication**: Cloud ingestion rejects unauthenticated or malformed requests with `401 Unauthorized` / `400 Bad Request`.
* **Authoritative Benchmark Separation**: The offline XGBoost model demonstration is explicitly isolated from live packet streams and clearly labeled on the web console.

---

## Test Verification

Run all test suites using Python unittest:
```bash
# 1. Cloud Ingestion & Authentication Tests (7/7 PASS)
python -m unittest tests/test_cloud_ingestion.py

# 2. Final Project Freeze & Regression Suite (35/35 PASS)
python -m unittest tests/test_phase7_cases.py

# 3. Core Protocol Unit Tests (10/10 PASS)
python tests/test_protocol.py
```
