# AI-Based Client–Server Network Intrusion Detection & Intelligent Traffic Monitoring System

> **College Computer Networks + AI/ML Project**  
> Phase-by-phase build — from basic TCP sockets to real-time ML-powered intrusion detection.

---

## Project Overview

This system is built across **8 progressive phases**, each producing a working, demonstrable milestone. Two physically separate computers on the same LAN run the Client and Server respectively.

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Basic TCP Client ↔ Server | ✅ Complete |
| 2 | Structured network requests & responses | 🔲 |
| 3 | Traffic generator + real-time monitoring | 🔲 |
| 4 | Network feature extraction & dataset | 🔲 |
| 5 | ML intrusion detection model (Random Forest) | 🔲 |
| 6 | Real-time ML detection integrated with live traffic | 🔲 |
| 7 | Dashboard + alert system | 🔲 |
| 8 | Attack simulation + complete final integration | 🔲 |

---

## Folder Structure

```
CN Project/
├── README.md
├── requirements.txt
│
├── server/                  ← Run on PC 2
│   ├── server.py
│   └── config.py
│
├── client/                  ← Run on PC 1
│   ├── client.py
│   └── config.py
│
├── shared/                  ← Shared protocol definitions (Phase 2+)
│
└── ml/                      ← Offline ML pipeline (Phase 5+)
    ├── dataset/
    ├── models/
    ├── train.py
    └── evaluate.py
```

---

## Phase 1 — Quick Start

### 1. Find the Server PC's LAN IP (on PC 2)

```
ipconfig
```

Look for **IPv4 Address** under Wi-Fi or Ethernet. Example: `192.168.1.10`

### 2. Allow port 5000 through Windows Firewall (on PC 2)

Run PowerShell **as Administrator**:

```powershell
netsh advfirewall firewall add rule name="CN_Project_5000" dir=in action=allow protocol=TCP localport=5000
```

### 3. Configure the client (on PC 1)

Edit `client/config.py`:

```python
SERVER_IP = "192.168.1.10"   # ← Replace with actual server IP
```

### 4. Start the server (on PC 2)

```
cd server
python server.py
```

### 5. Run the client (on PC 1)

```
cd client
python client.py
```

---

## Expected Output

**PC 2 — Server:**
```
╔══════════════════════════════════════════╗
║    AI-NIDS — TCP SERVER  (Phase 1)       ║
╚══════════════════════════════════════════╝

[20:32:01] [SERVER] Binding to 0.0.0.0:5000 ...
[20:32:01] [SERVER] Listening on port 5000. Backlog = 5
[20:32:01] [SERVER] Press Ctrl+C to stop the server.

[20:32:01] [SERVER] Waiting for a client ...

[20:32:08] [SERVER] ✓ Client connected from 192.168.1.5:54321
[20:32:08] [SERVER] Message received : Hello Server! This is PC 1.

[20:32:08] [SERVER] Response sent    : Hello from Server! ...
[20:32:08] [SERVER] Client 192.168.1.5:54321 disconnected. Socket closed.

[20:32:08] [SERVER] Waiting for a client ...
```

**PC 1 — Client:**
```
╔══════════════════════════════════════════╗
║    AI-NIDS — TCP CLIENT  (Phase 1)       ║
╚══════════════════════════════════════════╝

[20:32:08] [CLIENT] Target server  : 192.168.1.10:5000
[20:32:08] [CLIENT] Message to send: Hello Server! This is PC 1.

[20:32:08] [CLIENT] Connecting to 192.168.1.10:5000 ...
[20:32:08] [CLIENT] ✓ Connected successfully!

[20:32:08] [CLIENT] Sent    : Hello Server! This is PC 1.
[20:32:08] [CLIENT] Response: Hello from Server! [Server IP: 0.0.0.0 | Port: 5000] — Connection acknowledged.

[20:32:08] [CLIENT] Connection closed. Goodbye.
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `Connection REFUSED` | Server not running | Start `server.py` on PC 2 first |
| `Connection TIMED OUT` | Wrong IP or firewall | Check `SERVER_IP` in config; run firewall command above |
| `Address already in use` | Port 5000 taken | Kill old process or change `PORT` in both configs |
| Client connects on same PC but not cross-PC | Firewall blocking | Re-run the `netsh` firewall command as Administrator |

---

## CN Concepts Covered in Phase 1

- **TCP (Transmission Control Protocol)** — reliable, connection-oriented transport
- **IP Address** — identifies each host on the network
- **Port Number** — identifies the service on that host
- **Socket** — software endpoint for network communication
- **Client-Server Architecture** — asymmetric roles; server listens, client connects
- **Three-Way Handshake** — SYN → SYN-ACK → ACK establishes TCP connection
- **Ephemeral Port** — OS-assigned temporary source port for client sockets
- **Graceful Close** — FIN → FIN-ACK terminates TCP connection cleanly
