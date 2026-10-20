"""
=============================================================================
launch.py  --  Unified Launcher for AI-NIDS System
=============================================================================
Quick, hassle-free one-click orchestrator for:
  1. Full Local System : TCP Server (port 5000) + Web Console (port 5055)
  2. Demo PC Mode      : TCP Server + Packet Capture + Cloud Forwarding
  3. Cloud Dashboard   : Standalone Web Console + Ingestion Server (Port $PORT)
  4. Client Console    : Phase 3/4 Traffic Generator
  5. Test Suites       : Automated Verification
=============================================================================
"""

import os
import sys
import time
import socket
import argparse
import webbrowser
import subprocess
import threading

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is currently listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def run_full_system(cloud_url: str = None, cloud_secret: str = None):
    """Start TCP server, Dashboard server, and optional cloud forwarding simultaneously."""
    print("=" * 70)
    print("AI-NIDS: LAUNCHING COMPLETE CLIENT-SERVER & MONITORING SYSTEM")
    print("=" * 70)
    print("-> TCP Socket Server   : 0.0.0.0:5000")
    print("-> Web Telemetry Console: http://127.0.0.1:5055/")
    if cloud_url or os.environ.get("AI_NIDS_CLOUD_URL"):
        c_url = cloud_url or os.environ.get("AI_NIDS_CLOUD_URL")
        print(f"-> Cloud Forwarding    : Active -> {c_url}")
    print("=" * 70)

    # 1. Start Dashboard Server (Flask + Live Packet Telemetry) in background thread
    from ml.live_inference import LiveInferencePipeline
    from server.dashboard_server import DashboardServer

    pipe = LiveInferencePipeline(
        bpf_filter="tcp port 5000",
        cloud_url=cloud_url,
        cloud_secret=cloud_secret
    )
    cap_ok = pipe.start()
    if cap_ok:
        print(f"[CAPTURE] Packet capture active on: {pipe.packet_capture.interface}")
    else:
        print("[CAPTURE] Live packet sniffer inactive (Npcap not installed). Fallback mode active.")

    dash_server = DashboardServer(pipe, host="127.0.0.1", port=5055)
    if not dash_server.start():
        print("[ERROR] Failed to start Dashboard server on port 5055. Is it already running?")
        pipe.stop()
        return

    # 2. Start TCP Server in dedicated thread with lifecycle management
    from server.server import start_server

    server_stop_event = threading.Event()
    server_thread = threading.Thread(
        target=start_server,
        kwargs={"stop_event": server_stop_event},
        name="TCPServerThread",
        daemon=True
    )
    server_thread.start()

    # 3. Safe health check: confirm TCP socket is bound and accepting connections
    print("[HEALTH] Verifying TCP socket binding on 127.0.0.1:5000...")
    server_ready = False
    for attempt in range(1, 11):
        if is_port_in_use(5000, "127.0.0.1"):
            server_ready = True
            break
        time.sleep(0.3)

    if server_ready:
        print("[HEALTH] TCP Server confirmed ONLINE and accepting connections on 0.0.0.0:5000.")
    else:
        print("[WARNING] TCP Server socket did not respond on port 5000 within startup window.")

    # Automatically open browser once services are confirmed active
    try:
        webbrowser.open("http://127.0.0.1:5055/")
    except Exception:
        pass

    try:
        print("\n[SYSTEM READY] Both TCP Server (5000) and Web Dashboard (5055) are active.")
        print("Press Ctrl+C anytime to stop all services cleanly.\n")
        while server_thread.is_alive() and dash_server.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[SYSTEM] Received shutdown signal.")
    finally:
        print("[SYSTEM] Shutting down services...")
        server_stop_event.set()
        dash_server.stop()
        pipe.stop()
        if server_thread.is_alive():
            server_thread.join(timeout=2.0)
        print("[SYSTEM] All services stopped cleanly. Goodbye.")


def run_cloud_dashboard():
    """Run standalone cloud dashboard receiver."""
    print("=" * 70)
    print("AI-NIDS: LAUNCHING PUBLIC CLOUD DASHBOARD (RECEIVER MODE)")
    print("=" * 70)
    port = int(os.environ.get("PORT", 5055))
    host = os.environ.get("HOST", "0.0.0.0")

    from server.dashboard_server import DashboardServer, CloudTelemetryPipeline
    pipe = CloudTelemetryPipeline()
    srv = DashboardServer(pipe, host=host, port=port)
    if not srv.start():
        print(f"[ERROR] Failed to start cloud dashboard on port {port}.")
        return

    print(f"[CLOUD] Serving on http://{host}:{port}/")
    print("[CLOUD] Ready to ingest authenticated events at /api/ingest")
    try:
        while srv.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[CLOUD] Shutting down...")
    finally:
        srv.stop()


def run_client():
    """Run the client interactive console with safe startup health check."""
    from client.config import SERVER_IP, SERVER_PORT

    print("=" * 70)
    print("AI-NIDS: CLIENT TRAFFIC GENERATOR")
    print(f"Target Server: {SERVER_IP}:{SERVER_PORT}")
    print("=" * 70)

    # Safe startup health check: confirm TCP socket is accepting connections
    print(f"[HEALTH] Checking TCP socket connectivity to {SERVER_IP}:{SERVER_PORT}...")
    ready = False
    for attempt in range(1, 4):
        if is_port_in_use(SERVER_PORT, SERVER_IP):
            ready = True
            break
        print(f"  Attempt {attempt}/3: Waiting for server to accept connections...")
        time.sleep(0.5)

    if ready:
        print(f"[HEALTH] Verified! TCP Server is ONLINE and accepting connections on {SERVER_IP}:{SERVER_PORT}.\n")
    else:
        print(f"\n[WARNING] TCP Server on {SERVER_IP}:{SERVER_PORT} is not responding.")
        print(f"  -> Please ensure the server is started in Terminal 1 with: python launch.py --all")
        print(f"  -> Continuing to menu; connections will be attempted upon command selection.\n")

    from client.client import run_menu
    run_menu()


def run_tests():
    """Run full test suite."""
    print("=" * 70)
    print("AI-NIDS: RUNNING SYSTEM VERIFICATION SUITE")
    print("=" * 70)
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], cwd=PROJECT_ROOT)


def main():
    parser = argparse.ArgumentParser(description="AI-NIDS Unified System Launcher")
    parser.add_argument("--all", action="store_true", help="Launch complete system (TCP Server + Dashboard)")
    parser.add_argument("--client", action="store_true", help="Launch interactive client console")
    parser.add_argument("--cloud-dashboard", action="store_true", help="Launch standalone cloud dashboard receiver")
    parser.add_argument("--cloud-url", type=str, default=None, help="Target public cloud dashboard URL to forward events to")
    parser.add_argument("--cloud-secret", type=str, default=None, help="Shared ingestion secret key")
    parser.add_argument("--test", action="store_true", help="Run acceptance test suite")

    args = parser.parse_args()

    if args.cloud_url:
        os.environ["AI_NIDS_CLOUD_URL"] = args.cloud_url
    if args.cloud_secret:
        os.environ["AI_NIDS_INGESTION_SECRET"] = args.cloud_secret

    if args.all:
        run_full_system(args.cloud_url, args.cloud_secret)
    elif args.cloud_dashboard:
        run_cloud_dashboard()
    elif args.client:
        run_client()
    elif args.test:
        run_tests()
    else:
        # Interactive selector
        print("\n" + "=" * 55)
        print("    AI-NIDS UNIFIED LAUNCHER")
        print("=" * 55)
        print("  [1] Start Full Local System (Server + Web Dashboard)")
        print("  [2] Start Demo PC with Cloud Event Forwarding")
        print("  [3] Start Cloud Dashboard Receiver Only")
        print("  [4] Start Client Interactive Console")
        print("  [5] Run Full Automated Test Suite")
        print("  [6] Exit")
        print("=" * 55)
        choice = input("Enter choice (1-6): ").strip()

        if choice == "1":
            run_full_system()
        elif choice == "2":
            url = input("Enter Cloud HTTPS URL (e.g. https://ai-nids.onrender.com): ").strip()
            secret = input("Enter Ingestion Secret (press enter if none): ").strip()
            run_full_system(cloud_url=url, cloud_secret=secret if secret else None)
        elif choice == "3":
            run_cloud_dashboard()
        elif choice == "4":
            run_client()
        elif choice == "5":
            run_tests()
        else:
            print("Exiting.")


if __name__ == "__main__":
    main()
