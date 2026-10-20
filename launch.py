"""
=============================================================================
launch.py  --  Unified Launcher for AI-NIDS System
=============================================================================
Quick, hassle-free one-click orchestrator for:
  1. Full System: TCP Server (port 5000) + Live Web Console (port 5055)
  2. Client Interactive Console (Phase 3/4 Traffic Generator)
  3. Acceptance & Regression Test Suite
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


def run_full_system():
    """Start both TCP server and Dashboard server simultaneously."""
    print("=" * 70)
    print("AI-NIDS: LAUNCHING COMPLETE CLIENT-SERVER & MONITORING SYSTEM")
    print("=" * 70)
    print("-> TCP Socket Server   : 0.0.0.0:5000")
    print("-> Web Telemetry Console: http://127.0.0.1:5055/")
    print("=" * 70)

    # 1. Start Dashboard Server (Flask + Live Packet Telemetry) in background thread
    from ml.live_inference import LiveInferencePipeline
    from server.dashboard_server import DashboardServer

    pipe = LiveInferencePipeline(bpf_filter="tcp port 5000")
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

    # Automatically open browser
    try:
        webbrowser.open("http://127.0.0.1:5055/")
    except Exception:
        pass

    # 2. Start TCP Server
    from server.server import start_server

    try:
        print("\n[SYSTEM READY] Press Ctrl+C anytime to stop all services cleanly.\n")
        start_server()
    except KeyboardInterrupt:
        print("\n[SYSTEM] Received shutdown signal.")
    finally:
        print("[SYSTEM] Shutting down Dashboard server...")
        dash_server.stop()
        pipe.stop()
        print("[SYSTEM] All services stopped cleanly. Goodbye.")


def run_client():
    """Run the client interactive console."""
    from client.client import run_menu
    run_menu()


def run_tests():
    """Run full test suite."""
    print("=" * 70)
    print("AI-NIDS: RUNNING SYSTEM VERIFICATION SUITE")
    print("=" * 70)
    subprocess.run([sys.executable, "-m", "unittest", "tests/test_phase7_cases.py"], cwd=PROJECT_ROOT)


def main():
    parser = argparse.ArgumentParser(description="AI-NIDS Unified System Launcher")
    parser.add_argument("--all", action="store_true", help="Launch complete system (TCP Server + Dashboard)")
    parser.add_argument("--client", action="store_true", help="Launch interactive client console")
    parser.add_argument("--test", action="store_true", help="Run acceptance test suite")

    args = parser.parse_args()

    if args.all:
        run_full_system()
    elif args.client:
        run_client()
    elif args.test:
        run_tests()
    else:
        # Interactive selector
        print("\n" + "=" * 50)
        print("    AI-NIDS SYSTEM LAUNCHER")
        print("=" * 50)
        print("  [1] Start Full System (TCP Server + Web Dashboard)")
        print("  [2] Start Client Interactive Console")
        print("  [3] Run Full Acceptance Test Suite")
        print("  [4] Exit")
        print("=" * 50)
        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            run_full_system()
        elif choice == "2":
            run_client()
        elif choice == "3":
            run_tests()
        else:
            print("Exiting.")


if __name__ == "__main__":
    main()
