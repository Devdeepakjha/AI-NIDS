"""
server/dashboard_server.py
=============================================================================
Phase 6.6: Flask Backend & Server-Sent Events (SSE) Stream for Live Dashboard.

Provides:
  - GET /            : Serves dashboard/index.html
  - GET /api/status  : Returns current system & telemetry status JSON
  - GET /api/events  : Server-Sent Events (SSE) stream for live packet/flow updates

Designed for clean startup and shutdown via werkzeug make_server.
Zero orphan threads, zero background leaks.
=============================================================================
"""

import os
import json
import time
import queue
import threading
from typing import Optional, Generator
from flask import Flask, Response, jsonify, send_from_directory
from werkzeug.serving import make_server

from ml.live_inference import LiveInferencePipeline

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")


def create_dashboard_app(pipeline: LiveInferencePipeline) -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(__name__, static_folder=DASHBOARD_DIR, static_url_path="")
    app.config["JSON_SORT_KEYS"] = False

    @app.route("/")
    def index():
        return send_from_directory(DASHBOARD_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(DASHBOARD_DIR, filename)

    @app.route("/api/status")
    def api_status():
        status = pipeline.get_status_summary()
        return jsonify(status)

    @app.route("/api/events")
    def api_events():
        def event_stream() -> Generator[str, None, None]:
            client_queue = pipeline.subscribe()
            try:
                # Send initial snapshot
                initial_data = json.dumps({"type": "snapshot", "data": pipeline.get_status_summary()})
                yield f"data: {initial_data}\n\n"

                while True:
                    try:
                        event = client_queue.get(timeout=1.5)
                        data_str = json.dumps({"type": "event", "data": event})
                        yield f"data: {data_str}\n\n"
                    except queue.Empty:
                        # Send periodic heartbeat to keep SSE connection alive
                        heartbeat = json.dumps({"type": "heartbeat", "time": time.time(), "active_flows": pipeline.flow_tracker.active_flows_count})
                        yield f"data: {heartbeat}\n\n"
            finally:
                pipeline.unsubscribe(client_queue)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    @app.route("/api/demo-authoritative", methods=["POST", "GET"])
    def api_demo_authoritative():
        """
        Run a controlled demonstration of the frozen Phase-5 ML pipeline
        using an offline, complete authoritative 42-feature test vector.
        This verifies model inference without fabricating live network features.
        """
        sample_vector = {
            "dur": 0.001, "proto": "tcp", "service": "-", "state": "FIN",
            "spkts": 2, "dpkts": 2, "sbytes": 100, "dbytes": 100,
            "rate": 2000.0, "sttl": 64, "dttl": 64, "sload": 400000.0, "dload": 400000.0,
            "sloss": 0, "dloss": 0, "sinpkt": 0.5, "dinpkt": 0.5, "sjit": 0.0, "djit": 0.0,
            "swin": 255, "stcpb": 1000, "dtcpb": 1000, "dwin": 255, "tcprtt": 0.001,
            "synack": 0.0005, "ackdat": 0.0005, "smean": 50, "dmean": 50, "trans_depth": 0,
            "response_body_len": 0, "ct_srv_src": 1, "ct_state_ttl": 0, "ct_dst_ltm": 1,
            "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1, "is_ftp_login": 0,
            "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "ct_src_ltm": 1, "ct_srv_dst": 1, "is_sm_ips_ports": 0
        }
        is_valid, gate_status, reasons = pipeline.feature_gate.validate(sample_vector)
        if not is_valid:
            return jsonify({"status": "ERROR", "gate_status": gate_status, "reasons": reasons}), 400

        pred = pipeline.predictor.predict(sample_vector)
        return jsonify({
            "status": "SUCCESS",
            "demo_type": "DEMO B (CONTROLLED AUTHORITATIVE VECTOR)",
            "gate_status": gate_status,
            "prediction": pred["prediction"],
            "intrusion_probability": pred["intrusion_probability"],
            "features_evaluated": len(sample_vector),
            "note": "Verified frozen Phase 5 XGBoost model using an authoritative complete vector."
        })

    return app


class DashboardServer:
    """
    Wraps the Flask app inside a werkzeug server running on a daemon thread.
    Supports clean shutdown via server.shutdown().
    """

    def __init__(self, pipeline: LiveInferencePipeline, host: str = "127.0.0.1", port: int = 5055):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.app = create_dashboard_app(pipeline)
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self) -> bool:
        """Start the dashboard server in a background thread."""
        if self._is_running:
            return True

        try:
            self._server = make_server(self.host, self.port, self.app, threaded=True)
            self._thread = threading.Thread(target=self._server.serve_forever, name="DashboardServerThread", daemon=True)
            self._thread.start()
            self._is_running = True
            print(f"[DASHBOARD] Web dashboard running at http://{self.host}:{self.port}")
            return True
        except Exception as exc:
            print(f"[DASHBOARD] Failed to start dashboard server: {exc}")
            self._is_running = False
            return False

    def stop(self) -> None:
        """Shut down the dashboard server cleanly."""
        if not self._is_running or not self._server:
            return

        self._is_running = False
        try:
            self._server.shutdown()
        except Exception:
            pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None
        print("[DASHBOARD] Dashboard server stopped cleanly.")


if __name__ == "__main__":
    print("=" * 60)
    print("AI-NIDS LIVE TELEMETRY & INTRUSION DETECTION CONSOLE")
    print("=" * 60)
    pipe = LiveInferencePipeline(bpf_filter="tcp port 5000")
    cap_ok = pipe.start()
    if cap_ok:
        print(f"[PIPELINE] Packet capture active on interface '{pipe.packet_capture.interface}'")
    else:
        print("[PIPELINE] Packet capture could not start automatically.")

    srv = DashboardServer(pipe, host="127.0.0.1", port=5055)
    srv_ok = srv.start()
    if srv_ok:
        print("[DASHBOARD] Serving on http://127.0.0.1:5055/")
        print("[DASHBOARD] Press Ctrl+C to shut down.")
        try:
            while srv.is_running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[DASHBOARD] Stopping dashboard server...")
        finally:
            srv.stop()
            pipe.stop()
            print("[DASHBOARD] Shutdown complete.")
