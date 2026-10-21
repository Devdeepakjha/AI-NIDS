"""
server/dashboard_server.py
=============================================================================
Phase 6.6 & Cloud Telemetry: Flask Backend & Server-Sent Events (SSE) Stream
for Live AI-NIDS Dashboard.

Dual-Mode Operation:
  1. Local Sniffer Mode: Runs on Demo PC directly reading Scapy/Npcap packets.
  2. Cloud Receiver Mode: Runs on public cloud hosting (Render/Railway/etc.),
     ingests authenticated telemetry events via POST /api/ingest from the Demo PC,
     and streams them in real-time to the public web console via SSE.

Features:
  - GET  /                     : Serves dashboard/index.html
  - GET  /<path:filename>      : Serves dashboard static assets
  - GET  /api/status           : Returns system, telemetry & ingestion status JSON
  - GET  /api/events           : Server-Sent Events (SSE) live telemetry stream
  - POST /api/ingest           : Authenticated event ingestion endpoint for Demo PC
  - POST, GET /api/demo-authoritative : Authoritative model verification pipeline

Compatible with WSGI runners (Gunicorn) via module-level `app`.
=============================================================================
"""

import os
import sys
import json
import time
import queue
import socket
import threading
from collections import deque
from typing import Optional, Generator, Dict, Any
from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.serving import make_server

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")

from ml.feature_gate import FeatureGate
from ml.predict import IntrusionPredictor


class CloudTelemetryPipeline:
    """
    Lightweight telemetry and event coordinator for Cloud Dashboard deployments.
    Does NOT require Scapy, Npcap, raw network sockets, or root privileges.
    Receives authenticated events from the Demo PC and coordinates SSE streaming.
    """

    def __init__(self):
        self.flow_tracker = type("DummyFlowTracker", (), {"active_flows_count": 0, "total_flows_count": 0})()
        self.feature_gate = FeatureGate()
        self.predictor = IntrusionPredictor()
        self._lock = threading.Lock()
        self._subscribers = []
        self._recent_events = []
        self._seen_sigs = deque(maxlen=1000)
        self._flow_packets: Dict[str, Tuple[int, int]] = {}
        self.ingested_count = 0
        self.last_ingest_time = None
        self._events_published_count = 0

        self.stats = {
            "packets_captured": 0,
            "flows_reconstructed": 0,
            "vectors_evaluated": 0,
            "vectors_valid": 0,
            "vectors_rejected": 0,
            "predictions_made": 0,
            "benign_count": 0,
            "intrusion_count": 0,
            "last_prediction": None,
            "last_skip_reason": None,
        }

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish_event(self, event: Dict[str, Any]) -> None:
        dead = []
        with self._lock:
            self._events_published_count += 1
            self._recent_events.append(event)
            if len(self._recent_events) > 100:
                self._recent_events = self._recent_events[-100:]
            subscribers_copy = list(self._subscribers)

        for q in subscribers_copy:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)

        if dead:
            with self._lock:
                for q in dead:
                    if q in self._subscribers:
                        self._subscribers.remove(q)

    def ingest_event(self, event: Dict[str, Any]) -> tuple:
        """
        Deduplicate, update telemetry metrics, and publish ingested event.
        Returns (success: bool, message: str).
        """
        flow_id = event.get("flow_id", f"{event.get('src_ip')}:{event.get('src_port')} -> {event.get('dst_ip')}:{event.get('dst_port')}")
        sig = (flow_id, event.get("timestamp"), event.get("spkts"), event.get("dpkts"))

        with self._lock:
            if sig in self._seen_sigs:
                return False, "Duplicate event skipped"
            self._seen_sigs.append(sig)

            self.ingested_count += 1
            self.last_ingest_time = time.time()

            spkts = int(event.get("spkts", 0))
            dpkts = int(event.get("dpkts", 0))
            if flow_id not in self._flow_packets:
                self.stats["flows_reconstructed"] += 1
                delta_pkts = spkts + dpkts
            else:
                prev_s, prev_d = self._flow_packets[flow_id]
                delta_pkts = max(0, spkts - prev_s) + max(0, dpkts - prev_d)
            self._flow_packets[flow_id] = (spkts, dpkts)

            self.stats["packets_captured"] += delta_pkts
            self.stats["vectors_evaluated"] += 1

            status = event.get("inference_status", "SKIPPED")
            if status == "PREDICTED":
                self.stats["vectors_valid"] += 1
                self.stats["predictions_made"] += 1
                pred = event.get("prediction", "BENIGN")
                if pred == "INTRUSION":
                    self.stats["intrusion_count"] += 1
                else:
                    self.stats["benign_count"] += 1
                self.stats["last_prediction"] = event
            else:
                self.stats["vectors_rejected"] += 1
                reasons = event.get("reasons", ["Incomplete features"])
                self.stats["last_skip_reason"] = reasons[0] if reasons else "Incomplete features"

        # Broadcast live to SSE subscribers
        self._publish_event(event)
        return True, "Event ingested successfully"

    def get_status_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "mode": "CLOUD_RECEIVER",
                "cloud_receiver": {
                    "active": True,
                    "ingested_count": self.ingested_count,
                    "last_ingest_time": self.last_ingest_time,
                },
                "packet_capture": {
                    "running": self.ingested_count > 0,
                    "interface": "Remote Forwarder (Demo PC)",
                    "filter": "Live Ingested Telemetry",
                },
                "telemetry": {
                    "active_flows": self.stats["flows_reconstructed"],
                    "total_flows": self.stats["flows_reconstructed"],
                    "sse_events_published": self._events_published_count,
                    **self.stats
                },
                "recent_events": list(self._recent_events[-20:]),
                "domain_shift_disclaimer": (
                    "Phase 5 XGBoost model was trained on the offline UNSW-NB15 dataset. "
                    "Live detection events forwarded from the demo PC are authenticated and displayed in real time."
                )
            }


def check_tcp_server_listening(host: str = "127.0.0.1", port: int = 5000) -> bool:
    """Safe check if the local TCP server is listening on port 5000."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def create_dashboard_app(pipeline: Optional[Any] = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    if pipeline is None:
        pipeline = CloudTelemetryPipeline()

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
        status["tcp_server"] = {
            "host": "127.0.0.1",
            "port": 5000,
            "listening": check_tcp_server_listening("127.0.0.1", 5000)
        }
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
                        active_flows = getattr(pipeline.flow_tracker, "active_flows_count", 0)
                        heartbeat = json.dumps({
                            "type": "heartbeat",
                            "time": time.time(),
                            "active_flows": active_flows
                        })
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

    @app.route("/api/ingest", methods=["POST"])
    def api_ingest():
        """
        Secure ingestion endpoint for receiving detection events forwarded
        from the local Demo PC.
        """
        # 1. Require AI_NIDS_INGESTION_SECRET to be configured for ingestion
        expected_secret = os.environ.get("AI_NIDS_INGESTION_SECRET")
        if not expected_secret or not expected_secret.strip():
            return jsonify({
                "status": "UNCONFIGURED",
                "error": "Server ingestion is disabled: AI_NIDS_INGESTION_SECRET environment variable is not configured."
            }), 503

        auth_hdr = request.headers.get("Authorization", "")
        sec_hdr = request.headers.get("X-AI-NIDS-Secret", "")
        bearer_token = auth_hdr.replace("Bearer ", "").strip() if auth_hdr.startswith("Bearer ") else auth_hdr.strip()
        provided_secret = sec_hdr or bearer_token

        if provided_secret != expected_secret:
            return jsonify({
                "status": "UNAUTHORIZED",
                "error": "Missing or invalid ingestion secret."
            }), 401

        # 2. Check JSON content
        if not request.is_json:
            return jsonify({
                "status": "BAD_REQUEST",
                "error": "Request body must be JSON (application/json)"
            }), 400

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "status": "BAD_REQUEST",
                "error": "JSON body must be an object"
            }), 400

        # 3. Validate required telemetry fields
        required_fields = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "inference_status"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            return jsonify({
                "status": "BAD_REQUEST",
                "error": f"Missing required telemetry fields: {', '.join(missing)}"
            }), 400

        # 4. Ingest into pipeline
        success, msg = pipeline.ingest_event(data)
        if not success:
            return jsonify({"status": "IGNORED", "message": msg}), 200

        return jsonify({
            "status": "SUCCESS",
            "message": "Detection event successfully ingested and broadcasted.",
            "timestamp": data.get("timestamp")
        }), 200

    @app.route("/api/demo-authoritative", methods=["POST", "GET"])
    def api_demo_authoritative():
        """
        Controlled demonstration of the frozen Phase-5 ML pipeline using an offline,
        complete authoritative 42-feature test vector.
        Explicitly labeled as an offline model verification demo rather than live packet detection.
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
            "demo_type": "OFFLINE_AUTHORITATIVE_MODEL_DEMO",
            "gate_status": gate_status,
            "prediction": pred["prediction"],
            "intrusion_probability": pred["intrusion_probability"],
            "features_evaluated": len(sample_vector),
            "note": (
                "Verified frozen Phase 5 XGBoost model using an authoritative complete UNSW-NB15 vector. "
                "This is an offline model benchmark demonstration, not a live packet detection."
            )
        })

    return app


# Default WSGI application entrypoint for Gunicorn or cloud application servers
app = create_dashboard_app()


class DashboardServer:
    """
    Wraps the Flask app inside a werkzeug server running on a daemon thread.
    Supports clean shutdown via server.shutdown().
    """

    def __init__(self, pipeline: Optional[Any] = None, host: str = "0.0.0.0", port: Optional[int] = None):
        self.pipeline = pipeline or CloudTelemetryPipeline()
        self.host = host
        env_port = os.environ.get("PORT")
        self.port = int(env_port) if env_port else (port or 5055)
        self.app = create_dashboard_app(self.pipeline)
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

    # In standalone local mode, try to initialize packet capture
    try:
        from ml.live_inference import LiveInferencePipeline
        pipe = LiveInferencePipeline(bpf_filter="tcp port 5000")
        cap_ok = pipe.start()
        if cap_ok:
            print(f"[PIPELINE] Packet capture active on interface '{pipe.packet_capture.interface}'")
        else:
            print("[PIPELINE] Packet capture could not start automatically (running in telemetry receiver mode).")
    except Exception as exc:
        print(f"[PIPELINE] Running in cloud telemetry receiver mode: {exc}")
        pipe = CloudTelemetryPipeline()

    run_host = os.environ.get("HOST", "0.0.0.0")
    run_port = int(os.environ.get("PORT", 5055))

    srv = DashboardServer(pipe, host=run_host, port=run_port)
    srv_ok = srv.start()
    if srv_ok:
        print(f"[DASHBOARD] Serving on http://{run_host}:{run_port}/")
        print("[DASHBOARD] Press Ctrl+C to shut down.")
        try:
            while srv.is_running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[DASHBOARD] Stopping dashboard server...")
        finally:
            srv.stop()
            if hasattr(pipe, "stop"):
                pipe.stop()
            print("[DASHBOARD] Shutdown complete.")
