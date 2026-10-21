"""
ml/live_inference.py
=============================================================================
Phase 6.6 & Cloud Telemetry: Live Inference Orchestrator for Real Packet Telemetry.

Connects:
  PacketCapture (Scapy on Loopback)
  -> FlowTracker (TCP bidirectional reconstruction)
  -> UNSWFeatureExtractor (Semantic feature extraction with provenance)
  -> FeatureGate (Strict 42-feature validation)
  -> IntrusionPredictor (Phase 5 XGBoost model reuse)
  -> DetectionLogger (Genuine detection event logging to CSV)
  -> CloudEventForwarder (Optional non-blocking forwarder to Public Cloud Dashboard)

CRITICAL INTEGRITY GUARANTEES:
1. Only valid 42-feature vectors with 100% VALIDATED provenance reach the model.
2. If any feature is UNAVAILABLE, ML inference is bypassed with INVALID_FEATURE_VECTOR.
3. No fake events, no synthetic rows, no placeholder predictions.
4. Non-blocking cloud forwarding never delays packet capture or inference.
=============================================================================
"""

import os
import sys
import time
import queue
import threading
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from ml.packet_capture import PacketCapture
from ml.flow_tracker import FlowTracker, TCPFlow
from ml.unsw_feature_extractor import UNSWFeatureExtractor
from ml.feature_gate import FeatureGate
from ml.predict import IntrusionPredictor
from server.detection_logger import DetectionLogger

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class CloudEventForwarder:
    """
    Non-blocking background worker that forwards completed detection events
    from the local Demo PC to the public HTTPS cloud dashboard.
    """

    def __init__(self, cloud_url: str, secret: Optional[str] = None):
        self.cloud_url = cloud_url.rstrip("/")
        self.ingest_endpoint = f"{self.cloud_url}/api/ingest"
        self.secret = secret
        self.queue: queue.Queue = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self.events_sent = 0
        self.events_failed = 0
        self.last_status_code: Optional[int] = None
        self.last_error: Optional[str] = None

    def start(self) -> None:
        if not REQUESTS_AVAILABLE:
            print("[CLOUD-FORWARDER] Warning: 'requests' library not available. Cloud forwarding disabled.")
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="CloudForwarderWorker",
            daemon=True
        )
        self._worker_thread.start()
        print(f"[CLOUD-FORWARDER] Started -> Forwarding live events to {self.ingest_endpoint}")

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)
        self._worker_thread = None

    def enqueue(self, event: Dict[str, Any]) -> None:
        if not self._worker_thread or not self._worker_thread.is_alive():
            return

        # Strip any local machine paths or secrets before transmitting
        clean_event = {
            "timestamp": event.get("timestamp"),
            "flow_id": event.get("flow_id"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"),
            "protocol": event.get("protocol"),
            "duration": event.get("duration"),
            "spkts": event.get("spkts"),
            "dpkts": event.get("dpkts"),
            "sbytes": event.get("sbytes"),
            "dbytes": event.get("dbytes"),
            "gate_status": event.get("gate_status"),
            "inference_status": event.get("inference_status"),
            "prediction": event.get("prediction"),
            "probability": event.get("probability"),
            "reasons": event.get("reasons"),
            "origin": "demo_pc_capture"
        }
        try:
            self.queue.put_nowait(clean_event)
        except queue.Full:
            pass

    def _worker_loop(self) -> None:
        session = requests.Session()
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-AI-NIDS-Secret"] = self.secret

        while not self._stop_event.is_set():
            try:
                event = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                resp = session.post(self.ingest_endpoint, json=event, headers=headers, timeout=4.0)
                self.last_status_code = resp.status_code
                if resp.status_code in (200, 201):
                    self.events_sent += 1
                    self.last_error = None
                else:
                    self.events_failed += 1
                    err_msg = f"HTTP {resp.status_code}"
                    self.last_error = err_msg
                    if self.events_failed <= 3 or self.events_failed % 25 == 0:
                        print(f"[CLOUD-FORWARDER] Cloud rejected event: {err_msg}")
            except Exception as exc:
                self.events_failed += 1
                self.last_error = str(exc)
                if self.events_failed <= 3 or self.events_failed % 25 == 0:
                    print(f"[CLOUD-FORWARDER] Delivery error to {self.cloud_url}: {exc}")


class LiveInferencePipeline:
    """
    Coordinates live packet capture, TCP flow tracking, feature evaluation,
    strict feature gating, ML prediction, and event dispatching.
    """

    def __init__(
        self,
        capture_interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        detection_logger: Optional[DetectionLogger] = None,
        cloud_url: Optional[str] = None,
        cloud_secret: Optional[str] = None
    ):
        self.flow_tracker = FlowTracker()
        self.feature_extractor = UNSWFeatureExtractor()
        self.feature_gate = FeatureGate()
        self.detection_logger = detection_logger or DetectionLogger()

        # Load frozen Phase 5 model predictor
        self.predictor = IntrusionPredictor()

        # Packet capture instance
        self.packet_capture = PacketCapture(
            interface=capture_interface,
            bpf_filter=bpf_filter,
            packet_handler=self._on_packet_captured
        )

        # Cloud event forwarder (Demo PC -> Cloud Dashboard)
        target_cloud_url = cloud_url or os.environ.get("AI_NIDS_CLOUD_URL")
        target_secret = cloud_secret or os.environ.get("AI_NIDS_INGESTION_SECRET")
        if target_cloud_url:
            self.cloud_forwarder: Optional[CloudEventForwarder] = CloudEventForwarder(
                cloud_url=target_cloud_url,
                secret=target_secret
            )
        else:
            self.cloud_forwarder = None

        # Telemetry & Event state
        self._lock = threading.Lock()
        self._subscribers: List[queue.Queue] = []
        self._recent_events: List[Dict[str, Any]] = []
        self._seen_sigs: deque = deque(maxlen=1000)
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

        # Background maintenance thread for flow expiration
        self._is_running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> bool:
        """Start packet capture, cloud forwarder, and live inference pipeline."""
        with self._lock:
            if self._is_running:
                return True

            cap_ok = self.packet_capture.start()

            if self.cloud_forwarder:
                self.cloud_forwarder.start()

            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._maintenance_loop,
                name="LiveInferenceMaintenance",
                daemon=True
            )
            self._worker_thread.start()
            self._is_running = True
            if cap_ok:
                print("[PIPELINE] Live packet inference pipeline started.")
            else:
                print(f"[PIPELINE] Packet capture inactive: {self.packet_capture.error_reason}")
            return cap_ok

    def stop(self) -> None:
        """Stop packet capture, cloud forwarder, and pipeline cleanly."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

        if self.cloud_forwarder:
            self.cloud_forwarder.stop()

        self.packet_capture.stop()
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self._worker_thread = None
        print("[PIPELINE] Live packet inference pipeline stopped.")

    def subscribe(self) -> queue.Queue:
        """Subscribe a new client queue to the live event stream."""
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Unsubscribe a client queue."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish_event(self, event: Dict[str, Any]) -> None:
        """Dispatch event to all active SSE subscribers and optional cloud forwarder."""
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

        # Forward to public cloud dashboard if active and not already an ingested event
        if self.cloud_forwarder and not event.get("_is_ingested"):
            self.cloud_forwarder.enqueue(event)

    def ingest_event(self, event: Dict[str, Any]) -> tuple:
        """
        Ingest an externally forwarded event, update counters, and publish to subscribers.
        Returns (success: bool, message: str).
        """
        flow_id = event.get("flow_id", f"{event.get('src_ip')}:{event.get('src_port')} -> {event.get('dst_ip')}:{event.get('dst_port')}")
        sig = (flow_id, event.get("timestamp"), event.get("spkts"), event.get("dpkts"))

        with self._lock:
            if sig in self._seen_sigs:
                return False, "Duplicate event skipped"
            self._seen_sigs.append(sig)

            spkts = int(event.get("spkts", 0))
            dpkts = int(event.get("dpkts", 0))
            self.stats["packets_captured"] += (spkts + dpkts)
            self.stats["flows_reconstructed"] += 1
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

        # Mark as ingested so it doesn't get re-forwarded
        event_copy = dict(event)
        event_copy["_is_ingested"] = True
        self._publish_event(event_copy)
        return True, "Event ingested successfully"

    def _on_packet_captured(self, pkt: Dict[str, Any]) -> None:
        """Callback from PacketCapture for each arriving packet."""
        flow = self.flow_tracker.process_packet(pkt)
        with self._lock:
            self.stats["packets_captured"] += 1
            self.stats["flows_reconstructed"] = self.flow_tracker.total_flows_count

        # If a flow has packets and state CON or FIN, evaluate features
        if flow and flow.spkts > 0 and flow.dpkts > 0:
            self._evaluate_flow(flow)

    def _evaluate_flow(self, flow: TCPFlow) -> None:
        """Extract features, validate with FeatureGate, and predict if valid."""
        features, provenance = self.feature_extractor.extract_features(flow)
        is_valid, gate_status, reasons = self.feature_gate.validate(features, provenance)

        timestamp_str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        flow_id = f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}"

        event_data: Dict[str, Any] = {
            "timestamp": timestamp_str,
            "flow_id": flow_id,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.proto,
            "duration": round(flow.duration, 4),
            "spkts": flow.spkts,
            "dpkts": flow.dpkts,
            "sbytes": flow.sbytes,
            "dbytes": flow.dbytes,
            "gate_status": gate_status,
            "inference_status": "SKIPPED",
            "prediction": None,
            "probability": None,
            "reasons": reasons,
        }

        with self._lock:
            self.stats["vectors_evaluated"] += 1

            if is_valid:
                self.stats["vectors_valid"] += 1
                # Execute genuine model inference
                try:
                    result = self.predictor.predict(features)
                    pred_class = result["prediction"]
                    prob = float(result.get("intrusion_probability", result.get("probability", 0.0)))

                    event_data["inference_status"] = "PREDICTED"
                    event_data["prediction"] = pred_class
                    event_data["probability"] = round(prob, 6)

                    self.stats["predictions_made"] += 1
                    if pred_class == "INTRUSION":
                        self.stats["intrusion_count"] += 1
                    else:
                        self.stats["benign_count"] += 1

                    self.stats["last_prediction"] = event_data

                    # Log genuine detection event to CSV
                    self.detection_logger.log_event(
                        client_ip=flow.src_ip,
                        prediction=pred_class,
                        intrusion_probability=prob,
                        status="SUCCESS"
                    )
                except Exception as exc:
                    event_data["inference_status"] = "ERROR"
                    event_data["reasons"] = [f"Inference error: {exc}"]
            else:
                self.stats["vectors_rejected"] += 1
                self.stats["last_skip_reason"] = reasons[0] if reasons else "Incomplete features"

        # Publish telemetry update
        self._publish_event(event_data)

    def _maintenance_loop(self) -> None:
        """Periodic cleanup of idle flows and emission of heartbeat."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            retired = self.flow_tracker.cleanup_idle_flows()
            for f in retired:
                self.feature_extractor.record_flow_in_history(f)

    def get_status_summary(self) -> Dict[str, Any]:
        """Return snapshot of system status and telemetry metrics."""
        with self._lock:
            cloud_info = {
                "forwarding_enabled": bool(self.cloud_forwarder),
                "events_forwarded": self.cloud_forwarder.events_sent if self.cloud_forwarder else 0,
                "forwarding_failures": self.cloud_forwarder.events_failed if self.cloud_forwarder else 0,
                "last_status_code": self.cloud_forwarder.last_status_code if self.cloud_forwarder else None,
                "last_error": self.cloud_forwarder.last_error if self.cloud_forwarder else None,
                "target_cloud_url": self.cloud_forwarder.cloud_url if self.cloud_forwarder else None
            }
            return {
                "mode": "LOCAL_SNIFFER",
                "cloud_forwarder": cloud_info,
                "packet_capture": {
                    "running": self.packet_capture.is_running,
                    "interface": self.packet_capture.interface,
                    "filter": self.packet_capture.bpf_filter,
                    "packet_count": self.packet_capture.packet_count,
                    "error": self.packet_capture.error_reason,
                },
                "telemetry": {
                    "active_flows": self.flow_tracker.active_flows_count,
                    "total_flows": self.flow_tracker.total_flows_count,
                    "sse_events_published": self._events_published_count,
                    **self.stats
                },
                "recent_events": list(self._recent_events[-20:]),
                "domain_shift_disclaimer": (
                    "Phase 5 XGBoost model was trained on the offline UNSW-NB15 dataset. "
                    "Live predictions on localhost traffic are subject to distribution shift. "
                    "Unverified features are strictly rejected to prevent fabricated inference."
                )
            }
