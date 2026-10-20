"""
ml/live_inference.py
=============================================================================
Phase 6.6: Live Inference Orchestrator for Real Packet Telemetry.

Connects:
  PacketCapture (Scapy on Loopback)
  -> FlowTracker (TCP bidirectional reconstruction)
  -> UNSWFeatureExtractor (Semantic feature extraction with provenance)
  -> FeatureGate (Strict 42-feature validation)
  -> IntrusionPredictor (Phase 5 XGBoost model reuse)
  -> DetectionLogger (Genuine detection event logging to CSV)

CRITICAL INTEGRITY GUARANTEES:
1. Only valid 42-feature vectors with 100% VALIDATED provenance reach the model.
2. If any feature is UNAVAILABLE, ML inference is bypassed with INVALID_FEATURE_VECTOR.
3. No fake events, no synthetic rows, no placeholder predictions.
=============================================================================
"""

import time
import queue
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from ml.packet_capture import PacketCapture
from ml.flow_tracker import FlowTracker, TCPFlow
from ml.unsw_feature_extractor import UNSWFeatureExtractor
from ml.feature_gate import FeatureGate
from ml.predict import IntrusionPredictor
from server.detection_logger import DetectionLogger


class LiveInferencePipeline:
    """
    Coordinates live packet capture, TCP flow tracking, feature evaluation,
    strict feature gating, ML prediction, and event dispatching.
    """

    def __init__(
        self,
        capture_interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        detection_logger: Optional[DetectionLogger] = None
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

        # Telemetry & Event state
        self._lock = threading.Lock()
        self._subscribers: List[queue.Queue] = []
        self._recent_events: List[Dict[str, Any]] = []

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
        """Start packet capture and live inference pipeline."""
        with self._lock:
            if self._is_running:
                return True

            cap_ok = self.packet_capture.start()
            if not cap_ok:
                return False

            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._maintenance_loop,
                name="LiveInferenceMaintenance",
                daemon=True
            )
            self._worker_thread.start()
            self._is_running = True
            print("[PIPELINE] Live packet inference pipeline started.")
            return True

    def stop(self) -> None:
        """Stop packet capture and pipeline cleanly."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

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
        """Dispatch event to all active SSE subscribers."""
        dead = []
        with self._lock:
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
            return {
                "packet_capture": {
                    "running": self.packet_capture.is_running,
                    "interface": self.packet_capture.interface,
                    "filter": self.packet_capture.bpf_filter,
                },
                "telemetry": {
                    "active_flows": self.flow_tracker.active_flows_count,
                    "total_flows": self.flow_tracker.total_flows_count,
                    **self.stats
                },
                "recent_events": list(self._recent_events[-20:]),
                "domain_shift_disclaimer": (
                    "Phase 5 XGBoost model was trained on the offline UNSW-NB15 dataset. "
                    "Live predictions on localhost traffic are subject to distribution shift. "
                    "Unverified features are strictly rejected to prevent fabricated inference."
                )
            }
