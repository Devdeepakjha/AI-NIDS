"""
ml/feature_bridge.py
=============================================================================
Phase 6: Real-Time Feature Extraction, Validation, and UNSW-NB15 Bridge.

Implements:
1. Real-time per-flow connection tracking (thread-safe).
2. Direct feature extraction (Category A) and legitimate derivation (Category B).
3. Explicit refusal to fabricate unavailable Category C features.
4. Strict validation of feature vectors (types, NaN, Inf, ordering).
5. Integration with Phase 5 IntrusionPredictor for verified feature vectors.
6. Event creation and logging to data/detection_events.csv.
=============================================================================
"""

import math
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_audit import AUDIT_RESULTS, get_audit_summary
from ml.predict import IntrusionPredictor
from ml.preprocessing import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
)
from server.detection_logger import DetectionLogger


class FlowTracker:
    """
    Tracks state and byte transfers for a single active TCP connection.
    """

    def __init__(self, client_ip: str, client_port: int, server_ip: str = "127.0.0.1", server_port: int = 5000):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.start_time = time.perf_counter()
        self.end_time = None
        self.state = "CON"  # Connected
        self.proto = "tcp"
        self.service = "-"  # Default: custom structured TCP protocol
        self.sbytes = 0  # Bytes received from client
        self.dbytes = 0  # Bytes sent to client
        self.requests_count = 0
        self.responses_count = 0
        self.response_body_len = 0
        self.trans_depth = 0

    def record_request(self, payload_bytes: int, service_name: str = None):
        self.sbytes += payload_bytes
        self.requests_count += 1
        if service_name is not None:
            self.service = service_name
        if self.service == "http":
            self.trans_depth += 1

    def record_response(self, response_bytes: int):
        self.dbytes += response_bytes
        self.responses_count += 1
        self.response_body_len += response_bytes

    def close(self):
        self.end_time = time.perf_counter()
        self.state = "FIN"

    @property
    def duration(self) -> float:
        curr = self.end_time if self.end_time is not None else time.perf_counter()
        return max(0.0, curr - self.start_time)


class FeatureBridge:
    """
    Extracts, audits, and bridges TCP traffic features to the Phase 5 ML model.
    """

    def __init__(self, model_dir: str = None, logger: DetectionLogger = None):
        if model_dir is None:
            model_dir = os.path.join(PROJECT_ROOT, "models")
        self.model_dir = model_dir
        self.predictor = IntrusionPredictor(model_dir)
        self.logger = logger if logger is not None else DetectionLogger()

        # Audit definitions
        self.audit_summary = get_audit_summary()
        self.cat_a_features = set(self.audit_summary["directly_observable_features"])
        self.cat_b_features = set(self.audit_summary["legitimately_derivable_features"])
        self.cat_c_features = set(self.audit_summary["not_observable_features"])

        # History for rolling 100-connection window metrics
        self._lock = threading.Lock()
        self._conn_history = deque(maxlen=100)

    def record_connection_event(self, client_ip: str, client_port: int, server_port: int, service: str = "-"):
        """Record completed connection in rolling 100-connection history."""
        with self._lock:
            self._conn_history.append({
                "client_ip": client_ip,
                "client_port": client_port,
                "server_port": server_port,
                "service": service,
                "timestamp": time.time()
            })

    def extract_observed_features(self, flow: FlowTracker) -> dict:
        """
        Extract only Category A (directly observed) and Category B (legitimately derived) features.
        Does NOT fabricate Category C features.
        """
        dur = flow.duration
        sbytes = flow.sbytes
        dbytes = flow.dbytes

        # Legitimate derivations
        sload = (sbytes * 8.0) / max(dur, 1e-6)
        dload = (dbytes * 8.0) / max(dur, 1e-6)
        is_same = 1 if (flow.client_ip == flow.server_ip and flow.client_port == flow.server_port) else 0

        # Window history computations under lock
        with self._lock:
            history = list(self._conn_history)

        ct_srv_src = sum(1 for c in history if c["client_ip"] == flow.client_ip and c["service"] == flow.service)
        ct_dst_ltm = len(history)
        ct_src_dport_ltm = sum(1 for c in history if c["client_ip"] == flow.client_ip and c["server_port"] == flow.server_port)
        ct_dst_sport_ltm = sum(1 for c in history if c["client_port"] == flow.client_port)
        ct_dst_src_ltm = sum(1 for c in history if c["client_ip"] == flow.client_ip)
        ct_src_ltm = sum(1 for c in history if c["client_ip"] == flow.client_ip)
        ct_srv_dst = sum(1 for c in history if c["service"] == flow.service)

        return {
            # Category A (Directly Observable)
            "proto": flow.proto,
            "service": flow.service,
            "state": flow.state,
            "dur": round(dur, 6),
            "sbytes": int(sbytes),
            "dbytes": int(dbytes),

            # Category B (Legitimately Derivable)
            "sload": round(sload, 2),
            "dload": round(dload, 2),
            "trans_depth": int(flow.trans_depth if flow.service == "http" else 0),
            "response_body_len": int(flow.response_body_len if flow.service == "http" else 0),
            "ct_srv_src": int(max(1, ct_srv_src)),
            "ct_dst_ltm": int(max(1, ct_dst_ltm)),
            "ct_src_dport_ltm": int(max(1, ct_src_dport_ltm)),
            "ct_dst_sport_ltm": int(max(1, ct_dst_sport_ltm)),
            "ct_dst_src_ltm": int(max(1, ct_dst_src_ltm)),
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            "ct_src_ltm": int(max(1, ct_src_ltm)),
            "ct_srv_dst": int(max(1, ct_srv_dst)),
            "is_sm_ips_ports": is_same,
        }

    def validate_feature_vector(self, features: dict) -> tuple:
        """
        Strict validation of feature dictionary:
        - All required features exist
        - No unexpected extra features
        - Correct data types
        - No NaN
        - No Infinity
        - Valid numeric ranges
        Returns (is_valid: bool, error_reason: str, ordered_features: dict)
        """
        if not isinstance(features, dict):
            return False, "Features must be a dictionary", None

        # Check for unexpected extra features
        unexpected = [k for k in features if k not in ALL_MODEL_FEATURES]
        if unexpected:
            return False, f"Unexpected feature keys: {unexpected}", None

        # Check for missing features
        missing = [k for k in ALL_MODEL_FEATURES if k not in features]
        if missing:
            return False, f"Missing required features ({len(missing)} missing): {missing}", None

        ordered = {}
        for col in ALL_MODEL_FEATURES:
            val = features[col]

            if col in CATEGORICAL_FEATURES:
                if not isinstance(val, str):
                    return False, f"Categorical feature '{col}' must be a string, got {type(val).__name__}", None
                ordered[col] = val.strip().lower()

            elif col in NUMERICAL_FEATURES:
                if val is None or isinstance(val, str):
                    try:
                        fval = float(val)
                    except (ValueError, TypeError):
                        return False, f"Numerical feature '{col}' contains invalid non-numeric value: {val!r}", None
                elif isinstance(val, (int, float)):
                    fval = float(val)
                else:
                    return False, f"Numerical feature '{col}' contains invalid type {type(val).__name__}", None

                if math.isnan(fval) or np.isnan(fval):
                    return False, f"Numerical feature '{col}' contains NaN", None
                if math.isinf(fval) or np.isinf(fval):
                    return False, f"Numerical feature '{col}' contains Infinity", None
                if fval < 0 and col not in ["swin", "dwin"]:
                    return False, f"Numerical feature '{col}' cannot be negative ({fval})", None

                ordered[col] = fval

        return True, "", ordered

    def predict_flow(self, features: dict, client_ip: str = "127.0.0.1") -> dict:
        """
        Executes safe prediction on a candidate feature vector.
        
        If features are missing or unobservable:
          Refuses to fabricate values and returns structured ERROR.
        If features are valid:
          Runs model prediction and logs real detection event.
        """
        is_valid, reason, validated_dict = self.validate_feature_vector(features)

        if not is_valid:
            # Structured refusal / validation failure
            error_event = {
                "status": "ERROR",
                "reason": "INVALID_FEATURE_VECTOR",
                "message": reason,
                "timestamp": datetime.now().isoformat(),
                "client_ip": client_ip,
            }
            return error_event

        # Valid feature vector -> predict using Phase 5 model
        pred_res = self.predictor.predict(validated_dict)
        pred_label = pred_res["prediction"]
        prob = pred_res["intrusion_probability"]

        event = {
            "status": "SUCCESS",
            "timestamp": datetime.now().isoformat(),
            "client_ip": client_ip,
            "prediction": pred_label,
            "intrusion_probability": prob
        }

        # Log to data/detection_events.csv
        self.logger.log_event(client_ip, pred_label, prob, status="SUCCESS")
        return event


class LiveDetectionBridge:
    """
    High-level thread-safe singleton bridge connected to the TCP server.
    """

    def __init__(self, bridge: FeatureBridge = None):
        self.bridge = bridge if bridge is not None else FeatureBridge()
        self._active_flows = {}
        self._lock = threading.Lock()

    def on_connect(self, client_ip: str, client_port: int, server_port: int = 5000):
        key = (client_ip, client_port)
        with self._lock:
            self._active_flows[key] = FlowTracker(client_ip, client_port, server_port=server_port)

    def on_request(self, client_ip: str, client_port: int, payload_bytes: int, service: str = "-"):
        key = (client_ip, client_port)
        with self._lock:
            flow = self._active_flows.get(key)
            if flow:
                flow.record_request(payload_bytes, service)

    def on_response(self, client_ip: str, client_port: int, response_bytes: int):
        key = (client_ip, client_port)
        with self._lock:
            flow = self._active_flows.get(key)
            if flow:
                flow.record_response(response_bytes)

    def on_disconnect(self, client_ip: str, client_port: int) -> dict:
        key = (client_ip, client_port)
        with self._lock:
            flow = self._active_flows.pop(key, None)

        if not flow:
            return {"status": "ERROR", "reason": "FLOW_NOT_FOUND"}

        flow.close()
        # Record into history
        self.bridge.record_connection_event(client_ip, client_port, flow.server_port, flow.service)

        # Extract real observed/derived features
        observed = self.bridge.extract_observed_features(flow)

        # Note: Live stream without raw packet capture does not observe Category C features
        # We explicitly refuse to fabricate them
        eval_result = self.bridge.predict_flow(observed, client_ip=client_ip)
        return eval_result
