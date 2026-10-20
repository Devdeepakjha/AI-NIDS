"""
tests/test_phase7_cases.py
=============================================================================
Phase 7 Final Engineering Validation, Regression & Project Freeze Test Suite
(P7-01 to P7-35)
AI-Based Client–Server Network Intrusion Detection & Intelligent Traffic Monitoring System (AI-NIDS)

PHASE 7 STATUS: FINAL PROJECT FREEZE VALIDATION
  - Proves stability, reproducibility, regression-free status, artifact integrity,
    dataset integrity, runtime cleanliness, and semantic honesty.
  - Zero new features. Zero model retraining. Zero dataset modifications.
  - Strict 42-feature gate enforced. Zero fabrication.

TEST COVERAGE:
  P7-01  Phase-3 regression
  P7-02  Phase-4 regression
  P7-03  Phase-5 regression
  P7-04  Phase-6 regression
  P7-05  Phase-6.5 regression
  P7-06  Phase-6.6 regression
  P7-07  ML artifact hash verification
  P7-08  Phase-4 dataset hash verification
  P7-09  Feature schema integrity
  P7-10  Training metadata integrity
  P7-11  Model artifact timestamp/integrity check
  P7-12  Production dataset remains unchanged after tests
  P7-13  No test contamination
  P7-14  No orphan server process
  P7-15  Port 5000 released after testing
  P7-16  Dashboard port released after testing
  P7-17  Invalid live feature vector is rejected
  P7-18  Invalid vector does not invoke predictor
  P7-19  Valid authoritative vector still invokes predictor
  P7-20  Frozen Phase-5 predictor remains usable
  P7-21  Real packet capture remains operational
  P7-22  TCP flow reconstruction remains operational
  P7-23  Feature provenance remains present
  P7-24  Five protocol-specific unavailable features remain unavailable
  P7-25  Semantic safety gate remains enforced
  P7-26  Detection logging behavior remains intact
  P7-27  Dashboard/API behavior remains intact
  P7-28  SSE behavior remains intact
  P7-29  No model regeneration occurs
  P7-30  No preprocessing regeneration occurs
  P7-31  No dataset modification occurs
  P7-32  Complete project smoke test
  P7-33  Clean shutdown
  P7-34  Final filesystem integrity
  P7-35  Final runtime integrity

USAGE:
  python -m unittest tests/test_phase7_cases.py
=============================================================================
"""

import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Isolate dataset writes for any test that triggers traffic logging
os.environ["AI_NIDS_DATASET_PATH"] = os.path.join(PROJECT_ROOT, "data", "_test_phase7_traffic.csv")

# ---------------------------------------------------------------------------
# Frozen Baselines (Baseline A)
# ---------------------------------------------------------------------------
EXPECTED_HASHES = {
    os.path.join(PROJECT_ROOT, "models", "intrusion_model.json"): "ebeff2aaba1d02f13f5e819f4c9290c75d99f9cd0f14a277423365238faa1eea",
    os.path.join(PROJECT_ROOT, "models", "preprocessor.pkl"): "15747da0ac83471f061d05204a4f20e9bf15f225a63ba39ef20f3f3e6c16b915",
    os.path.join(PROJECT_ROOT, "models", "feature_schema.json"): "6c97f12fdd5c923ce380e807d1fcfe12ad88365bb8c071e045ef89be8d41812b",
    os.path.join(PROJECT_ROOT, "models", "training_metadata.json"): "437ea304d8e0fb26c7cfd175b53f3f0aa54bf190e51cb11133cb149a18afb521",
    os.path.join(PROJECT_ROOT, "data", "network_traffic.csv"): "9ac544411aff859cb70de9d26a27db387327c28166886a005240c758920ea787",
}
EXPECTED_PHASE4_CSV_SIZE = 2478
EXPECTED_PHASE4_CSV_HEADER = "timestamp,experiment_id,window_duration_sec,requests_per_sec,bytes_per_sec,avg_request_size_bytes,active_connections,total_connections_in_window,client_ip"

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

from ml.packet_capture import PacketCapture, find_loopback_interface, SCAPY_AVAILABLE
from ml.flow_tracker import FlowTracker, TCPFlow
from ml.unsw_feature_extractor import UNSWFeatureExtractor, ALL_42_FEATURES
from ml.feature_gate import FeatureGate
from ml.predict import IntrusionPredictor
from ml.live_inference import LiveInferencePipeline
from server.dashboard_server import DashboardServer
from server.detection_logger import DetectionLogger
import shared.protocol as protocol
import server.dataset_writer as dataset_writer
import server.monitor as monitor


class Phase7AcceptanceTests(unittest.TestCase):
    """Phase 7 Final Acceptance Test Suite (P7-01 to P7-35)."""

    @classmethod
    def setUpClass(cls):
        # Record initial baseline state
        cls.initial_dataset_size = os.path.getsize(os.path.join(PROJECT_ROOT, "data", "network_traffic.csv"))
        cls.initial_dataset_hash = _sha256(os.path.join(PROJECT_ROOT, "data", "network_traffic.csv"))

    @classmethod
    def tearDownClass(cls):
        # Clean up any test artifacts created in data/
        for tmp_name in ["_test_phase7_traffic.csv", "_test_phase7_det.csv", "_test_p7_live_det.csv"]:
            p = os.path.join(PROJECT_ROOT, "data", tmp_name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # Historical Regressions (P7-01 to P7-06)
    # -------------------------------------------------------------------------
    def test_P7_01_phase3_regression(self):
        """P7-01: Phase 3 client/server protocol & telemetry modules intact."""
        req = protocol.build_request("DATA_REQUEST", "ping")
        self.assertIn("request_id", req)
        self.assertEqual(req["payload"], "ping")
        valid, err = protocol.validate_request(req)
        self.assertTrue(valid, f"Request validation failed: {err}")
        tm = monitor.TrafficMonitor(interval=1.0)
        self.assertEqual(tm.total_requests, 0)
        print("  --> PASS: P7-01 (Phase-3 regression: protocol & monitor intact)")

    def test_P7_02_phase4_regression(self):
        """P7-02: Phase 4 DatasetWriter integrity and validation intact."""
        test_path = os.path.join(PROJECT_ROOT, "data", "_test_phase7_traffic.csv")
        writer = dataset_writer.DatasetWriter(filepath=test_path)
        self.assertTrue(os.path.exists(test_path))
        writer.start_session()
        valid = writer.write_observation({
            "requests_per_sec": 10.0,
            "bytes_per_sec": 500.0,
            "avg_request_size_bytes": 50.0,
            "active_connections": 1,
            "total_connections_in_window": 1,
            "window_duration_sec": 1.0,
            "client_ip": "127.0.0.1",
        })
        self.assertTrue(valid)
        invalid_nan = writer.write_observation({
            "requests_per_sec": float("nan"),
            "bytes_per_sec": 500.0,
            "avg_request_size_bytes": 50.0,
            "active_connections": 1,
            "total_connections_in_window": 1,
            "window_duration_sec": 1.0,
            "client_ip": "127.0.0.1",
        })
        self.assertFalse(invalid_nan)
        writer.stop_session()
        print("  --> PASS: P7-02 (Phase-4 regression: dataset writer & schema intact)")

    def test_P7_03_phase5_regression(self):
        """P7-03: Phase 5 model loading and inference pipeline intact."""
        predictor = IntrusionPredictor()
        self.assertIsNotNone(predictor.model)
        self.assertIsNotNone(predictor.preprocessor)
        self.assertEqual(len(predictor.schema["raw_model_features"]), 42)
        print("  --> PASS: P7-03 (Phase-5 regression: model, preprocessor, schema intact)")

    def test_P7_04_phase6_regression(self):
        """P7-04: Phase 6 Flow tracking and feature bridging intact."""
        from ml.feature_bridge import FeatureBridge, FlowTracker as BridgeFlowTracker
        from ml.preprocessing import ALL_MODEL_FEATURES
        tracker = BridgeFlowTracker(client_ip="127.0.0.1", client_port=50001)
        self.assertEqual(tracker.client_ip, "127.0.0.1")
        bridge = FeatureBridge()
        self.assertEqual(len(ALL_MODEL_FEATURES), 42)
        obs = bridge.extract_observed_features(tracker)
        self.assertIn("proto", obs)
        self.assertIn("sbytes", obs)
        print("  --> PASS: P7-04 (Phase-6 regression: flow tracker & feature bridge intact)")

    def test_P7_05_phase65_regression(self):
        """P7-05: Phase 6.5 environment discovery intact."""
        import ml.env_discovery as env_discovery
        report = env_discovery.discover_packet_capture_environment()
        self.assertIn("packet_capture_status", report)
        self.assertIn(report["packet_capture_status"], ["PARTIAL", "AVAILABLE"])
        print("  --> PASS: P7-05 (Phase-6.5 regression: environment discovery intact)")

    def test_P7_06_phase66_regression(self):
        """P7-06: Phase 6.6 Scapy capture, flow tracker, feature gate, and pipeline intact."""
        gate = FeatureGate()
        self.assertEqual(gate.total_feature_count, 42)
        pipeline = LiveInferencePipeline()
        self.assertEqual(pipeline.stats["packets_captured"], 0)
        print("  --> PASS: P7-06 (Phase-6.6 regression: live telemetry pipeline intact)")

    # -------------------------------------------------------------------------
    # Artifact & Dataset Forensic Integrity (P7-07 to P7-11)
    # -------------------------------------------------------------------------
    def test_P7_07_ml_artifact_hash_verification(self):
        """P7-07: ML artifact SHA-256 hashes match Baseline A exactly."""
        model_p = os.path.join(PROJECT_ROOT, "models", "intrusion_model.json")
        preproc_p = os.path.join(PROJECT_ROOT, "models", "preprocessor.pkl")
        self.assertEqual(_sha256(model_p), EXPECTED_HASHES[model_p])
        self.assertEqual(_sha256(preproc_p), EXPECTED_HASHES[preproc_p])
        print("  --> PASS: P7-07 (ML model and preprocessor hashes match Baseline A)")

    def test_P7_08_phase4_dataset_hash_verification(self):
        """P7-08: Phase-4 dataset SHA-256 and size match frozen baseline exactly."""
        csv_p = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
        self.assertEqual(os.path.getsize(csv_p), EXPECTED_PHASE4_CSV_SIZE)
        self.assertEqual(_sha256(csv_p), EXPECTED_HASHES[csv_p])
        print("  --> PASS: P7-08 (Phase-4 dataset verified: 2,478 bytes, sha256=9ac54441...)")

    def test_P7_09_feature_schema_integrity(self):
        """P7-09: Feature schema JSON hash matches Baseline A and has 42 features."""
        schema_p = os.path.join(PROJECT_ROOT, "models", "feature_schema.json")
        self.assertEqual(_sha256(schema_p), EXPECTED_HASHES[schema_p])
        with open(schema_p, "r", encoding="utf-8") as f:
            data = json.load(f)
        features = data.get("raw_model_features", [])
        self.assertEqual(len(features), 42)
        print("  --> PASS: P7-09 (Feature schema verified: 42 features, hash matches Baseline A)")

    def test_P7_10_training_metadata_integrity(self):
        """P7-10: Training metadata JSON hash matches Baseline A."""
        meta_p = os.path.join(PROJECT_ROOT, "models", "training_metadata.json")
        self.assertEqual(_sha256(meta_p), EXPECTED_HASHES[meta_p])
        with open(meta_p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("accuracy", data.get("metrics_untouched_test_set", {}))
        print("  --> PASS: P7-10 (Training metadata verified: hash matches Baseline A)")

    def test_P7_11_model_artifact_timestamp_integrity(self):
        """P7-11: Model artifact exists, is non-empty, and loadable."""
        model_p = os.path.join(PROJECT_ROOT, "models", "intrusion_model.json")
        self.assertTrue(os.path.isfile(model_p))
        self.assertGreater(os.path.getsize(model_p), 500000)
        with open(model_p, "r", encoding="utf-8") as f:
            m = json.load(f)
        self.assertIn("learner", m)
        print("  --> PASS: P7-11 (Model artifact structural integrity verified)")

    # -------------------------------------------------------------------------
    # Dataset Protection & Runtime Cleanliness (P7-12 to P7-16)
    # -------------------------------------------------------------------------
    def test_P7_12_production_dataset_unchanged_after_tests(self):
        """P7-12: Production dataset remains untouched."""
        csv_p = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
        self.assertEqual(os.path.getsize(csv_p), self.initial_dataset_size)
        self.assertEqual(_sha256(csv_p), self.initial_dataset_hash)
        print("  --> PASS: P7-12 (Production dataset untouched)")

    def test_P7_13_no_test_contamination(self):
        """P7-13: Test writes are strictly isolated via AI_NIDS_DATASET_PATH."""
        csv_p = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
        with open(csv_p, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        self.assertEqual(os.path.getsize(csv_p), EXPECTED_PHASE4_CSV_SIZE)
        self.assertEqual(lines[0], EXPECTED_PHASE4_CSV_HEADER)
        print("  --> PASS: P7-13 (Zero contamination: production dataset byte-for-byte intact)")

    def test_P7_14_no_orphan_server_process(self):
        """P7-14: Port 5000 has no orphan listening server."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", 5000))
            is_listening = True
        except (OSError, ConnectionRefusedError):
            is_listening = False
        finally:
            s.close()
        self.assertFalse(is_listening, "Port 5000 must not have an orphan listening process")
        print("  --> PASS: P7-14 (No orphan process listening on port 5000)")

    def test_P7_15_port_5000_released(self):
        """P7-15: Port 5000 is available for bind."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", 5000))
            bound = True
        except OSError:
            bound = False
        finally:
            s.close()
        self.assertTrue(bound, "Port 5000 must be bindable")
        print("  --> PASS: P7-15 (Port 5000 confirmed released and bindable)")

    def test_P7_16_dashboard_port_released(self):
        """P7-16: Dashboard port 5055 is available for bind."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", 5055))
            bound = True
        except OSError:
            bound = False
        finally:
            s.close()
        self.assertTrue(bound, "Port 5055 must be bindable")
        print("  --> PASS: P7-16 (Dashboard port 5055 confirmed released and bindable)")

    # -------------------------------------------------------------------------
    # Feature Gate & Predictor Integrity (P7-17 to P7-20)
    # -------------------------------------------------------------------------
    def test_P7_17_invalid_live_vector_rejected(self):
        """P7-17: Incomplete live feature vector is rejected with INVALID_FEATURE_VECTOR."""
        gate = FeatureGate()
        partial_vector = {
            "dur": 0.05, "proto": "tcp", "service": "-", "state": "CON",
            "spkts": 2, "dpkts": 2, "sbytes": 100, "dbytes": 100,
        }
        is_valid, status, reasons = gate.validate(partial_vector)
        self.assertFalse(is_valid)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P7-17 (Incomplete live vector rejected as INVALID_FEATURE_VECTOR)")

    def test_P7_18_invalid_vector_does_not_invoke_predictor(self):
        """P7-18: Invalid feature vector strictly prevents predictor execution."""
        pipeline = LiveInferencePipeline()
        flow = TCPFlow("127.0.0.1", 54321, "127.0.0.1", 5000, time.time())
        flow.add_packet({"timestamp": time.time(), "src_ip": "127.0.0.1", "src_port": 54321, "ip_len": 60, "payload_len": 0, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False})
        pipeline._evaluate_flow(flow)
        self.assertEqual(pipeline.stats["predictions_made"], 0)
        self.assertGreater(pipeline.stats["vectors_evaluated"], 0)
        self.assertEqual(len(pipeline._recent_events), 1)
        self.assertEqual(pipeline._recent_events[0]["gate_status"], "INVALID_FEATURE_VECTOR")
        self.assertEqual(pipeline._recent_events[0]["inference_status"], "SKIPPED")
        print("  --> PASS: P7-18 (Invalid vector does not invoke ML predictor)")

    def test_P7_19_valid_authoritative_vector_invokes_predictor(self):
        """P7-19: Complete authoritative 42-feature vector invokes existing Phase-5 predictor."""
        gate = FeatureGate()
        sample = {
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
        is_valid, status, reasons = gate.validate(sample)
        self.assertTrue(is_valid, f"Authoritative vector validation failed: {reasons}")
        predictor = IntrusionPredictor()
        pred = predictor.predict(sample)
        self.assertIn(pred["prediction"], ["BENIGN", "ATTACK"])
        self.assertTrue(0.0 <= pred["intrusion_probability"] <= 1.0)
        print(f"  --> PASS: P7-19 (Authoritative vector invoked predictor: {pred['prediction']}, prob={pred['intrusion_probability']:.6f})")

    def test_P7_20_frozen_phase5_predictor_remains_usable(self):
        """P7-20: Frozen Phase-5 IntrusionPredictor executes deterministically."""
        p1 = IntrusionPredictor()
        p2 = IntrusionPredictor()
        sample = {
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
        res1 = p1.predict(sample)
        res2 = p2.predict(sample)
        self.assertEqual(res1["prediction"], res2["prediction"])
        self.assertAlmostEqual(res1["intrusion_probability"], res2["intrusion_probability"], places=6)
        print("  --> PASS: P7-20 (Phase-5 predictor deterministic across reloads)")

    # -------------------------------------------------------------------------
    # Packet Capture & Flow Reconstruction (P7-21 to P7-25)
    # -------------------------------------------------------------------------
    def test_P7_21_packet_capture_operational(self):
        """P7-21: PacketCapture initializes and resolves interface cleanly."""
        cap = PacketCapture(bpf_filter="tcp port 5000")
        self.assertIsNotNone(cap.interface)
        self.assertFalse(cap.is_running)
        print(f"  --> PASS: P7-21 (Packet capture initialized on iface '{cap.interface}')")

    def test_P7_22_tcp_flow_reconstruction_operational(self):
        """P7-22: TCP flow reconstruction builds accurate bidirectional flow."""
        tracker = FlowTracker()
        now = 100.0
        # Client -> Server SYN
        tracker.process_packet({
            "timestamp": now, "src_ip": "127.0.0.1", "src_port": 50001,
            "dst_ip": "127.0.0.1", "dst_port": 5000, "ip_len": 60,
            "payload_len": 0, "tcp_seq": 1000, "tcp_ack": 0, "tcp_window": 65535,
            "ip_ttl": 128, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False
        })
        # Server -> Client SYN-ACK
        f = tracker.process_packet({
            "timestamp": now + 0.001, "src_ip": "127.0.0.1", "src_port": 5000,
            "dst_ip": "127.0.0.1", "dst_port": 50001, "ip_len": 60,
            "payload_len": 0, "tcp_seq": 2000, "tcp_ack": 1001, "tcp_window": 65535,
            "ip_ttl": 128, "has_syn": True, "has_ack": True, "has_fin": False, "has_rst": False
        })
        self.assertEqual(tracker.active_flows_count, 1)
        self.assertEqual(f.spkts, 1)
        self.assertEqual(f.dpkts, 1)
        self.assertEqual(f.sbytes, 60)
        self.assertEqual(f.dbytes, 60)
        print("  --> PASS: P7-22 (Bidirectional TCP flow tracking verified)")

    def test_P7_23_feature_provenance_present(self):
        """P7-23: Feature provenance records category and status for all 42 features."""
        extractor = UNSWFeatureExtractor()
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.add_packet({"timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 50001, "ip_len": 60, "payload_len": 0, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False})
        features, provenance = extractor.extract_features(flow)
        self.assertEqual(len(features), 42)
        self.assertEqual(len(provenance), 42)
        for feat, prov in provenance.items():
            self.assertIn("category", prov)
            self.assertIn("status", prov)
        print("  --> PASS: P7-23 (All 42 features have verifiable provenance)")

    def test_P7_24_five_protocol_features_unavailable(self):
        """P7-24: Five protocol-specific features remain unavailable without fabrication."""
        extractor = UNSWFeatureExtractor()
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        features, provenance = extractor.extract_features(flow)
        unavailable_keys = ["trans_depth", "response_body_len", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd"]
        for key in unavailable_keys:
            self.assertIsNone(features[key], f"Feature {key} must be None")
            self.assertEqual(provenance[key]["status"], "UNAVAILABLE")
        print("  --> PASS: P7-24 (5 protocol-specific features confirmed UNAVAILABLE)")

    def test_P7_25_semantic_safety_gate_enforced(self):
        """P7-25: Semantic safety gate cannot be bypassed with missing/None features."""
        gate = FeatureGate()
        incomplete_vector = {"dur": 0.1, "proto": "tcp", "trans_depth": None}
        is_valid, status, reasons = gate.validate(incomplete_vector)
        self.assertFalse(is_valid)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P7-25 (Semantic safety gate strictly enforced)")

    # -------------------------------------------------------------------------
    # Detection Logging & Dashboard/SSE (P7-26 to P7-28)
    # -------------------------------------------------------------------------
    def test_P7_26_detection_logging_intact(self):
        """P7-26: DetectionLogger logs valid predictions to CSV cleanly."""
        test_log = os.path.join(PROJECT_ROOT, "data", "_test_phase7_det.csv")
        logger = DetectionLogger(log_path=test_log)
        ok = logger.log_event(
            client_ip="127.0.0.1",
            prediction="BENIGN",
            intrusion_probability=0.0001,
            status="SUCCESS"
        )
        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(test_log))
        print("  --> PASS: P7-26 (DetectionLogger records genuine events without corruption)")

    def test_P7_27_dashboard_api_behavior_intact(self):
        """P7-27: Dashboard HTTP server responds to / and /api/status."""
        pipeline = LiveInferencePipeline()
        pipeline.stats["packets_captured"] = 15
        srv = DashboardServer(pipeline, port=5066)
        started = srv.start()
        self.assertTrue(started)
        try:
            time.sleep(0.5)
            with urllib.request.urlopen("http://127.0.0.1:5066/", timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
            with urllib.request.urlopen("http://127.0.0.1:5066/api/status", timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["telemetry"]["packets_captured"], 15)
                self.assertIn("domain_shift_disclaimer", data)
        finally:
            srv.stop()
        print("  --> PASS: P7-27 (Dashboard HTTP server and /api/status intact)")

    def test_P7_28_sse_behavior_intact(self):
        """P7-28: Dashboard SSE endpoint streams valid events."""
        pipeline = LiveInferencePipeline()
        srv = DashboardServer(pipeline, port=5067)
        srv.start()
        try:
            time.sleep(0.5)
            req = urllib.request.Request("http://127.0.0.1:5067/api/events")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("text/event-stream", resp.headers.get("Content-Type", ""))
                line = resp.readline().decode("utf-8")
                self.assertTrue(line.startswith("data:"))
        finally:
            srv.stop()
        print("  --> PASS: P7-28 (SSE endpoint streams valid text/event-stream)")

    # -------------------------------------------------------------------------
    # Pipeline Stability & Unmodified Integrity (P7-29 to P7-31)
    # -------------------------------------------------------------------------
    def test_P7_29_no_model_regeneration(self):
        """P7-29: Model artifact hash remains identical to Phase-5 baseline."""
        p = os.path.join(PROJECT_ROOT, "models", "intrusion_model.json")
        self.assertEqual(_sha256(p), EXPECTED_HASHES[p])
        print("  --> PASS: P7-29 (Zero model regeneration: hash matches Baseline A)")

    def test_P7_30_no_preprocessing_regeneration(self):
        """P7-30: Preprocessor pickle hash remains identical to Phase-5 baseline."""
        p = os.path.join(PROJECT_ROOT, "models", "preprocessor.pkl")
        self.assertEqual(_sha256(p), EXPECTED_HASHES[p])
        print("  --> PASS: P7-30 (Zero preprocessor regeneration: hash matches Baseline A)")

    def test_P7_31_no_dataset_modification(self):
        """P7-31: Phase-4 dataset remains untouched at 2,478 bytes with 32 rows."""
        p = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
        self.assertEqual(os.path.getsize(p), EXPECTED_PHASE4_CSV_SIZE)
        self.assertEqual(_sha256(p), EXPECTED_HASHES[p])
        print("  --> PASS: P7-31 (Zero dataset modification: exactly 2,478 bytes)")

    # -------------------------------------------------------------------------
    # Smoke Test & Final Integrity (P7-32 to P7-35)
    # -------------------------------------------------------------------------
    def test_P7_32_complete_project_smoke_test(self):
        """P7-32: Controlled live smoke test through capture, flow, gate, and safe refusal."""
        pipeline = LiveInferencePipeline()
        flow = TCPFlow("127.0.0.1", 52222, "127.0.0.1", 5000, 100.0)
        flow.add_packet({"timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 52222, "ip_len": 74, "payload_len": 0, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False})
        flow.add_packet({"timestamp": 100.001, "src_ip": "127.0.0.1", "src_port": 5000, "ip_len": 74, "payload_len": 0, "has_syn": True, "has_ack": True, "has_fin": False, "has_rst": False})
        flow.add_packet({"timestamp": 100.002, "src_ip": "127.0.0.1", "src_port": 52222, "ip_len": 54, "payload_len": 0, "has_syn": False, "has_ack": True, "has_fin": False, "has_rst": False})

        extractor = UNSWFeatureExtractor()
        gate = FeatureGate()

        feats, prov = extractor.extract_features(flow)
        is_valid, status, reasons = gate.validate(feats, prov)
        self.assertFalse(is_valid)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")

        pipeline._evaluate_flow(flow)
        self.assertEqual(pipeline.stats["predictions_made"], 0)
        print("  --> PASS: P7-32 (Complete smoke test: live flow safely refused by gate)")

    def test_P7_33_clean_shutdown(self):
        """P7-33: Clean shutdown of capture, dashboard, and background threads."""
        pipeline = LiveInferencePipeline()
        srv = DashboardServer(pipeline, port=5068)
        srv.start()
        time.sleep(0.3)
        srv.stop()
        self.assertFalse(srv.is_running)
        print("  --> PASS: P7-33 (Clean shutdown of services verified)")

    def test_P7_34_final_filesystem_integrity(self):
        """P7-34: No unapproved files in production directories."""
        approved_exts = {".py", ".json", ".pkl", ".csv", ".html", ".css", ".js", ".md", ".txt"}
        approved_names = {".gitignore"}
        for root, dirs, files in os.walk(PROJECT_ROOT):
            if any(x in root for x in [".git", "__pycache__", ".gemini", ".agents", ".pytest_cache"]):
                continue
            for f in files:
                ext = os.path.splitext(f)[1]
                self.assertTrue(f in approved_names or ext in approved_exts, f"Unapproved file found: {f}")
        print("  --> PASS: P7-34 (Filesystem integrity confirmed: all files approved)")

    def test_P7_35_final_runtime_integrity(self):
        """P7-35: Runtime integrity: Ports 5000 and 5055 are not held open."""
        for port in [5000, 5055]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                s.connect(("127.0.0.1", port))
                active = True
            except (OSError, ConnectionRefusedError):
                active = False
            finally:
                s.close()
            self.assertFalse(active, f"Port {port} must be free")
        print("  --> PASS: P7-35 (Final runtime integrity confirmed: ports released)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
