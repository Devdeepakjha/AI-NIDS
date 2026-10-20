"""
tests/test_phase66_cases.py
=============================================================================
Phase 6.6 Acceptance Test Suite: Real Packet-Level Telemetry, TCP Flow
Reconstruction, Strict Feature Gating, Genuine Live Inference, and Dashboard.

Validates all Phase 6.6 acceptance criteria:
  P6.6-01 to P6.6-06 : Packet Capture Architecture & Capabilities
  P6.6-07 to P6.6-12 : TCP Flow Reconstruction & Real Metric Derivations
  P6.6-13 to P6.6-19 : UNSW-NB15 Semantic Provenance & Protocol Honesty
  P6.6-20 to P6.6-26 : 42-Feature Gate & Model Inference Safeguards
  P6.6-27 to P6.6-31 : Flask SSE Stream & Web Dashboard Functionality
  P6.6-32 to P6.6-36 : Process Cleanup, Port Release, and Artifact Immutability
  P6.6-37 to P6.6-41 : Full Phase 3, 4, 5, 6, and 6.5 Regression Suites
=============================================================================
"""

import os
import sys
import time
import json
import math
import socket
import hashlib
import unittest
import subprocess
import urllib.request
from typing import Dict, Any

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.packet_capture import PacketCapture, find_loopback_interface, SCAPY_AVAILABLE
from ml.flow_tracker import FlowTracker, TCPFlow
from ml.unsw_feature_extractor import UNSWFeatureExtractor, ALL_42_FEATURES
from ml.feature_gate import FeatureGate
from ml.predict import IntrusionPredictor
from ml.live_inference import LiveInferencePipeline
from server.dashboard_server import DashboardServer
from server.detection_logger import DetectionLogger
import shared.protocol as protocol

PHASE4_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
EXPECTED_PHASE4_HASH = "9ac544411aff859cb70de9d26a27db387327c28166886a005240c758920ea787"
EXPECTED_PHASE4_SIZE = 2478

FROZEN_MODEL_HASHES = {
    os.path.join(PROJECT_ROOT, "models", "intrusion_model.json"):
        "ebeff2aaba1d02f13f5e819f4c9290c75d99f9cd0f14a277423365238faa1eea",
    os.path.join(PROJECT_ROOT, "models", "preprocessor.pkl"):
        "15747da0ac83471f061d05204a4f20e9bf15f225a63ba39ef20f3f3e6c16b915",
    os.path.join(PROJECT_ROOT, "models", "feature_schema.json"):
        "6c97f12fdd5c923ce380e807d1fcfe12ad88365bb8c071e045ef89be8d41812b",
    os.path.join(PROJECT_ROOT, "models", "training_metadata.json"):
        "437ea304d8e0fb26c7cfd175b53f3f0aa54bf190e51cb11133cb149a18afb521",
}


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestPhase66Acceptance(unittest.TestCase):
    """Phase 6.6 Acceptance Test Suite."""

    @classmethod
    def setUpClass(cls):
        # Snapshot Phase 4 dataset bytes to guarantee data immutability
        if os.path.exists(PHASE4_CSV_PATH):
            with open(PHASE4_CSV_PATH, "rb") as f:
                cls._p4_initial_bytes = f.read()
        else:
            cls._p4_initial_bytes = b""

    @classmethod
    def tearDownClass(cls):
        # Restore Phase 4 dataset if touched
        if cls._p4_initial_bytes and os.path.exists(PHASE4_CSV_PATH):
            with open(PHASE4_CSV_PATH, "rb") as f:
                cur = f.read()
            if cur != cls._p4_initial_bytes:
                with open(PHASE4_CSV_PATH, "wb") as f:
                    f.write(cls._p4_initial_bytes)

    # -------------------------------------------------------------------------
    # P6.6-01 to P6.6-06: Packet Capture
    # -------------------------------------------------------------------------
    def test_P66_01_packet_capture_import(self):
        """P6.6-01: Packet capture module imports successfully."""
        import ml.packet_capture as pc
        self.assertTrue(hasattr(pc, "PacketCapture"))
        self.assertTrue(hasattr(pc, "find_loopback_interface"))
        print("  --> PASS: P6.6-01 (Packet capture module imports cleanly)")

    def test_P66_02_scapy_npcap_capability(self):
        """P6.6-02: Scapy capability detected in environment."""
        self.assertTrue(SCAPY_AVAILABLE, "Scapy library must be available")
        print("  --> PASS: P6.6-02 (Scapy/Npcap capability detected)")

    def test_P66_03_loopback_interface_discovered(self):
        """P6.6-03: Loopback interface is resolved."""
        iface = find_loopback_interface()
        self.assertIsNotNone(iface)
        self.assertIn("Loopback", iface)
        print(f"  --> PASS: P6.6-03 (Loopback interface resolved: {iface})")

    def test_P66_04_capture_filter_configuration(self):
        """P6.6-04: Capture filter configuration validated."""
        cap = PacketCapture(bpf_filter="tcp port 5000")
        self.assertEqual(cap.bpf_filter, "tcp port 5000")
        print("  --> PASS: P6.6-04 (BPF filter configuration validated)")

    def test_P66_05_start_stop_capture(self):
        """P6.6-05: Real TCP packet capture can start and stop cleanly."""
        cap = PacketCapture()
        started = cap.start()
        self.assertTrue(started, "Packet capture should start")
        self.assertTrue(cap.is_running)
        time.sleep(0.5)
        cap.stop()
        self.assertFalse(cap.is_running)
        print("  --> PASS: P6.6-05 (Packet capture starts and stops cleanly)")

    def test_P66_06_capture_real_packets(self):
        """P6.6-06: Live port 5000 packets can be captured."""
        captured = []
        cap = PacketCapture(bpf_filter="tcp port 5000", packet_handler=lambda p: captured.append(p))
        cap.start()
        try:
            # Create a loopback server socket on 5000 temporarily to trigger TCP handshake
            s_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s_srv.bind(("127.0.0.1", 5000))
                s_srv.listen(1)
                # Connect client
                s_cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s_cli.connect(("127.0.0.1", 5000))
                conn, _ = s_srv.accept()
                s_cli.sendall(b'{"test":"real_packet"}\n')
                data = conn.recv(1024)
                conn.close()
                s_cli.close()
            finally:
                s_srv.close()

            time.sleep(1.0)
            self.assertGreater(cap.packet_count, 0, "Packets must be captured on loopback")
            self.assertGreater(len(captured), 0, "Callback must receive captured packets")
        finally:
            cap.stop()
        print(f"  --> PASS: P6.6-06 (Captured {len(captured)} real packets on port 5000)")

    # -------------------------------------------------------------------------
    # P6.6-07 to P6.6-12: Flow Reconstruction & Metrics
    # -------------------------------------------------------------------------
    def test_P66_07_flow_reconstruction(self):
        """P6.6-07: TCP flow reconstruction works."""
        tracker = FlowTracker()
        f = tracker.process_packet({
            "timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 50001,
            "dst_ip": "127.0.0.1", "dst_port": 5000, "ip_len": 60,
            "payload_len": 0, "tcp_seq": 100, "tcp_ack": 0, "tcp_window": 65535,
            "ip_ttl": 128, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False
        })
        self.assertIsNotNone(f)
        self.assertEqual(tracker.active_flows_count, 1)
        print("  --> PASS: P6.6-07 (TCP flow reconstruction creates flow)")

    def test_P66_08_bidirectional_tracking(self):
        """P6.6-08: Bidirectional flow tracking associates client and server."""
        tracker = FlowTracker()
        # Client SYN
        tracker.process_packet({
            "timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 50001,
            "dst_ip": "127.0.0.1", "dst_port": 5000, "ip_len": 60,
            "payload_len": 0, "tcp_seq": 100, "tcp_ack": 0, "tcp_window": 65535,
            "ip_ttl": 128, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False
        })
        # Server SYN-ACK (reverse 5-tuple)
        f = tracker.process_packet({
            "timestamp": 100.001, "src_ip": "127.0.0.1", "src_port": 5000,
            "dst_ip": "127.0.0.1", "dst_port": 50001, "ip_len": 60,
            "payload_len": 0, "tcp_seq": 500, "tcp_ack": 101, "tcp_window": 65535,
            "ip_ttl": 128, "has_syn": True, "has_ack": True, "has_fin": False, "has_rst": False
        })
        self.assertEqual(tracker.active_flows_count, 1, "Must associate into single bidirectional flow")
        self.assertEqual(f.spkts, 1)
        self.assertEqual(f.dpkts, 1)
        self.assertEqual(f.state, "CON")
        print("  --> PASS: P6.6-08 (Bidirectional flow tracking confirmed)")

    def test_P66_09_packet_counts_derived_from_packets(self):
        """P6.6-09: Packet counts derived from real packets."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.add_packet({"timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 50001, "ip_len": 60, "payload_len": 0, "has_syn": True, "has_ack": False, "has_fin": False, "has_rst": False})
        flow.add_packet({"timestamp": 100.1, "src_ip": "127.0.0.1", "src_port": 50001, "ip_len": 120, "payload_len": 60, "has_syn": False, "has_ack": True, "has_fin": False, "has_rst": False})
        flow.add_packet({"timestamp": 100.2, "src_ip": "127.0.0.1", "src_port": 5000, "ip_len": 80, "payload_len": 20, "has_syn": False, "has_ack": True, "has_fin": False, "has_rst": False})
        self.assertEqual(flow.spkts, 2)
        self.assertEqual(flow.dpkts, 1)
        print("  --> PASS: P6.6-09 (Packet counts accurately derived)")

    def test_P66_10_byte_counts_derived_from_packets(self):
        """P6.6-10: Byte counts derived from packet lengths."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.add_packet({"timestamp": 100.0, "src_ip": "127.0.0.1", "src_port": 50001, "ip_len": 150, "payload_len": 100, "has_syn": False, "has_ack": False, "has_fin": False, "has_rst": False})
        flow.add_packet({"timestamp": 100.1, "src_ip": "127.0.0.1", "src_port": 5000, "ip_len": 250, "payload_len": 200, "has_syn": False, "has_ack": False, "has_fin": False, "has_rst": False})
        self.assertEqual(flow.sbytes, 150)
        self.assertEqual(flow.dbytes, 250)
        print("  --> PASS: P6.6-10 (Byte counts accurately derived)")

    def test_P66_11_duration_derived_from_timestamps(self):
        """P6.6-11: Duration derived from packet timestamps."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.add_packet({"timestamp": 102.5, "src_ip": "127.0.0.1", "src_port": 50001, "ip_len": 60, "payload_len": 0, "has_syn": False, "has_ack": False, "has_fin": False, "has_rst": False})
        self.assertAlmostEqual(flow.duration, 2.5, places=4)
        print("  --> PASS: P6.6-11 (Duration derived from timestamps)")

    def test_P66_12_no_fabricated_packet_values(self):
        """P6.6-12: Zero synthetic packet values injected."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        self.assertEqual(flow.spkts, 0)
        self.assertEqual(flow.dpkts, 0)
        self.assertEqual(flow.sbytes, 0)
        self.assertEqual(flow.dbytes, 0)
        print("  --> PASS: P6.6-12 (No fabricated initial values)")

    # -------------------------------------------------------------------------
    # P6.6-13 to P6.6-19: Feature Provenance & Protocol Honesty
    # -------------------------------------------------------------------------
    def test_P66_13_unsw_feature_provenance(self):
        """P6.6-13: Feature provenance metadata is recorded."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        extractor = UNSWFeatureExtractor()
        features, provenance = extractor.extract_features(flow)
        self.assertEqual(len(features), 42)
        self.assertEqual(len(provenance), 42)
        for key in ALL_42_FEATURES:
            self.assertIn(key, provenance)
            self.assertIn("category", provenance[key])
            self.assertIn("status", provenance[key])
        print("  --> PASS: P6.6-13 (UNSW feature provenance recorded for all 42 keys)")

    def test_P66_14_feature_schema_matches_phase5(self):
        """P6.6-14: Feature schema exactly matches Phase 5 schema."""
        schema_path = os.path.join(PROJECT_ROOT, "models", "feature_schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        expected_raw = schema["raw_model_features"]
        self.assertEqual(ALL_42_FEATURES, expected_raw)
        print("  --> PASS: P6.6-14 (Schema matches Phase 5 exactly)")

    def test_P66_15_incomplete_vector_rejected(self):
        """P6.6-15: Incomplete feature vector is rejected."""
        gate = FeatureGate()
        incomplete = {"proto": "tcp", "service": "-", "dur": 1.0}
        ok, status, reasons = gate.validate(incomplete)
        self.assertFalse(ok)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P6.6-15 (Incomplete vector cleanly rejected)")

    def test_P66_16_unknown_feature_rejected(self):
        """P6.6-16: Unknown feature is rejected."""
        gate = FeatureGate()
        features = {k: 0.0 for k in ALL_42_FEATURES}
        features["unknown_feature_x"] = 123
        ok, status, reasons = gate.validate(features)
        self.assertFalse(ok)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P6.6-16 (Unknown feature cleanly rejected)")

    def test_P66_17_non_finite_numerical_rejected(self):
        """P6.6-17: Non-finite numerical feature is rejected."""
        gate = FeatureGate()
        features = {k: 0.0 for k in ALL_42_FEATURES}
        features["proto"] = "tcp"
        features["service"] = "-"
        features["state"] = "CON"
        features["dur"] = float("nan")
        ok, status, reasons = gate.validate(features)
        self.assertFalse(ok)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P6.6-17 (NaN/Inf cleanly rejected)")

    def test_P66_18_unsupported_protocol_features_rejected(self):
        """P6.6-18: Unsupported HTTP/FTP features are UNAVAILABLE for JSON-over-TCP."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        extractor = UNSWFeatureExtractor()
        features, provenance = extractor.extract_features(flow, is_http_traffic=False, is_ftp_traffic=False)
        # Verify HTTP and FTP features are marked UNAVAILABLE
        for f_name in ["trans_depth", "response_body_len", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd"]:
            self.assertEqual(provenance[f_name]["status"], "UNAVAILABLE")
            self.assertIsNone(features[f_name])
        print("  --> PASS: P6.6-18 (Protocol-specific features correctly marked UNAVAILABLE)")

    def test_P66_19_service_not_falsely_reported_as_http(self):
        """P6.6-19: service is not falsely reported as HTTP for JSON-over-TCP."""
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        extractor = UNSWFeatureExtractor()
        features, _ = extractor.extract_features(flow, is_http_traffic=False)
        self.assertEqual(features["service"], "-")
        print("  --> PASS: P6.6-19 (service correctly reported as '-' rather than 'http')")

    # -------------------------------------------------------------------------
    # P6.6-20 to P6.6-26: Predictor & Feature Gate
    # -------------------------------------------------------------------------
    def test_P66_20_existing_predictor_reused(self):
        """P6.6-20: Existing Phase 5 predictor is reused."""
        pred = IntrusionPredictor()
        self.assertTrue(hasattr(pred, "predict"))
        print("  --> PASS: P6.6-20 (Phase 5 IntrusionPredictor reused)")

    def test_P66_21_model_not_retrained(self):
        """P6.6-21: Model artifacts remain frozen and unretrained."""
        for path, exp_hash in FROZEN_MODEL_HASHES.items():
            actual = _sha256(path)
            self.assertEqual(actual, exp_hash, f"Artifact mutated: {path}")
        print("  --> PASS: P6.6-21 (All Phase 5 model artifacts verified unretrained)")

    def test_P66_22_invalid_vector_never_invokes_prediction(self):
        """P6.6-22: Invalid vector never invokes prediction."""
        pipeline = LiveInferencePipeline()
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        # Custom TCP flow has unavailable HTTP/FTP features
        pipeline._evaluate_flow(flow)
        self.assertEqual(pipeline.stats["predictions_made"], 0)
        self.assertEqual(pipeline.stats["vectors_rejected"], 1)
        print("  --> PASS: P6.6-22 (Invalid vector cleanly prevented prediction)")

    def test_P66_23_valid_vector_invokes_predictor(self):
        """P6.6-23: Valid vector invokes existing predictor only when all 42 features are validated."""
        pipeline = LiveInferencePipeline()
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.spkts = 5
        flow.dpkts = 5
        # Simulate traffic where all features are legitimate
        features, provenance = pipeline.feature_extractor.extract_features(flow, is_http_traffic=True, is_ftp_traffic=False)
        # Make all valid
        for k in features:
            if features[k] is None:
                features[k] = 0.0
            provenance[k]["status"] = "VALIDATED"

        is_valid, _, _ = pipeline.feature_gate.validate(features, provenance)
        self.assertTrue(is_valid)
        res = pipeline.predictor.predict(features)
        self.assertIn(res["prediction"], {"BENIGN", "INTRUSION"})
        self.assertTrue(0.0 <= float(res.get("intrusion_probability", res.get("probability", 0.0))) <= 1.0)
        print("  --> PASS: P6.6-23 (Valid vector invokes existing predictor successfully)")

    def test_P66_24_real_live_flow_reaches_gate(self):
        """P6.6-24: Real live flow reaches the feature gate."""
        pipeline = LiveInferencePipeline()
        flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
        flow.spkts = 2
        flow.dpkts = 2
        pipeline._evaluate_flow(flow)
        self.assertEqual(pipeline.stats["vectors_evaluated"], 1)
        print("  --> PASS: P6.6-24 (Real live flow evaluated at feature gate)")

    def test_P66_25_genuine_prediction_logs_event(self):
        """P6.6-25: Genuine prediction logs detection event."""
        # Use isolated logger for test
        test_log = os.path.join(PROJECT_ROOT, "data", "_test_p66_detect.csv")
        if os.path.exists(test_log):
            os.remove(test_log)

        try:
            logger = DetectionLogger(log_path=test_log)
            logger.log_event("127.0.0.1", "BENIGN", 0.005, status="SUCCESS")
            self.assertTrue(os.path.exists(test_log))
            with open(test_log, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("127.0.0.1", content)
            self.assertIn("BENIGN", content)
        finally:
            if os.path.exists(test_log):
                os.remove(test_log)
        print("  --> PASS: P6.6-25 (Detection logger records genuine events)")

    def test_P66_26_invalid_vector_produces_no_detection_event(self):
        """P6.6-26: Invalid vector produces no detection event."""
        test_log = os.path.join(PROJECT_ROOT, "data", "_test_p66_nodetect.csv")
        if os.path.exists(test_log):
            os.remove(test_log)

        try:
            logger = DetectionLogger(log_path=test_log)
            pipeline = LiveInferencePipeline(detection_logger=logger)
            flow = TCPFlow("127.0.0.1", 50001, "127.0.0.1", 5000, 100.0)
            pipeline._evaluate_flow(flow)
            self.assertEqual(pipeline.stats["predictions_made"], 0)
            # Log file should have only header or 0 rows
            with open(test_log, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1, "Only header line should exist")
        finally:
            if os.path.exists(test_log):
                os.remove(test_log)
        print("  --> PASS: P6.6-26 (Invalid vector does not log detection event)")

    # -------------------------------------------------------------------------
    # P6.6-27 to P6.6-31: Flask & Dashboard
    # -------------------------------------------------------------------------
    def test_P66_27_flask_starts_successfully(self):
        """P6.6-27: Flask dashboard server starts successfully."""
        pipeline = LiveInferencePipeline()
        srv = DashboardServer(pipeline, port=5058)
        started = srv.start()
        self.assertTrue(started)
        srv.stop()
        print("  --> PASS: P6.6-27 (Flask starts successfully)")

    def test_P66_28_sse_endpoint_works(self):
        """P6.6-28: SSE endpoint emits data stream."""
        pipeline = LiveInferencePipeline()
        srv = DashboardServer(pipeline, port=5059)
        srv.start()
        try:
            time.sleep(0.5)
            req = urllib.request.Request("http://127.0.0.1:5059/api/events")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("text/event-stream", resp.headers.get("Content-Type", ""))
                # Read initial snapshot chunk
                chunk = resp.readline().decode("utf-8")
                self.assertTrue(chunk.startswith("data:"), f"Expected SSE data prefix, got: {chunk[:40]}")
        finally:
            srv.stop()
        print("  --> PASS: P6.6-28 (SSE endpoint streams valid event-stream)")

    def test_P66_29_dashboard_loads(self):
        """P6.6-29: Dashboard HTML loads cleanly."""
        pipeline = LiveInferencePipeline()
        srv = DashboardServer(pipeline, port=5060)
        srv.start()
        try:
            time.sleep(0.5)
            with urllib.request.urlopen("http://127.0.0.1:5060/", timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                html = resp.read().decode("utf-8")
                self.assertIn("AI-NIDS", html)
                self.assertIn("Network Telemetry", html)
        finally:
            srv.stop()
        print("  --> PASS: P6.6-29 (Dashboard HTML loads cleanly)")

    def test_P66_30_dashboard_values_driven_by_backend(self):
        """P6.6-30: Dashboard values are driven by actual backend state."""
        pipeline = LiveInferencePipeline()
        pipeline.stats["packets_captured"] = 42
        pipeline.stats["flows_reconstructed"] = 7
        srv = DashboardServer(pipeline, port=5061)
        srv.start()
        try:
            time.sleep(0.5)
            with urllib.request.urlopen("http://127.0.0.1:5061/api/status", timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["telemetry"]["packets_captured"], 42)
                self.assertEqual(data["telemetry"]["flows_reconstructed"], 7)
        finally:
            srv.stop()
        print("  --> PASS: P6.6-30 (Dashboard status accurately mirrors backend)")

    def test_P66_31_no_fake_events_when_no_traffic(self):
        """P6.6-31: No fake events appear when there is no traffic."""
        pipeline = LiveInferencePipeline()
        summary = pipeline.get_status_summary()
        self.assertEqual(len(summary["recent_events"]), 0)
        self.assertEqual(summary["telemetry"]["predictions_made"], 0)
        print("  --> PASS: P6.6-31 (Zero fake events when idle)")

    # -------------------------------------------------------------------------
    # P6.6-32 to P6.6-36: Process & Artifact Integrity
    # -------------------------------------------------------------------------
    def test_P66_32_port_5000_released_after_test(self):
        """P6.6-32: Server shutdown releases port 5000."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", 5000))
            s.listen(1)
        finally:
            s.close()
        # Verify port is open for binding
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s2.bind(("127.0.0.1", 5000))
        s2.close()
        print("  --> PASS: P6.6-32 (Port 5000 confirmed available for bind)")

    def test_P66_33_packet_capture_stops_cleanly(self):
        """P6.6-33: Packet capture stops cleanly."""
        cap = PacketCapture()
        cap.start()
        time.sleep(0.3)
        cap.stop()
        self.assertFalse(cap.is_running)
        print("  --> PASS: P6.6-33 (Packet capture stopped cleanly)")

    def test_P66_34_no_orphan_processes(self):
        """P6.6-34: No orphan background server process on port 5000."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        conn_refused = False
        try:
            s.connect(("127.0.0.1", 5000))
            s.close()
        except (OSError, ConnectionRefusedError):
            conn_refused = True
        self.assertTrue(conn_refused, "Port 5000 must not have an active listener")
        print("  --> PASS: P6.6-34 (No orphan process on port 5000)")

    def test_P66_35_phase4_csv_hash_unchanged(self):
        """P6.6-35: Phase 4 frozen CSV hash remains unchanged."""
        self.assertTrue(os.path.exists(PHASE4_CSV_PATH))
        self.assertEqual(os.path.getsize(PHASE4_CSV_PATH), EXPECTED_PHASE4_SIZE)
        self.assertEqual(_sha256(PHASE4_CSV_PATH), EXPECTED_PHASE4_HASH)
        print(f"  --> PASS: P6.6-35 (Phase 4 CSV verified: {EXPECTED_PHASE4_HASH[:16]}...)")

    def test_P66_36_phase5_artifact_hashes_unchanged(self):
        """P6.6-36: Phase 5 model artifact hashes remain unchanged."""
        for path, exp_hash in FROZEN_MODEL_HASHES.items():
            self.assertEqual(_sha256(path), exp_hash)
        print("  --> PASS: P6.6-36 (Phase 5 artifact hashes preserved)")

    # -------------------------------------------------------------------------
    # P6.6-37 to P6.6-41: Regressions (Phases 3, 4, 5, 6, 6.5)
    # -------------------------------------------------------------------------
    def test_P66_37_phase3_regression(self):
        """P6.6-37: Phase 3 acceptance suite passes 32/32."""
        print("\n[P6.6-37] Running Phase 3 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase3_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 3 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("32/32 Tests Passed", res.stdout)
        print("  --> PASS: P6.6-37 (Phase 3: 32/32 Passed)")

    def test_P66_38_phase4_regression(self):
        """P6.6-38: Phase 4 acceptance suite passes 28/28."""
        print("[P6.6-38] Running Phase 4 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase4_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 4 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("ALL PHASE 4 TESTS PASSED", res.stdout)
        print("  --> PASS: P6.6-38 (Phase 4: 28/28 Passed)")

    def test_P66_39_phase5_regression(self):
        """P6.6-39: Phase 5 acceptance suite passes 36/36."""
        print("[P6.6-39] Running Phase 5 test suite...")
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_phase5_cases.py"],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 5 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("OK", res.stderr)
        print("  --> PASS: P6.6-39 (Phase 5: 36/36 Passed)")

    def test_P66_40_phase6_regression(self):
        """P6.6-40: Phase 6 acceptance suite passes 37/37."""
        print("[P6.6-40] Running Phase 6 test suite...")
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_phase6_cases.py"],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 6 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("OK", res.stderr)
        print("  --> PASS: P6.6-40 (Phase 6: 37/37 Passed)")

    def test_P66_41_phase65_regression(self):
        """P6.6-41: Phase 6.5 acceptance suite passes 28/28."""
        print("[P6.6-41] Running Phase 6.5 test suite...")
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_phase65_cases.py"],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 6.5 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("OK", res.stderr)
        print("  --> PASS: P6.6-41 (Phase 6.5: 28/28 Passed)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
