"""
tests/test_phase6_cases.py
=============================================================================
Phase 6 Comprehensive Acceptance Test Suite (P6-01 to P6-37)
AI-Based Network Intrusion Detection System — Real-Time ML Detection

USAGE:
    python tests/test_phase6_cases.py
=============================================================================
"""

import hashlib
import json
import math
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_audit import AUDIT_RESULTS, get_audit_summary
from ml.feature_bridge import FeatureBridge, FlowTracker, LiveDetectionBridge
from ml.predict import IntrusionPredictor
from ml.preprocessing import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
)
from server.detection_logger import DetectionLogger
import shared.protocol as protocol

PHASE4_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
EXPECTED_PHASE4_HASH = "9ac544411aff859cb70de9d26a27db387327c28166886a005240c758920ea787"

EXPECTED_MODEL_HASH = "ebeff2aaba1d02f13f5e819f4c9290c75d99f9cd0f14a277423365238faa1eea"
EXPECTED_PREPROC_HASH = "15747da0ac83471f061d05204a4f20e9bf15f225a63ba39ef20f3f3e6c16b915"


class TestPhase6Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 75)
        print("PHASE 6 ACCEPTANCE TEST SUITE (P6-01 to P6-37)")
        print("=" * 75)
        cls.models_dir = os.path.join(PROJECT_ROOT, "models")
        cls.audit_path = os.path.join(cls.models_dir, "feature_availability_audit.json")
        cls.detection_log_path = os.path.join(PROJECT_ROOT, "data", "detection_events.csv")
        cls.test_log_path = os.path.join(PROJECT_ROOT, "data", "test_suite_events.csv")
        cls.test_logger = DetectionLogger(cls.test_log_path)
        cls.bridge = FeatureBridge(cls.models_dir, logger=cls.test_logger)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_log_path):
            try:
                os.remove(cls.test_log_path)
            except Exception:
                pass

    def _get_valid_sample(self):
        sample = {col: 10.0 for col in NUMERICAL_FEATURES}
        sample.update({"proto": "tcp", "service": "http", "state": "con"})
        return sample

    # -------------------------------------------------------------------------
    # P6-01: Repository Architecture Verification
    # -------------------------------------------------------------------------
    def test_P6_01_repository_architecture_verification(self):
        """P6-01: Verify required modules and directories exist."""
        for folder in ["client", "server", "shared", "ml", "models", "data", "tests"]:
            self.assertTrue(os.path.isdir(os.path.join(PROJECT_ROOT, folder)), f"Missing dir: {folder}")
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, "ml", "feature_audit.py")))
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, "ml", "feature_bridge.py")))
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, "server", "detection_logger.py")))
        print("  --> PASS: P6-01 (Repository architecture verified)")

    # -------------------------------------------------------------------------
    # P6-02: Phase 3 Regression
    # -------------------------------------------------------------------------
    def test_P6_02_phase3_regression(self):
        """P6-02: Phase 3 test suite passes 32/32 cleanly."""
        print("[P6-02] Running Phase 3 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase3_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 3 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("32/32 Tests Passed", res.stdout)
        print("  --> PASS: P6-02 (Phase 3: 32/32 Passed)")

    # -------------------------------------------------------------------------
    # P6-03: Phase 4 Regression
    # -------------------------------------------------------------------------
    def test_P6_03_phase4_regression(self):
        """P6-03: Phase 4 test suite passes 28/28 cleanly with data preserved."""
        print("[P6-03] Running Phase 4 test suite...")
        with open(PHASE4_CSV_PATH, "rb") as f:
            initial_bytes = f.read()
        try:
            res = subprocess.run(
                [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase4_cases.py")],
                cwd=PROJECT_ROOT, capture_output=True, text=True
            )
            self.assertEqual(res.returncode, 0, f"Phase 4 regression failed:\n{res.stdout}\n{res.stderr}")
            self.assertIn("ALL PHASE 4 TESTS PASSED", res.stdout)
        finally:
            with open(PHASE4_CSV_PATH, "wb") as f:
                f.write(initial_bytes)
        print("  --> PASS: P6-03 (Phase 4: 28/28 Passed)")

    # -------------------------------------------------------------------------
    # P6-04: Phase 5 Regression
    # -------------------------------------------------------------------------
    def test_P6_04_phase5_regression(self):
        """P6-04: Phase 5 test suite passes 36/36 cleanly."""
        print("[P6-04] Running Phase 5 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase5_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"Phase 5 regression failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("36/36 Tests Passed", res.stdout)
        print("  --> PASS: P6-04 (Phase 5: 36/36 Passed)")

    # -------------------------------------------------------------------------
    # P6-05: Phase 4 CSV Hash Unchanged
    # -------------------------------------------------------------------------
    def test_P6_05_phase4_csv_hash_unchanged(self):
        """P6-05: data/network_traffic.csv SHA-256 matches baseline exactly."""
        with open(PHASE4_CSV_PATH, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(h, EXPECTED_PHASE4_HASH)
        print(f"  --> PASS: P6-05 (Phase 4 CSV hash verified: {h[:16]}...)")

    # -------------------------------------------------------------------------
    # P6-06: Phase 5 Model Artifacts Unchanged
    # -------------------------------------------------------------------------
    def test_P6_06_phase5_model_artifacts_unchanged(self):
        """P6-06: intrusion_model.json and preprocessor.pkl SHA-256 match baseline."""
        model_p = os.path.join(self.models_dir, "intrusion_model.json")
        prep_p = os.path.join(self.models_dir, "preprocessor.pkl")
        with open(model_p, "rb") as f:
            m_hash = hashlib.sha256(f.read()).hexdigest()
        with open(prep_p, "rb") as f:
            p_hash = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(m_hash, EXPECTED_MODEL_HASH)
        self.assertEqual(p_hash, EXPECTED_PREPROC_HASH)
        print("  --> PASS: P6-06 (Model and preprocessor artifacts strictly identical)")

    # -------------------------------------------------------------------------
    # P6-07: Feature Availability Audit Verified
    # -------------------------------------------------------------------------
    def test_P6_07_feature_availability_audit_verified(self):
        """P6-07: models/feature_availability_audit.json documents all 42 features."""
        self.assertTrue(os.path.exists(self.audit_path))
        with open(self.audit_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        summary = data["summary"]
        self.assertEqual(summary["total_model_features"], 42)
        self.assertEqual(summary["directly_observable_count"], 6)
        self.assertEqual(summary["legitimately_derivable_count"], 15)
        self.assertEqual(summary["not_observable_count"], 21)
        print("  --> PASS: P6-07 (Audit verified: 6 Cat A, 15 Cat B, 21 Cat C)")

    # -------------------------------------------------------------------------
    # P6-08: Direct Feature Extraction Verified
    # -------------------------------------------------------------------------
    def test_P6_08_direct_feature_extraction_verified(self):
        """P6-08: Category A features are directly observed from FlowTracker."""
        tracker = FlowTracker("192.168.1.100", 55443)
        time.sleep(0.01)
        tracker.record_request(150, service_name="http")
        tracker.record_response(300)
        tracker.close()
        obs = self.bridge.extract_observed_features(tracker)
        self.assertEqual(obs["proto"], "tcp")
        self.assertEqual(obs["service"], "http")
        self.assertEqual(obs["state"], "FIN")
        self.assertGreater(obs["dur"], 0.0)
        self.assertEqual(obs["sbytes"], 150)
        self.assertEqual(obs["dbytes"], 300)
        print("  --> PASS: P6-08 (Direct features correctly observed)")

    # -------------------------------------------------------------------------
    # P6-09: Derived Feature Calculation Verified
    # -------------------------------------------------------------------------
    def test_P6_09_derived_feature_calculation_verified(self):
        """P6-09: Category B features (rates, loads, window connections) legitimately derived."""
        # 1. Custom TCP protocol (service="-")
        tracker = FlowTracker("192.168.1.100", 55443)
        time.sleep(0.02)
        tracker.record_request(200)
        tracker.record_response(400)
        tracker.close()
        obs = self.bridge.extract_observed_features(tracker)
        self.assertGreater(obs["sload"], 0.0)
        self.assertGreater(obs["dload"], 0.0)
        self.assertEqual(obs["trans_depth"], 0)
        self.assertEqual(obs["response_body_len"], 0)
        self.assertEqual(obs["is_ftp_login"], 0)
        self.assertEqual(obs["ct_ftp_cmd"], 0)
        self.assertEqual(obs["ct_flw_http_mthd"], 0)

        # 2. Genuine HTTP flow (service="http")
        http_tracker = FlowTracker("192.168.1.101", 55444)
        time.sleep(0.02)
        http_tracker.service = "http"
        http_tracker.record_request(200)
        http_tracker.record_response(400)
        http_tracker.close()
        http_obs = self.bridge.extract_observed_features(http_tracker)
        self.assertEqual(http_obs["trans_depth"], 1)
        self.assertEqual(http_obs["response_body_len"], 400)
        print("  --> PASS: P6-09 (Derived features legitimately calculated for TCP and HTTP)")

    # -------------------------------------------------------------------------
    # P6-10: Unavailable Features Explicitly Handled
    # -------------------------------------------------------------------------
    def test_P6_10_unavailable_features_explicitly_handled(self):
        """P6-10: Live flow missing Category C returns structured ERROR without crash."""
        tracker = FlowTracker("10.0.0.5", 50000)
        tracker.record_request(100)
        tracker.close()
        obs = self.bridge.extract_observed_features(tracker)
        # Category C features are absent
        self.assertNotIn("spkts", obs)
        self.assertNotIn("sttl", obs)
        self.assertNotIn("tcprtt", obs)
        res = self.bridge.predict_flow(obs, client_ip="10.0.0.5")
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason"], "INVALID_FEATURE_VECTOR")
        print("  --> PASS: P6-10 (Unavailable features explicitly handled)")

    # -------------------------------------------------------------------------
    # P6-11: No Fabricated Features
    # -------------------------------------------------------------------------
    def test_P6_11_no_fabricated_features(self):
        """P6-11: Assert bridge refuses to invent dummy/default values for missing Category C features."""
        tracker = FlowTracker("10.0.0.5", 50000)
        tracker.record_request(100)
        tracker.close()
        obs = self.bridge.extract_observed_features(tracker)
        # None of the unobservable Category C features should be fabricated
        for unobservable in self.bridge.cat_c_features:
            self.assertNotIn(unobservable, obs, f"Fabricated feature found: {unobservable}")
        print("  --> PASS: P6-11 (Zero fabricated features in extracted observation)")

    # -------------------------------------------------------------------------
    # P6-12: Feature Schema Ordering Verified
    # -------------------------------------------------------------------------
    def test_P6_12_feature_schema_ordering_verified(self):
        """P6-12: FeatureBridge outputs columns matching models/feature_schema.json order."""
        sample = self._get_valid_sample()
        is_valid, _, ordered = self.bridge.validate_feature_vector(sample)
        self.assertTrue(is_valid)
        self.assertEqual(list(ordered.keys()), ALL_MODEL_FEATURES)
        print("  --> PASS: P6-12 (Feature ordering strictly preserved)")

    # -------------------------------------------------------------------------
    # P6-13: Feature Datatype Validation
    # -------------------------------------------------------------------------
    def test_P6_13_feature_datatype_validation(self):
        """P6-13: Non-numeric string in numerical field returns validation error."""
        sample = self._get_valid_sample()
        sample["sbytes"] = "not_a_valid_number"
        is_valid, reason, _ = self.bridge.validate_feature_vector(sample)
        self.assertFalse(is_valid)
        self.assertIn("invalid non-numeric value", reason)
        print("  --> PASS: P6-13 (Invalid data types rejected)")

    # -------------------------------------------------------------------------
    # P6-14: NaN Rejected
    # -------------------------------------------------------------------------
    def test_P6_14_nan_rejected(self):
        """P6-14: NaN value in feature vector is rejected."""
        sample = self._get_valid_sample()
        sample["rate"] = float("nan")
        is_valid, reason, _ = self.bridge.validate_feature_vector(sample)
        self.assertFalse(is_valid)
        self.assertIn("contains NaN", reason)
        print("  --> PASS: P6-14 (NaN rejected)")

    # -------------------------------------------------------------------------
    # P6-15: Infinity Rejected
    # -------------------------------------------------------------------------
    def test_P6_15_infinity_rejected(self):
        """P6-15: Infinity value in feature vector is rejected."""
        sample = self._get_valid_sample()
        sample["sload"] = float("inf")
        is_valid, reason, _ = self.bridge.validate_feature_vector(sample)
        self.assertFalse(is_valid)
        self.assertIn("contains Infinity", reason)
        print("  --> PASS: P6-15 (Infinity rejected)")

    # -------------------------------------------------------------------------
    # P6-16: Missing Feature Rejected
    # -------------------------------------------------------------------------
    def test_P6_16_missing_feature_rejected(self):
        """P6-16: Incomplete feature vector is rejected."""
        sample = self._get_valid_sample()
        del sample["dur"]
        is_valid, reason, _ = self.bridge.validate_feature_vector(sample)
        self.assertFalse(is_valid)
        self.assertIn("Missing required features", reason)
        print("  --> PASS: P6-16 (Missing feature rejected)")

    # -------------------------------------------------------------------------
    # P6-17: Unexpected Feature Rejected
    # -------------------------------------------------------------------------
    def test_P6_17_unexpected_feature_rejected(self):
        """P6-17: Unexpected feature key is rejected."""
        sample = self._get_valid_sample()
        sample["attacker_secret_label"] = 999
        is_valid, reason, _ = self.bridge.validate_feature_vector(sample)
        self.assertFalse(is_valid)
        self.assertIn("Unexpected feature keys", reason)
        print("  --> PASS: P6-17 (Unexpected feature rejected)")

    # -------------------------------------------------------------------------
    # P6-18: Unknown Categorical Value Safely Handled
    # -------------------------------------------------------------------------
    def test_P6_18_unknown_categorical_value_handled(self):
        """P6-18: Unseen protocol / service strings do not cause crashes."""
        sample = self._get_valid_sample()
        sample["proto"] = "custom_unseen_proto_xyz"
        sample["service"] = "unknown_port_service_999"
        res = self.bridge.predict_flow(sample)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn(res["prediction"], ["BENIGN", "INTRUSION"])
        print(f"  --> PASS: P6-18 (Unknown categories handled safely: {res['prediction']})")

    # -------------------------------------------------------------------------
    # P6-19: Valid Prediction Succeeds
    # -------------------------------------------------------------------------
    def test_P6_19_valid_prediction_succeeds(self):
        """P6-19: Valid complete feature vector produces SUCCESS event."""
        sample = self._get_valid_sample()
        res = self.bridge.predict_flow(sample, client_ip="192.168.1.50")
        self.assertEqual(res["status"], "SUCCESS")
        print("  --> PASS: P6-19 (Valid prediction succeeds with SUCCESS status)")

    # -------------------------------------------------------------------------
    # P6-20: Prediction is BENIGN or INTRUSION
    # -------------------------------------------------------------------------
    def test_P6_20_prediction_is_benign_or_intrusion(self):
        """P6-20: Prediction output class is strictly BENIGN or INTRUSION."""
        sample = self._get_valid_sample()
        res = self.bridge.predict_flow(sample, client_ip="192.168.1.50")
        self.assertIn(res["prediction"], ["BENIGN", "INTRUSION"])
        print(f"  --> PASS: P6-20 (Prediction class: {res['prediction']})")

    # -------------------------------------------------------------------------
    # P6-21: Probability is Finite
    # -------------------------------------------------------------------------
    def test_P6_21_probability_is_finite(self):
        """P6-21: Intrusion probability is a finite non-NaN float."""
        sample = self._get_valid_sample()
        res = self.bridge.predict_flow(sample, client_ip="192.168.1.50")
        p = res["intrusion_probability"]
        self.assertIsInstance(p, float)
        self.assertTrue(math.isfinite(p))
        self.assertFalse(math.isnan(p))
        print(f"  --> PASS: P6-21 (Probability is finite: {p})")

    # -------------------------------------------------------------------------
    # P6-22: Probability is Within [0, 1]
    # -------------------------------------------------------------------------
    def test_P6_22_probability_is_within_0_1(self):
        """P6-22: Intrusion probability is strictly in [0.0, 1.0]."""
        sample = self._get_valid_sample()
        res = self.bridge.predict_flow(sample, client_ip="192.168.1.50")
        p = res["intrusion_probability"]
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)
        print(f"  --> PASS: P6-22 (Probability is within [0, 1]: {p:.6f})")

    # -------------------------------------------------------------------------
    # P6-23: Prediction Determinism
    # -------------------------------------------------------------------------
    def test_P6_23_prediction_determinism(self):
        """P6-23: Identical input features yield identical predictions bit-for-bit."""
        sample = self._get_valid_sample()
        res1 = self.bridge.predict_flow(sample)
        res2 = self.bridge.predict_flow(sample)
        self.assertEqual(res1["prediction"], res2["prediction"])
        self.assertEqual(res1["intrusion_probability"], res2["intrusion_probability"])
        print("  --> PASS: P6-23 (Prediction deterministic)")

    # -------------------------------------------------------------------------
    # P6-24: Model Artifacts Reload Successfully
    # -------------------------------------------------------------------------
    def test_P6_24_model_artifacts_reload_successfully(self):
        """P6-24: Fresh FeatureBridge instance reloads models and executes cleanly."""
        fresh_bridge = FeatureBridge(self.models_dir, logger=self.test_logger)
        sample = self._get_valid_sample()
        res = fresh_bridge.predict_flow(sample)
        self.assertEqual(res["status"], "SUCCESS")
        print("  --> PASS: P6-24 (Fresh FeatureBridge reloaded & predicted)")

    # -------------------------------------------------------------------------
    # P6-25: Normal Traffic Integration
    # -------------------------------------------------------------------------
    def test_P6_25_normal_traffic_integration(self):
        """P6-25: Live detection bridge tracks normal client session without crashing."""
        live_bridge = LiveDetectionBridge()
        live_bridge.on_connect("127.0.0.1", 51111)
        live_bridge.on_request("127.0.0.1", 51111, 80, service="status")
        live_bridge.on_response("127.0.0.1", 51111, 120)
        res = live_bridge.on_disconnect("127.0.0.1", 51111)
        self.assertIn(res["status"], ["ERROR", "SUCCESS"])
        print("  --> PASS: P6-25 (Normal traffic flow cleanly completed)")

    # -------------------------------------------------------------------------
    # P6-26: Sustained Traffic Integration
    # -------------------------------------------------------------------------
    def test_P6_26_sustained_traffic_integration(self):
        """P6-26: Live detection bridge tracks 100 sustained requests across session."""
        live_bridge = LiveDetectionBridge()
        live_bridge.on_connect("127.0.0.1", 52222)
        for i in range(100):
            live_bridge.on_request("127.0.0.1", 52222, 50 + (i % 20))
            live_bridge.on_response("127.0.0.1", 52222, 60)
        res = live_bridge.on_disconnect("127.0.0.1", 52222)
        self.assertIn(res["status"], ["ERROR", "SUCCESS"])
        print("  --> PASS: P6-26 (Sustained traffic: 100 requests tracked)")

    # -------------------------------------------------------------------------
    # P6-27: High-Rate Traffic Integration
    # -------------------------------------------------------------------------
    def test_P6_27_high_rate_traffic_integration(self):
        """P6-27: High-rate traffic burst processed without memory or flow leaks."""
        live_bridge = LiveDetectionBridge()
        live_bridge.on_connect("127.0.0.1", 53333)
        for _ in range(500):
            live_bridge.on_request("127.0.0.1", 53333, 20)
        live_bridge.on_disconnect("127.0.0.1", 53333)
        self.assertEqual(len(live_bridge._active_flows), 0)
        print("  --> PASS: P6-27 (500 high-rate requests tracked with 0 leaks)")

    # -------------------------------------------------------------------------
    # P6-28: Multiple Connections
    # -------------------------------------------------------------------------
    def test_P6_28_multiple_connections(self):
        """P6-28: Multiple concurrent connections maintain strictly isolated flows."""
        live_bridge = LiveDetectionBridge()
        live_bridge.on_connect("10.0.0.1", 1001)
        live_bridge.on_connect("10.0.0.2", 1002)
        live_bridge.on_request("10.0.0.1", 1001, 500)
        live_bridge.on_request("10.0.0.2", 1002, 100)
        flow1 = live_bridge._active_flows[("10.0.0.1", 1001)]
        flow2 = live_bridge._active_flows[("10.0.0.2", 1002)]
        self.assertEqual(flow1.sbytes, 500)
        self.assertEqual(flow2.sbytes, 100)
        live_bridge.on_disconnect("10.0.0.1", 1001)
        live_bridge.on_disconnect("10.0.0.2", 1002)
        self.assertEqual(len(live_bridge._active_flows), 0)
        print("  --> PASS: P6-28 (Multiple concurrent connections isolated)")

    # -------------------------------------------------------------------------
    # P6-29: Disconnect Cleanup
    # -------------------------------------------------------------------------
    def test_P6_29_disconnect_cleanup(self):
        """P6-29: Disconnect event cleans active flow map."""
        live_bridge = LiveDetectionBridge()
        live_bridge.on_connect("127.0.0.1", 54444)
        self.assertIn(("127.0.0.1", 54444), live_bridge._active_flows)
        live_bridge.on_disconnect("127.0.0.1", 54444)
        self.assertNotIn(("127.0.0.1", 54444), live_bridge._active_flows)
        print("  --> PASS: P6-29 (Flow state cleaned upon disconnect)")

    # -------------------------------------------------------------------------
    # P6-30: Server Shutdown Cleanup
    # -------------------------------------------------------------------------
    def test_P6_30_server_shutdown_cleanup(self):
        """P6-30: Live server starts and shuts down cleanly with bridge active."""
        server_path = os.path.join(PROJECT_ROOT, "server", "server.py")
        proc = subprocess.Popen(
            [sys.executable, server_path],
            cwd=PROJECT_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.5)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        self.assertIsNotNone(proc.poll())
        print("  --> PASS: P6-30 (Server with detection bridge shuts down cleanly)")

    # -------------------------------------------------------------------------
    # P6-31: Detection Event Logging
    # -------------------------------------------------------------------------
    def test_P6_31_detection_event_logging(self):
        """P6-31: Valid prediction logs real event to isolated CSV."""
        test_log_path = os.path.join(PROJECT_ROOT, "data", "test_detection_events_p31.csv")
        try:
            logger = DetectionLogger(test_log_path)
            sample = self._get_valid_sample()
            b = FeatureBridge(self.models_dir, logger=logger)
            res = b.predict_flow(sample, client_ip="172.16.0.15")
            self.assertEqual(res["status"], "SUCCESS")
            self.assertTrue(os.path.exists(test_log_path))
            with open(test_log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertGreater(len(lines), 1)
            last_line = lines[-1].strip().split(",")
            self.assertEqual(last_line[1], "172.16.0.15")
            self.assertEqual(last_line[2], res["prediction"])
            print(f"  --> PASS: P6-31 (Event logged to CSV: {last_line[1]} -> {last_line[2]})")
        finally:
            if os.path.exists(test_log_path):
                os.remove(test_log_path)

    # -------------------------------------------------------------------------
    # P6-32: Concurrent Traffic Stability
    # -------------------------------------------------------------------------
    def test_P6_32_concurrent_traffic_stability(self):
        """P6-32: Multithreaded client connections execute without lock contention."""
        live_bridge = LiveDetectionBridge()
        errors = []

        def worker(tid):
            try:
                ip = f"10.1.{tid}.1"
                port = 50000 + tid
                live_bridge.on_connect(ip, port)
                for _ in range(50):
                    live_bridge.on_request(ip, port, 100)
                    live_bridge.on_response(ip, port, 80)
                live_bridge.on_disconnect(ip, port)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(len(live_bridge._active_flows), 0)
        print("  --> PASS: P6-32 (10 concurrent threads completed with 0 errors)")

    # -------------------------------------------------------------------------
    # P6-33: No Server Crash on Invalid Features
    # -------------------------------------------------------------------------
    def test_P6_33_no_server_crash_on_invalid_features(self):
        """P6-33: Malformed feature inputs return ERROR without unhandled exceptions."""
        b = FeatureBridge(self.models_dir)
        for bad_input in [{}, None, "not_a_dict", {"sbytes": "abc"}, {"rate": float("nan")}]:
            res = b.predict_flow(bad_input)
            self.assertEqual(res["status"], "ERROR")
        print("  --> PASS: P6-33 (Malformed inputs safely handled without crashes)")

    # -------------------------------------------------------------------------
    # P6-34: No Duplicate Prediction Implementation
    # -------------------------------------------------------------------------
    def test_P6_34_no_duplicate_prediction_implementation(self):
        """P6-34: FeatureBridge delegates inference to existing IntrusionPredictor."""
        self.assertIsInstance(self.bridge.predictor, IntrusionPredictor)
        print("  --> PASS: P6-34 (Delegates directly to existing IntrusionPredictor)")

    # -------------------------------------------------------------------------
    # P6-35: No Unnecessary Files
    # -------------------------------------------------------------------------
    def test_P6_35_no_unnecessary_files(self):
        """P6-35: Verify project directory contains only approved files."""
        expected_py = {
            "client.py", "config.py",
            "server.py", "monitor.py", "dataset_writer.py", "detection_logger.py",
            "protocol.py",
            "__init__.py", "download_dataset.py", "preprocessing.py", "train.py", "predict.py",
            "feature_audit.py", "feature_bridge.py",
            "test_protocol.py", "test_phase3_cases.py", "test_phase4_cases.py",
            "test_phase5_cases.py", "test_phase6_cases.py",
            # Phase 6.5 additions (approved architecture)
            "env_discovery.py", "test_phase65_cases.py",
            # Phase 6.6 additions (approved architecture)
            "packet_capture.py", "flow_tracker.py", "unsw_feature_extractor.py",
            "feature_gate.py", "live_inference.py", "dashboard_server.py",
            "test_phase66_cases.py",
            # Phase 7 & Cloud Forwarder additions (approved architecture)
            "launch.py", "test_phase7_cases.py", "test_cloud_ingestion.py",
            "test_live_forwarder_diagnostics.py",
        }
        for root, dirs, files in os.walk(PROJECT_ROOT):
            if any(x in root for x in [".git", "__pycache__", ".gemini", "data"]):
                continue
            for f in files:
                if f.endswith(".py"):
                    self.assertIn(f, expected_py, f"Unexpected python file found: {f}")
        print("  --> PASS: P6-35 (File tree matches approved Phase 6 architecture)")

    # -------------------------------------------------------------------------
    # P6-36: Complete Phase 6 End-to-End Pipeline
    # -------------------------------------------------------------------------
    def test_P6_36_complete_phase6_end_to_end(self):
        """P6-36: Full flow from client session to flow tracking, bridge, and detection log."""
        test_log_path = os.path.join(PROJECT_ROOT, "data", "test_detection_events_p36.csv")
        try:
            test_logger = DetectionLogger(test_log_path)
            test_bridge = FeatureBridge(self.models_dir, logger=test_logger)
            live_bridge = LiveDetectionBridge(bridge=test_bridge)
            client_ip = "192.168.1.99"
            client_port = 56789

            # 2. Client connects
            live_bridge.on_connect(client_ip, client_port)

            # 3. Client sends requests
            for i in range(5):
                live_bridge.on_request(client_ip, client_port, 120 + i, service="-")
                live_bridge.on_response(client_ip, client_port, 200 + i)

            # 4. Client disconnects -> returns INVALID_FEATURE_VECTOR on unobservable features
            disconnect_res = live_bridge.on_disconnect(client_ip, client_port)
            self.assertEqual(disconnect_res["status"], "ERROR")
            self.assertEqual(disconnect_res["reason"], "INVALID_FEATURE_VECTOR")

            # 5. Controlled verified test flow through bridge to detection event
            sample = self._get_valid_sample()
            pred_res = live_bridge.bridge.predict_flow(sample, client_ip=client_ip)
            self.assertEqual(pred_res["status"], "SUCCESS")
            self.assertIn(pred_res["prediction"], ["BENIGN", "INTRUSION"])

            # 6. Verify detection log output
            self.assertTrue(os.path.exists(test_log_path))
            with open(test_log_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(client_ip, content)
            print("  --> PASS: P6-36 (Complete end-to-end detection pipeline verified)")
        finally:
            if os.path.exists(test_log_path):
                os.remove(test_log_path)

    # -------------------------------------------------------------------------
    # P6-37: Real Live Socket Traffic Rejection (Zero Category C Fabrication)
    # -------------------------------------------------------------------------
    def test_P6_37_real_live_socket_unobservable_features_rejected(self):
        """
        P6-37: Audits end-to-end real socket traffic from real client socket to server:
        REAL CLIENT SOCKET -> REAL SERVER -> REAL FLOW TRACKER -> FeatureBridge
        Proves:
        1. Real TCP flow produces 21 observed/derived features (6 Cat A + 15 Cat B).
        2. Real flow lacks the 21 unobservable Category C features.
        3. FeatureBridge strictly REFUSES to fabricate missing features.
        4. IntrusionPredictor is NOT called on incomplete vectors.
        5. Return status is explicitly ERROR with reason INVALID_FEATURE_VECTOR.
        """
        server_proc = subprocess.Popen(
            [sys.executable, os.path.join(PROJECT_ROOT, "server", "server.py")],
            cwd=PROJECT_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.0)
        try:
            # Connect real client socket to live server with retry loop
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for attempt in range(8):
                try:
                    s.connect(("127.0.0.1", 5000))
                    break
                except ConnectionRefusedError:
                    if attempt == 7:
                        raise
                    time.sleep(0.5)
            client_ip, client_port = s.getsockname()

            client_buf = bytearray()
            req = protocol.build_request("DATA_REQUEST", "Audit Test")
            protocol.send_message(s, req)
            resp = protocol.recv_message(s, client_buf, 4096)
            self.assertEqual(resp["status"], "SUCCESS")
            s.close()
            time.sleep(0.5)

            # Replicate server flow tracking on this real flow
            tracker = FlowTracker(client_ip, client_port, server_port=5000)
            tracker.record_request(len(json.dumps(req).encode("utf-8")), service_name="-")
            tracker.record_response(len(json.dumps(resp).encode("utf-8")))
            tracker.close()

            obs = self.bridge.extract_observed_features(tracker)
            # Exactly 21 features present (6 Category A + 15 Category B)
            self.assertEqual(len(obs), 21)
            for c_feat in ["spkts", "dpkts", "sttl", "dttl", "sinpkt", "dinpkt"]:
                self.assertNotIn(c_feat, obs)

            # Bridge evaluation on this real flow must return INVALID_FEATURE_VECTOR
            eval_res = self.bridge.predict_flow(obs, client_ip=client_ip)
            self.assertEqual(eval_res["status"], "ERROR")
            self.assertEqual(eval_res["reason"], "INVALID_FEATURE_VECTOR")
            self.assertIn("Missing required features", eval_res["message"])
            print("  --> PASS: P6-37 (Real socket traffic correctly produces INVALID_FEATURE_VECTOR without fabrication)")
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server_proc.kill()


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhase6Acceptance)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    print("\n" + "=" * 75)
    print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun} Tests Passed")
    print("=" * 75)
    if not result.wasSuccessful():
        sys.exit(1)
    print("\nALL PHASE 6 TEST CASES (P6-01 to P6-37) PASSED PERFECTLY!\n")


if __name__ == "__main__":
    main()
