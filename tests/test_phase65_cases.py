"""
tests/test_phase65_cases.py
=============================================================================
Phase 6.5 Acceptance Test Suite (P6.5-01 to P6.5-28)
AI-Based Network Intrusion Detection System
Packet-Level Telemetry & Real-Time ML Inference — Environment Discovery

PHASE 6.5 STATUS: FORMALLY DOCUMENTED BLOCKED STATE
  - No Npcap/WinPcap driver installed in this environment.
  - No administrator privileges available.
  - No packet capture libraries (scapy/pyshark/dpkt) installed.
  - All 21 Category C (packet/kernel-level) UNSW-NB15 features remain
    unobservable. Live ML inference correctly and consistently refused.
  - This test suite verifies the honest, non-fabricated BLOCKED status.

USAGE:
    python tests/test_phase65_cases.py

FROZEN FILES (zero modifications allowed):
    ml/feature_bridge.py, ml/predict.py, ml/preprocessing.py, ml/train.py,
    server/server.py, server/monitor.py, server/dataset_writer.py,
    server/detection_logger.py, shared/protocol.py, client/client.py,
    data/network_traffic.csv, models/intrusion_model.json,
    models/preprocessor.pkl, models/feature_schema.json,
    models/training_metadata.json, tests/test_phase6_cases.py,
    tests/test_phase5_cases.py, tests/test_phase4_cases.py,
    tests/test_phase3_cases.py
=============================================================================
"""

import hashlib
import importlib
import json
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
from ml.feature_bridge import FeatureBridge, FlowTracker
from ml.preprocessing import ALL_MODEL_FEATURES, CATEGORICAL_FEATURES, NUMERICAL_FEATURES
from server.detection_logger import DetectionLogger
import shared.protocol as protocol

# ---------------------------------------------------------------------------
# Frozen hash baselines
# ---------------------------------------------------------------------------
PHASE4_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
EXPECTED_PHASE4_HASH = "9ac544411aff859cb70de9d26a27db387327c28166886a005240c758920ea787"
EXPECTED_MODEL_HASH = "ebeff2aaba1d02f13f5e819f4c9290c75d99f9cd0f14a277423365238faa1eea"
EXPECTED_PREPROC_HASH = "15747da0ac83471f061d05204a4f20e9bf15f225a63ba39ef20f3f3e6c16b915"

# ---------------------------------------------------------------------------
# Approved file tree for Phase 6.5
# ---------------------------------------------------------------------------
APPROVED_PY_FILES = {
    # Phase 1-6 (unchanged)
    os.path.join("client", "client.py"),
    os.path.join("client", "config.py"),
    os.path.join("server", "config.py"),
    os.path.join("server", "dataset_writer.py"),
    os.path.join("server", "detection_logger.py"),
    os.path.join("server", "monitor.py"),
    os.path.join("server", "server.py"),
    os.path.join("shared", "protocol.py"),
    os.path.join("ml", "__init__.py"),
    os.path.join("ml", "download_dataset.py"),
    os.path.join("ml", "feature_audit.py"),
    os.path.join("ml", "feature_bridge.py"),
    os.path.join("ml", "predict.py"),
    os.path.join("ml", "preprocessing.py"),
    os.path.join("ml", "train.py"),
    os.path.join("tests", "test_protocol.py"),
    os.path.join("tests", "test_phase3_cases.py"),
    os.path.join("tests", "test_phase4_cases.py"),
    os.path.join("tests", "test_phase5_cases.py"),
    os.path.join("tests", "test_phase6_cases.py"),
    # Phase 6.5 additions
    os.path.join("ml", "env_discovery.py"),
    os.path.join("tests", "test_phase65_cases.py"),
    # Phase 6.6 additions
    os.path.join("ml", "packet_capture.py"),
    os.path.join("ml", "flow_tracker.py"),
    os.path.join("ml", "unsw_feature_extractor.py"),
    os.path.join("ml", "feature_gate.py"),
    os.path.join("ml", "live_inference.py"),
    os.path.join("server", "dashboard_server.py"),
    os.path.join("tests", "test_phase66_cases.py"),
}

# Category C features that must never appear in extracted observations
CAT_C_FEATURES = [
    "spkts", "dpkts", "rate", "sttl", "dttl",
    "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean", "ct_state_ttl",
]

# Required top-level keys in the env discovery report
REQUIRED_REPORT_KEYS = {
    "phase",
    "discovery_reason",
    "platform_info",
    "npcap",
    "privileges",
    "raw_socket",
    "promiscuous_sniffer",
    "capture_libraries",
    "packet_capture_status",
    "block_reason",
    "cat_c_upgrade_path",
}

# Required keys inside the capture_libraries sub-dict
REQUIRED_LIBS_KEYS = {
    "scapy_available",
    "pyshark_available",
    "dpkt_available",
    "any_capture_library_available",
}

# Required upgrade path keys
REQUIRED_UPGRADE_KEYS = {
    "step_1_install_npcap",
    "step_2_install_scapy",
    "step_3_run_as_administrator",
    "cat_c_features_unlocked",
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestPhase65Acceptance(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 75)
        print("PHASE 6.5 ACCEPTANCE TEST SUITE (P6.5-01 to P6.5-28)")
        print("Packet-Level Telemetry & Environment Discovery")
        print("=" * 75)
        cls.models_dir = os.path.join(PROJECT_ROOT, "models")
        cls.detection_log_path = os.path.join(PROJECT_ROOT, "data", "detection_events.csv")
        cls.test_log_path = os.path.join(PROJECT_ROOT, "data", "test_suite_p65_events.csv")
        cls.test_logger = DetectionLogger(cls.test_log_path)
        cls.bridge = FeatureBridge(cls.models_dir, logger=cls.test_logger)
        cls.env_report_path = os.path.join(cls.models_dir, "env_discovery_report.json")

    @classmethod
    def tearDownClass(cls):
        # Clean up isolated test log
        if os.path.exists(cls.test_log_path):
            try:
                os.remove(cls.test_log_path)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # P6.5-01: Phase 3 Regression (32/32)
    # -------------------------------------------------------------------------
    def test_P65_01_phase3_regression(self):
        """P6.5-01: Phase 3 test suite passes 32/32."""
        print("[P6.5-01] Running Phase 3 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase3_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode, 0,
            f"Phase 3 regression failed:\n{res.stdout}\n{res.stderr}"
        )
        self.assertIn("32/32 Tests Passed", res.stdout)
        print("  --> PASS: P6.5-01 (Phase 3: 32/32 Passed)")

    # -------------------------------------------------------------------------
    # P6.5-02: Phase 4 Regression (28/28)
    # -------------------------------------------------------------------------
    def test_P65_02_phase4_regression(self):
        """P6.5-02: Phase 4 test suite passes 28/28 with CSV preserved."""
        print("[P6.5-02] Running Phase 4 test suite...")
        with open(PHASE4_CSV_PATH, "rb") as f:
            saved_bytes = f.read()
        try:
            res = subprocess.run(
                [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase4_cases.py")],
                cwd=PROJECT_ROOT, capture_output=True, text=True
            )
            self.assertEqual(
                res.returncode, 0,
                f"Phase 4 regression failed:\n{res.stdout}\n{res.stderr}"
            )
            self.assertIn("ALL PHASE 4 TESTS PASSED", res.stdout)
        finally:
            with open(PHASE4_CSV_PATH, "wb") as f:
                f.write(saved_bytes)
        print("  --> PASS: P6.5-02 (Phase 4: 28/28 Passed)")

    # -------------------------------------------------------------------------
    # P6.5-03: Phase 5 Regression (36/36)
    # -------------------------------------------------------------------------
    def test_P65_03_phase5_regression(self):
        """P6.5-03: Phase 5 test suite passes 36/36."""
        print("[P6.5-03] Running Phase 5 test suite...")
        res = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase5_cases.py")],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode, 0,
            f"Phase 5 regression failed:\n{res.stdout}\n{res.stderr}"
        )
        self.assertIn("36/36 Tests Passed", res.stdout)
        print("  --> PASS: P6.5-03 (Phase 5: 36/36 Passed)")

    # -------------------------------------------------------------------------
    # P6.5-04: Phase 6 Regression (37/37)
    # -------------------------------------------------------------------------
    def test_P65_04_phase6_regression(self):
        """P6.5-04: Phase 6 test suite passes 37/37."""
        print("[P6.5-04] Running Phase 6 test suite...")
        with open(PHASE4_CSV_PATH, "rb") as f:
            saved_bytes = f.read()
        try:
            res = subprocess.run(
                [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase6_cases.py")],
                cwd=PROJECT_ROOT, capture_output=True, text=True
            )
            self.assertEqual(
                res.returncode, 0,
                f"Phase 6 regression failed:\n{res.stdout}\n{res.stderr}"
            )
            self.assertIn("37/37 Tests Passed", res.stdout)
        finally:
            with open(PHASE4_CSV_PATH, "wb") as f:
                f.write(saved_bytes)
        print("  --> PASS: P6.5-04 (Phase 6: 37/37 Passed)")

    # -------------------------------------------------------------------------
    # P6.5-05: Phase 4 CSV hash preserved
    # -------------------------------------------------------------------------
    def test_P65_05_phase4_csv_hash(self):
        """P6.5-05: Phase 4 dataset SHA-256 matches frozen baseline."""
        actual = _sha256(PHASE4_CSV_PATH)
        self.assertEqual(
            actual, EXPECTED_PHASE4_HASH,
            f"Phase 4 CSV hash mismatch!\nExpected: {EXPECTED_PHASE4_HASH}\nActual:   {actual}"
        )
        print(f"  --> PASS: P6.5-05 (Phase 4 CSV hash verified: {EXPECTED_PHASE4_HASH[:16]}...)")

    # -------------------------------------------------------------------------
    # P6.5-06: Phase 5 artifact hashes preserved
    # -------------------------------------------------------------------------
    def test_P65_06_phase5_artifact_hashes(self):
        """P6.5-06: Phase 5 model and preprocessor hashes match frozen baselines."""
        model_path = os.path.join(self.models_dir, "intrusion_model.json")
        preproc_path = os.path.join(self.models_dir, "preprocessor.pkl")
        actual_model = _sha256(model_path)
        actual_preproc = _sha256(preproc_path)
        self.assertEqual(
            actual_model, EXPECTED_MODEL_HASH,
            f"Model hash mismatch!\nExpected: {EXPECTED_MODEL_HASH}\nActual: {actual_model}"
        )
        self.assertEqual(
            actual_preproc, EXPECTED_PREPROC_HASH,
            f"Preprocessor hash mismatch!\nExpected: {EXPECTED_PREPROC_HASH}\nActual: {actual_preproc}"
        )
        print("  --> PASS: P6.5-06 (Phase 5 artifact hashes preserved)")

    # -------------------------------------------------------------------------
    # P6.5-07: env_discovery module importable
    # -------------------------------------------------------------------------
    def test_P65_07_env_discovery_importable(self):
        """P6.5-07: ml/env_discovery.py can be imported without errors."""
        env_path = os.path.join(PROJECT_ROOT, "ml", "env_discovery.py")
        self.assertTrue(
            os.path.isfile(env_path),
            "ml/env_discovery.py does not exist"
        )
        try:
            from ml.env_discovery import discover_packet_capture_environment, PACKET_CAPTURE_STATUS
        except ImportError as exc:
            self.fail(f"Failed to import ml.env_discovery: {exc}")
        print("  --> PASS: P6.5-07 (ml/env_discovery.py importable)")

    # -------------------------------------------------------------------------
    # P6.5-08: discover_packet_capture_environment() returns a dict
    # -------------------------------------------------------------------------
    def test_P65_08_discovery_function_returns_dict(self):
        """P6.5-08: discover_packet_capture_environment() returns a non-empty dict."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        self.assertIsInstance(report, dict, "Report must be a dict")
        self.assertGreater(len(report), 0, "Report must be non-empty")
        print("  --> PASS: P6.5-08 (discover_packet_capture_environment() returns dict)")

    # -------------------------------------------------------------------------
    # P6.5-09: Report contains all required top-level keys
    # -------------------------------------------------------------------------
    def test_P65_09_report_required_keys(self):
        """P6.5-09: Environment report contains all mandatory top-level keys."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        missing = REQUIRED_REPORT_KEYS - set(report.keys())
        self.assertEqual(
            missing, set(),
            f"Report is missing required keys: {sorted(missing)}"
        )
        print(f"  --> PASS: P6.5-09 (Report has all {len(REQUIRED_REPORT_KEYS)} required keys)")

    # -------------------------------------------------------------------------
    # P6.5-10: PACKET_CAPTURE_STATUS is a valid string constant
    # -------------------------------------------------------------------------
    def test_P65_10_packet_capture_status_constant(self):
        """P6.5-10: PACKET_CAPTURE_STATUS is a module-level string in {BLOCKED, PARTIAL, AVAILABLE}."""
        from ml.env_discovery import PACKET_CAPTURE_STATUS
        self.assertIsInstance(PACKET_CAPTURE_STATUS, str)
        self.assertIn(
            PACKET_CAPTURE_STATUS, {"BLOCKED", "PARTIAL", "AVAILABLE"},
            f"PACKET_CAPTURE_STATUS must be BLOCKED/PARTIAL/AVAILABLE, got: {PACKET_CAPTURE_STATUS!r}"
        )
        print(f"  --> PASS: P6.5-10 (PACKET_CAPTURE_STATUS = '{PACKET_CAPTURE_STATUS}')")

    # -------------------------------------------------------------------------
    # P6.5-11: npcap check result is a bool
    # -------------------------------------------------------------------------
    def test_P65_11_npcap_check_is_bool(self):
        """P6.5-11: report['npcap']['npcap_dll_found'] is a boolean."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        val = report["npcap"]["npcap_dll_found"]
        self.assertIsInstance(val, bool, f"npcap_dll_found must be bool, got {type(val).__name__}")
        print(f"  --> PASS: P6.5-11 (npcap_dll_found = {val})")

    # -------------------------------------------------------------------------
    # P6.5-12: admin check result is a bool
    # -------------------------------------------------------------------------
    def test_P65_12_admin_check_is_bool(self):
        """P6.5-12: report['privileges']['is_admin'] is a boolean."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        val = report["privileges"]["is_admin"]
        self.assertIsInstance(val, bool, f"is_admin must be bool, got {type(val).__name__}")
        print(f"  --> PASS: P6.5-12 (is_admin = {val})")

    # -------------------------------------------------------------------------
    # P6.5-13: raw socket check result is a bool
    # -------------------------------------------------------------------------
    def test_P65_13_raw_socket_check_is_bool(self):
        """P6.5-13: report['raw_socket']['raw_socket_available'] is a boolean."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        val = report["raw_socket"]["raw_socket_available"]
        self.assertIsInstance(val, bool, f"raw_socket_available must be bool, got {type(val).__name__}")
        print(f"  --> PASS: P6.5-13 (raw_socket_available = {val})")

    # -------------------------------------------------------------------------
    # P6.5-14: scapy check result is a bool
    # -------------------------------------------------------------------------
    def test_P65_14_scapy_check_is_bool(self):
        """P6.5-14: report['capture_libraries']['scapy_available'] is a boolean."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        val = report["capture_libraries"]["scapy_available"]
        self.assertIsInstance(val, bool, f"scapy_available must be bool, got {type(val).__name__}")
        # Also verify all required library keys exist
        libs = report["capture_libraries"]
        missing = REQUIRED_LIBS_KEYS - set(libs.keys())
        self.assertEqual(missing, set(), f"capture_libraries missing keys: {sorted(missing)}")
        print(f"  --> PASS: P6.5-14 (scapy_available = {val})")

    # -------------------------------------------------------------------------
    # P6.5-15: env report JSON file created and valid
    # -------------------------------------------------------------------------
    def test_P65_15_env_report_file_written(self):
        """P6.5-15: write_env_report() writes a valid JSON file to models/."""
        from ml.env_discovery import write_env_report
        out_path = write_env_report()
        self.assertTrue(
            os.path.isfile(out_path),
            f"env_discovery_report.json not found at: {out_path}"
        )
        self.assertGreater(
            os.path.getsize(out_path), 0,
            "env_discovery_report.json is empty"
        )
        with open(out_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertIsInstance(loaded, dict, "Report JSON must be a dict")
        self.assertIn("packet_capture_status", loaded, "JSON missing packet_capture_status key")
        print(f"  --> PASS: P6.5-15 (env_discovery_report.json written: {os.path.basename(out_path)})")

    # -------------------------------------------------------------------------
    # P6.5-16: Status is BLOCKED in this specific environment
    # -------------------------------------------------------------------------
    def test_P65_16_status_blocked_in_this_environment(self):
        """P6.5-16: PACKET_CAPTURE_STATUS must be BLOCKED given absence of Npcap + admin + libs."""
        from ml.env_discovery import discover_packet_capture_environment, PACKET_CAPTURE_STATUS
        report = discover_packet_capture_environment()
        # Verify the conditions that force BLOCKED are actually present
        npcap_found = report["npcap"]["npcap_dll_found"]
        raw_available = report["raw_socket"]["raw_socket_available"]
        any_lib = report["capture_libraries"]["any_capture_library_available"]
        # In this environment: all three absent = BLOCKED
        if not npcap_found and not raw_available and not any_lib:
            self.assertEqual(
                PACKET_CAPTURE_STATUS, "BLOCKED",
                f"Expected BLOCKED but got: {PACKET_CAPTURE_STATUS}"
            )
        # If environment has changed, PARTIAL or AVAILABLE is acceptable
        self.assertIn(PACKET_CAPTURE_STATUS, {"BLOCKED", "PARTIAL", "AVAILABLE"})
        print(f"  --> PASS: P6.5-16 (Environment status correctly classified as '{PACKET_CAPTURE_STATUS}')")

    # -------------------------------------------------------------------------
    # P6.5-17: block_reason is a non-empty string when BLOCKED
    # -------------------------------------------------------------------------
    def test_P65_17_block_reason_documented(self):
        """P6.5-17: block_reason is a non-empty string when status is BLOCKED."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        status = report["packet_capture_status"]
        reason = report["block_reason"]
        self.assertIsInstance(reason, str, "block_reason must be a string")
        if status == "BLOCKED":
            self.assertGreater(
                len(reason.strip()), 0,
                "block_reason must be non-empty when status is BLOCKED"
            )
        print(f"  --> PASS: P6.5-17 (block_reason documented: {reason[:60]}...)")

    # -------------------------------------------------------------------------
    # P6.5-18: Upgrade path is documented in the report
    # -------------------------------------------------------------------------
    def test_P65_18_upgrade_path_documented(self):
        """P6.5-18: cat_c_upgrade_path contains all required step keys."""
        from ml.env_discovery import discover_packet_capture_environment
        report = discover_packet_capture_environment()
        upgrade = report["cat_c_upgrade_path"]
        self.assertIsInstance(upgrade, dict, "cat_c_upgrade_path must be a dict")
        missing = REQUIRED_UPGRADE_KEYS - set(upgrade.keys())
        self.assertEqual(
            missing, set(),
            f"cat_c_upgrade_path is missing keys: {sorted(missing)}"
        )
        # Verify cat_c_features_unlocked is a list of 21 features
        unlocked = upgrade["cat_c_features_unlocked"]
        self.assertIsInstance(unlocked, list)
        self.assertEqual(
            len(unlocked), 21,
            f"Expected 21 Cat C features in upgrade path, got {len(unlocked)}"
        )
        print(f"  --> PASS: P6.5-18 (Upgrade path documented with {len(unlocked)} Cat C features)")

    # -------------------------------------------------------------------------
    # P6.5-19: extract_observed_features() still returns exactly 21 keys
    # -------------------------------------------------------------------------
    def test_P65_19_extracted_features_count_unchanged(self):
        """P6.5-19: extract_observed_features() returns exactly 21 keys (6 Cat A + 15 Cat B)."""
        flow = FlowTracker("127.0.0.1", 50001, "127.0.0.1", 5000)
        flow.record_request(128)
        flow.record_response(256)
        flow.close()
        obs = self.bridge.extract_observed_features(flow)
        self.assertIsInstance(obs, dict)
        self.assertEqual(
            len(obs), 21,
            f"Expected 21 extracted features (6 Cat A + 15 Cat B), got {len(obs)}"
        )
        print(f"  --> PASS: P6.5-19 (extract_observed_features() returns exactly 21 keys)")

    # -------------------------------------------------------------------------
    # P6.5-20: No Cat C feature keys appear in the extracted observation
    # -------------------------------------------------------------------------
    def test_P65_20_no_cat_c_keys_in_observation(self):
        """P6.5-20: None of the 21 Category C feature names appear in extract_observed_features()."""
        flow = FlowTracker("127.0.0.1", 50002, "127.0.0.1", 5000)
        flow.record_request(200)
        flow.record_response(300)
        flow.close()
        obs = self.bridge.extract_observed_features(flow)
        fabricated = [f for f in CAT_C_FEATURES if f in obs]
        self.assertEqual(
            fabricated, [],
            f"FABRICATION DETECTED — Cat C features found in observation: {fabricated}"
        )
        print(f"  --> PASS: P6.5-20 (Zero Cat C features in extracted observation)")

    # -------------------------------------------------------------------------
    # P6.5-21: Real TCP socket still produces INVALID_FEATURE_VECTOR
    # -------------------------------------------------------------------------
    def test_P65_21_live_socket_produces_invalid_feature_vector(self):
        """P6.5-21: Real client-server TCP traffic → INVALID_FEATURE_VECTOR (no fabrication)."""
        server_script = os.path.join(PROJECT_ROOT, "server", "server.py")
        server_proc = subprocess.Popen(
            [sys.executable, server_script],
            cwd=os.path.join(PROJECT_ROOT, "server"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2.0)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(("127.0.0.1", 5000))
            client_ip, client_port = s.getsockname()

            buf = bytearray()
            req = protocol.build_request("DATA_REQUEST", "Phase6.5 Audit Test")
            protocol.send_message(s, req)
            resp = protocol.recv_message(s, buf, 4096)
            self.assertEqual(resp["status"], "SUCCESS")
            s.close()
            time.sleep(0.5)

            # Simulate what the server's FlowTracker observed
            tracker = FlowTracker(client_ip, client_port, server_port=5000)
            tracker.record_request(len(json.dumps(req).encode("utf-8")), service_name="-")
            tracker.record_response(len(json.dumps(resp).encode("utf-8")))
            tracker.close()

            obs = self.bridge.extract_observed_features(tracker)
            # 21 partial features extracted
            self.assertEqual(len(obs), 21, f"Expected 21 partial features, got {len(obs)}")
            # No Cat C present
            fabricated = [f for f in CAT_C_FEATURES if f in obs]
            self.assertEqual(fabricated, [], f"Cat C fabrication: {fabricated}")
            # Prediction refused with INVALID_FEATURE_VECTOR
            eval_res = self.bridge.predict_flow(obs, client_ip=client_ip)
            self.assertEqual(eval_res["status"], "ERROR")
            self.assertEqual(eval_res["reason"], "INVALID_FEATURE_VECTOR")
            print("  --> PASS: P6.5-21 (Real socket traffic produces INVALID_FEATURE_VECTOR)")
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    # -------------------------------------------------------------------------
    # P6.5-22: Rejection message references missing features
    # -------------------------------------------------------------------------
    def test_P65_22_rejection_message_explains_missing_features(self):
        """P6.5-22: INVALID_FEATURE_VECTOR error message specifies 'Missing required features'."""
        flow = FlowTracker("10.0.0.1", 60000, "127.0.0.1", 5000)
        flow.record_request(512)
        flow.record_response(256)
        flow.close()
        obs = self.bridge.extract_observed_features(flow)
        result = self.bridge.predict_flow(obs, client_ip="10.0.0.1")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["reason"], "INVALID_FEATURE_VECTOR")
        self.assertIn(
            "Missing required features",
            result["message"],
            f"Error message does not mention missing features: {result['message']!r}"
        )
        # Verify the count is correct (21 Cat C features missing)
        self.assertIn("21", result["message"], "Expected '21' in missing features message")
        print(f"  --> PASS: P6.5-22 (Rejection message explains missing features)")

    # -------------------------------------------------------------------------
    # P6.5-23: Audit summary now contains live_telemetry_status
    # -------------------------------------------------------------------------
    def test_P65_23_audit_summary_has_telemetry_status(self):
        """P6.5-23: get_audit_summary() returns 'live_telemetry_status' key (Phase 6.5 addition)."""
        summary = get_audit_summary()
        self.assertIn(
            "live_telemetry_status", summary,
            "get_audit_summary() missing 'live_telemetry_status' key (Phase 6.5 addition)"
        )
        status = summary["live_telemetry_status"]
        self.assertIsInstance(status, str)
        self.assertIn(
            status, {"BLOCKED", "PARTIAL", "AVAILABLE", "UNKNOWN"},
            f"live_telemetry_status must be BLOCKED/PARTIAL/AVAILABLE/UNKNOWN, got: {status!r}"
        )
        # Pre-existing keys must still be present (backward compatibility)
        for key in [
            "total_model_features", "directly_observable_count",
            "legitimately_derivable_count", "not_observable_count",
            "directly_observable_features", "legitimately_derivable_features",
            "not_observable_features", "architectural_limitation_statement",
        ]:
            self.assertIn(key, summary, f"Pre-existing audit key missing: {key}")
        print(f"  --> PASS: P6.5-23 (Audit summary has live_telemetry_status = '{status}')")

    # -------------------------------------------------------------------------
    # P6.5-24: Audit summary now contains packet_capture_upgrade_path
    # -------------------------------------------------------------------------
    def test_P65_24_audit_summary_has_upgrade_path(self):
        """P6.5-24: get_audit_summary() returns 'packet_capture_upgrade_path' key."""
        summary = get_audit_summary()
        self.assertIn(
            "packet_capture_upgrade_path", summary,
            "get_audit_summary() missing 'packet_capture_upgrade_path' key (Phase 6.5 addition)"
        )
        upgrade = summary["packet_capture_upgrade_path"]
        self.assertIsInstance(upgrade, dict)
        # Must contain step keys when available (empty dict acceptable if UNKNOWN)
        if upgrade:
            for key in ["step_1_install_npcap", "step_2_install_scapy"]:
                self.assertIn(key, upgrade, f"upgrade path missing key: {key}")
        print("  --> PASS: P6.5-24 (Audit summary has packet_capture_upgrade_path)")

    # -------------------------------------------------------------------------
    # P6.5-25: File tree contains only approved Phase 6.5 Python files
    # -------------------------------------------------------------------------
    def test_P65_25_file_tree_clean(self):
        """P6.5-25: No unexpected .py files exist beyond the approved Phase 6.5 set."""
        # Collect all .py files under project root (excluding __pycache__ and hidden dirs)
        actual_py_files = set()
        excluded_dirs = {"__pycache__", ".git", ".gemini", ".agents"}
        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in excluded_dirs and not d.startswith(".")]
            for fname in files:
                if fname.endswith(".py"):
                    rel = os.path.relpath(os.path.join(root, fname), PROJECT_ROOT)
                    actual_py_files.add(rel)

        unexpected = actual_py_files - APPROVED_PY_FILES
        self.assertEqual(
            unexpected, set(),
            f"Unexpected .py files found (not in approved Phase 6.5 set):\n"
            + "\n".join(f"  - {f}" for f in sorted(unexpected))
        )
        # Verify all approved files exist
        for rel in sorted(APPROVED_PY_FILES):
            path = os.path.join(PROJECT_ROOT, rel)
            self.assertTrue(os.path.isfile(path), f"Approved file missing: {rel}")
        print(f"  --> PASS: P6.5-25 (File tree clean: {len(APPROVED_PY_FILES)} approved .py files)")

    # -------------------------------------------------------------------------
    # P6.5-26: requirements.txt contains no new packet-capture dependencies
    # -------------------------------------------------------------------------
    def test_P65_26_no_new_dependencies(self):
        """P6.5-26: requirements.txt contains no new packet-capture libraries."""
        req_path = os.path.join(PROJECT_ROOT, "requirements.txt")
        self.assertTrue(os.path.isfile(req_path), "requirements.txt not found")
        with open(req_path, "r", encoding="utf-8") as f:
            content = f.read().lower()
        # Packet capture libraries must NOT have been added
        forbidden_deps = ["scapy", "pyshark", "dpkt", "pypcap", "pcapy", "npcap"]
        found_forbidden = [dep for dep in forbidden_deps if dep in content]
        self.assertEqual(
            found_forbidden, [],
            f"Forbidden packet-capture dependencies found in requirements.txt: {found_forbidden}"
        )
        # Phase 5 dependencies must still be present
        for dep in ["numpy", "scikit-learn", "xgboost", "joblib"]:
            self.assertIn(dep, content, f"Required Phase 5 dep missing from requirements.txt: {dep}")
        print("  --> PASS: P6.5-26 (requirements.txt unchanged: no new packet-capture deps)")

    # -------------------------------------------------------------------------
    # P6.5-27: detection_events.csv remains clean (no fabricated events)
    # -------------------------------------------------------------------------
    def test_P65_27_detection_events_clean(self):
        """P6.5-27: data/detection_events.csv has no fabricated detection events."""
        det_path = os.path.join(PROJECT_ROOT, "data", "detection_events.csv")
        self.assertTrue(os.path.isfile(det_path), "detection_events.csv missing")
        with open(det_path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f.readlines() if ln.strip()]
        # File should contain only the header (1 line) when no successful predictions made
        # This test verifies Phase 6.5 didn't fabricate any inference results
        header = lines[0] if lines else ""
        self.assertIn(
            "timestamp", header,
            "detection_events.csv first line must be the CSV header"
        )
        # If any data rows exist, they must be real logged events (status=SUCCESS)
        # not fabrications. We cannot assert zero data rows because P6-02 to P6-04
        # run sub-suites that may legitimately log events. We assert no ERROR rows
        # with intrusion_probability values that look fabricated (e.g., exactly 0.000000
        # for a refusal that was incorrectly promoted to a logged event).
        data_rows = lines[1:]
        for row in data_rows:
            # Each row must be a real SUCCESS event with valid CSV structure
            parts = row.split(",")
            self.assertGreaterEqual(len(parts), 5, f"Malformed CSV row: {row!r}")
            # status field (last field) must be SUCCESS
            self.assertEqual(
                parts[-1].strip(), "SUCCESS",
                f"Non-SUCCESS event in detection_events.csv: {row!r}"
            )
        print(f"  --> PASS: P6.5-27 (detection_events.csv clean: {len(data_rows)} real event(s))")

    # -------------------------------------------------------------------------
    # P6.5-28: End-to-end env report JSON matches expected schema
    # -------------------------------------------------------------------------
    def test_P65_28_end_to_end_report_schema(self):
        """P6.5-28: Full env discovery report JSON has valid nested schema."""
        from ml.env_discovery import write_env_report, discover_packet_capture_environment
        out_path = write_env_report()
        with open(out_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        # Top-level structure
        self.assertIn("phase", report)
        self.assertEqual(report["phase"], "Phase 6.5")

        # platform_info sub-dict
        pinfo = report.get("platform_info", {})
        for key in ["os", "python_version"]:
            self.assertIn(key, pinfo, f"platform_info missing '{key}'")

        # npcap sub-dict
        npcap = report.get("npcap", {})
        self.assertIn("npcap_dll_found", npcap)
        self.assertIsInstance(npcap["npcap_dll_found"], bool)
        self.assertIn("npcap_dll_paths_checked", npcap)
        self.assertIsInstance(npcap["npcap_dll_paths_checked"], list)

        # privileges sub-dict
        priv = report.get("privileges", {})
        self.assertIn("is_admin", priv)
        self.assertIsInstance(priv["is_admin"], bool)

        # raw_socket sub-dict
        raw = report.get("raw_socket", {})
        self.assertIn("raw_socket_available", raw)
        self.assertIsInstance(raw["raw_socket_available"], bool)

        # capture_libraries sub-dict
        libs = report.get("capture_libraries", {})
        for key in ["scapy_available", "any_capture_library_available"]:
            self.assertIn(key, libs, f"capture_libraries missing '{key}'")
            self.assertIsInstance(libs[key], bool, f"'{key}' must be bool")

        # Status must be a valid string
        status = report.get("packet_capture_status", "")
        self.assertIn(status, {"BLOCKED", "PARTIAL", "AVAILABLE"})

        # cat_c_upgrade_path sub-dict
        upgrade = report.get("cat_c_upgrade_path", {})
        self.assertIn("cat_c_features_unlocked", upgrade)
        self.assertIsInstance(upgrade["cat_c_features_unlocked"], list)

        # In-memory and on-disk reports must agree
        live = discover_packet_capture_environment()
        self.assertEqual(
            report["packet_capture_status"],
            live["packet_capture_status"],
            "On-disk JSON status does not match in-memory report"
        )
        print(
            f"  --> PASS: P6.5-28 "
            f"(End-to-end report schema valid, status='{status}')"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
import json  # noqa: E402 (already imported at top, re-asserted for clarity)


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhase65Acceptance)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    print("\n" + "=" * 75)
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"TEST SUMMARY: {passed}/{result.testsRun} Tests Passed")
    print("=" * 75)
    if not result.wasSuccessful():
        sys.exit(1)
    print("\nALL PHASE 6.5 TEST CASES (P6.5-01 to P6.5-28) PASSED PERFECTLY!\n")


if __name__ == "__main__":
    main()
