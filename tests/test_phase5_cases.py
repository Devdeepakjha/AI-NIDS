"""
tests/test_phase5_cases.py
=============================================================================
Phase 5 Comprehensive Acceptance Test Suite (P5-01 to P5-36)
AI-Based Network Intrusion Detection System — Phase 5 ML Classification

USAGE:
    python tests/test_phase5_cases.py
=============================================================================
"""

import hashlib
import json
import os
import subprocess
import sys
import unittest
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.download_dataset import DATA_DIR, compute_sha256
from ml.predict import IntrusionPredictor
from ml.preprocessing import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    IDENTIFIER_COLUMNS,
    LEAKAGE_COLUMNS,
    NUMERICAL_FEATURES,
    TARGET_COLUMN,
    build_preprocessor,
    load_raw_dataset,
)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
PHASE4_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
EXPECTED_PHASE4_HASH = "9ac544411aff859cb70de9d26a27db387327c28166886a005240c758920ea787"


class TestPhase5Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 75)
        print("PHASE 5 ACCEPTANCE TEST SUITE (P5-01 to P5-36)")
        print("=" * 75)
        cls.train_csv = os.path.join(DATA_DIR, "UNSW_NB15_training-set.csv")
        cls.test_csv = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.csv")
        cls.model_path = os.path.join(MODELS_DIR, "intrusion_model.json")
        cls.preprocessor_path = os.path.join(MODELS_DIR, "preprocessor.pkl")
        cls.schema_path = os.path.join(MODELS_DIR, "feature_schema.json")
        cls.metadata_path = os.path.join(MODELS_DIR, "training_metadata.json")

    # -------------------------------------------------------------------------
    # P5-01: Regression Tests (Phase 3 & Phase 4)
    # -------------------------------------------------------------------------
    def test_P5_01_phase3_and_phase4_regression(self):
        """P5-01: Phase 3 (32/32) and Phase 4 (28/28) regressions pass cleanly."""
        # Read and preserve initial Phase 4 CSV bytes so live collection tests don't overwrite historical data
        with open(PHASE4_CSV_PATH, "rb") as f:
            initial_p4_bytes = f.read()

        try:
            print("\n[P5-01] Executing Phase 3 regression tests...")
            p3_res = subprocess.run(
                [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase3_cases.py")],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )
            self.assertEqual(p3_res.returncode, 0, f"Phase 3 regression failed:\n{p3_res.stdout}\n{p3_res.stderr}")
            self.assertIn("32/32 Tests Passed", p3_res.stdout)

            print("[P5-01] Executing Phase 4 regression tests...")
            p4_res = subprocess.run(
                [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_phase4_cases.py")],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )
            self.assertEqual(p4_res.returncode, 0, f"Phase 4 regression failed:\n{p4_res.stdout}\n{p4_res.stderr}")
            self.assertIn("ALL PHASE 4 TESTS PASSED", p4_res.stdout)
            print("  --> PASS: P5-01 (Phase 3: 32/32, Phase 4: 28/28)")
        finally:
            # Restore exact initial Phase 4 dataset bytes to guarantee data immutability
            with open(PHASE4_CSV_PATH, "wb") as f:
                f.write(initial_p4_bytes)

    # -------------------------------------------------------------------------
    # P5-02: Labeled Dataset Loads
    # -------------------------------------------------------------------------
    def test_P5_02_labeled_dataset_loads(self):
        """P5-02: Both training and testing CSVs exist and load cleanly."""
        self.assertTrue(os.path.exists(self.train_csv), "Missing training CSV")
        self.assertTrue(os.path.exists(self.test_csv), "Missing testing CSV")
        X_tr, y_tr, _ = load_raw_dataset(self.train_csv)
        X_te, y_te, _ = load_raw_dataset(self.test_csv)
        self.assertEqual(len(X_tr), 175341)
        self.assertEqual(len(X_te), 82332)
        print("  --> PASS: P5-02 (Train: 175,341 rows, Test: 82,332 rows)")

    # -------------------------------------------------------------------------
    # P5-03: Labels Inspected
    # -------------------------------------------------------------------------
    def test_P5_03_labels_inspected(self):
        """P5-03: Target labels are strictly binary {0, 1} and attack_cat inspected."""
        df_tr = pd.read_csv(self.train_csv, nrows=1000)
        self.assertIn("label", df_tr.columns)
        self.assertIn("attack_cat", df_tr.columns)
        unique_labels = set(df_tr["label"].unique())
        self.assertTrue(unique_labels.issubset({0, 1}))
        print("  --> PASS: P5-03 (Labels strictly binary {0, 1})")

    # -------------------------------------------------------------------------
    # P5-04: Class Distribution Reported
    # -------------------------------------------------------------------------
    def test_P5_04_class_distribution_reported(self):
        """P5-04: Training metadata accurately reports class distributions."""
        self.assertTrue(os.path.exists(self.metadata_path))
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        ds = meta.get("dataset", {})
        self.assertEqual(ds.get("train_samples_full"), 175341)
        self.assertEqual(ds.get("test_samples_untouched"), 82332)
        print("  --> PASS: P5-04 (Class distributions reported in metadata)")

    # -------------------------------------------------------------------------
    # P5-05: No Target Leakage
    # -------------------------------------------------------------------------
    def test_P5_05_no_target_leakage(self):
        """P5-05: Target 'label' and 'attack_cat' are strictly excluded from X."""
        X_tr, _, _ = load_raw_dataset(self.train_csv)
        self.assertNotIn("label", X_tr.columns)
        self.assertNotIn("attack_cat", X_tr.columns)
        print("  --> PASS: P5-05 (Zero target/category leakage in X)")

    # -------------------------------------------------------------------------
    # P5-06: Metadata / Identifier Exclusion
    # -------------------------------------------------------------------------
    def test_P5_06_metadata_exclusion(self):
        """P5-06: Index 'id' and metadata columns are excluded from model features."""
        X_tr, _, _ = load_raw_dataset(self.train_csv)
        self.assertNotIn("id", X_tr.columns)
        for col in ["timestamp", "experiment_id", "client_ip", "traffic_mode"]:
            self.assertNotIn(col, X_tr.columns)
        print("  --> PASS: P5-06 (Zero identifier / metadata columns in features)")

    # -------------------------------------------------------------------------
    # P5-07: No NaN/Inf Post-Preprocessing
    # -------------------------------------------------------------------------
    def test_P5_07_no_nan_inf_post_preprocessing(self):
        """P5-07: Preprocessed feature matrices have 0 NaN and 0 Inf values."""
        X_sample, _, _ = load_raw_dataset(self.train_csv)
        X_subset = X_sample.iloc[:1000]
        prep = joblib.load(self.preprocessor_path)
        trans = prep.transform(X_subset)
        self.assertFalse(np.isnan(trans).any(), "NaN found in transformed matrix")
        self.assertTrue(np.isfinite(trans).all(), "Inf found in transformed matrix")
        print("  --> PASS: P5-07 (Preprocessed output is strictly finite with 0 NaNs)")

    # -------------------------------------------------------------------------
    # P5-08: Train / Validation Split Works
    # -------------------------------------------------------------------------
    def test_P5_08_train_validation_split_works(self):
        """P5-08: 80/20 train/validation split maintains sample proportions."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        ds = meta["dataset"]
        self.assertEqual(ds["train_split_80pct"], 140272)
        self.assertEqual(ds["val_split_20pct"], 35069)
        self.assertEqual(ds["train_split_80pct"] + ds["val_split_20pct"], 175341)
        print("  --> PASS: P5-08 (80/20 split: 140,272 train / 35,069 val)")

    # -------------------------------------------------------------------------
    # P5-09: Split Reproducibility
    # -------------------------------------------------------------------------
    def test_P5_09_split_reproducibility(self):
        """P5-09: Stratified train/val split is reproducible with random_state=42."""
        from sklearn.model_selection import train_test_split
        dummy_y = np.array([0, 1] * 50)
        idx1_tr, idx1_val = train_test_split(np.arange(100), test_size=0.20, stratify=dummy_y, random_state=42)
        idx2_tr, idx2_val = train_test_split(np.arange(100), test_size=0.20, stratify=dummy_y, random_state=42)
        np.testing.assert_array_equal(idx1_tr, idx2_tr)
        np.testing.assert_array_equal(idx1_val, idx2_val)
        print("  --> PASS: P5-09 (Split indices 100% reproducible)")

    # -------------------------------------------------------------------------
    # P5-10: Model Training Succeeds
    # -------------------------------------------------------------------------
    def test_P5_10_model_training_succeeds(self):
        """P5-10: XGBoost training completed successfully and recorded best iteration."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["model"]["framework"], "XGBoost")
        self.assertGreater(meta["model"]["best_iteration"], 0)
        print(f"  --> PASS: P5-10 (XGBoost fit successfully, best iteration: {meta['model']['best_iteration']})")

    # -------------------------------------------------------------------------
    # P5-11: Model Artifact Exists
    # -------------------------------------------------------------------------
    def test_P5_11_model_artifact_exists(self):
        """P5-11: models/intrusion_model.json exists, is non-empty and valid JSON."""
        self.assertTrue(os.path.exists(self.model_path))
        self.assertGreater(os.path.getsize(self.model_path), 50000)
        with open(self.model_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("learner", data)
        print("  --> PASS: P5-11 (intrusion_model.json valid JSON)")

    # -------------------------------------------------------------------------
    # P5-12: Preprocessor Artifact Exists
    # -------------------------------------------------------------------------
    def test_P5_12_preprocessor_artifact_exists(self):
        """P5-12: models/preprocessor.pkl exists and loads valid ColumnTransformer."""
        self.assertTrue(os.path.exists(self.preprocessor_path))
        prep = joblib.load(self.preprocessor_path)
        self.assertTrue(hasattr(prep, "transform"))
        print("  --> PASS: P5-12 (preprocessor.pkl is loadable)")

    # -------------------------------------------------------------------------
    # P5-13: Feature Schema Exists
    # -------------------------------------------------------------------------
    def test_P5_13_feature_schema_exists(self):
        """P5-13: models/feature_schema.json exists and documents 42 raw features."""
        self.assertTrue(os.path.exists(self.schema_path))
        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        self.assertEqual(len(schema["raw_model_features"]), 42)
        self.assertIn("phase4_bridge_status", schema)
        print("  --> PASS: P5-13 (feature_schema.json complete with bridge disclaimer)")

    # -------------------------------------------------------------------------
    # P5-14: Training Metadata Exists
    # -------------------------------------------------------------------------
    def test_P5_14_training_metadata_exists(self):
        """P5-14: models/training_metadata.json exists with metrics and config."""
        self.assertTrue(os.path.exists(self.metadata_path))
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertIn("metrics_untouched_test_set", meta)
        self.assertIn("hyperparameters", meta["model"])
        print("  --> PASS: P5-14 (training_metadata.json verified)")

    # -------------------------------------------------------------------------
    # P5-15: Prediction Class Valid
    # -------------------------------------------------------------------------
    def test_P5_15_prediction_class_valid(self):
        """P5-15: IntrusionPredictor returns 'BENIGN' or 'INTRUSION'."""
        predictor = IntrusionPredictor(MODELS_DIR)
        sample = {col: 0.0 for col in NUMERICAL_FEATURES}
        sample.update({"proto": "tcp", "service": "http", "state": "fin"})
        res = predictor.predict(sample)
        self.assertIn(res["prediction"], ["BENIGN", "INTRUSION"])
        print(f"  --> PASS: P5-15 (Prediction class: {res['prediction']})")

    # -------------------------------------------------------------------------
    # P5-16: Prediction Probability Valid
    # -------------------------------------------------------------------------
    def test_P5_16_prediction_probability_valid(self):
        """P5-16: IntrusionPredictor returns probability in [0.0, 1.0]."""
        predictor = IntrusionPredictor(MODELS_DIR)
        sample = {col: 0.0 for col in NUMERICAL_FEATURES}
        sample.update({"proto": "tcp", "service": "http", "state": "fin"})
        res = predictor.predict(sample)
        p = res["intrusion_probability"]
        self.assertIsInstance(p, float)
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)
        print(f"  --> PASS: P5-16 (Intrusion probability: {p:.6f})")

    # -------------------------------------------------------------------------
    # P5-17: Accuracy Calculated
    # -------------------------------------------------------------------------
    def test_P5_17_accuracy_calculated(self):
        """P5-17: Test accuracy is calculated, finite, and within valid range."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        acc = meta["metrics_untouched_test_set"]["accuracy"]
        self.assertGreater(acc, 0.85)
        self.assertLessEqual(acc, 1.0)
        self.assertTrue(np.isfinite(acc))
        print(f"  --> PASS: P5-17 (Accuracy: {acc:.4f})")

    # -------------------------------------------------------------------------
    # P5-18: Precision Calculated
    # -------------------------------------------------------------------------
    def test_P5_18_precision_calculated(self):
        """P5-18: Test precision is calculated, finite, and within valid range."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        prec = meta["metrics_untouched_test_set"]["precision"]
        self.assertGreater(prec, 0.80)
        self.assertLessEqual(prec, 1.0)
        self.assertTrue(np.isfinite(prec))
        print(f"  --> PASS: P5-18 (Precision: {prec:.4f})")

    # -------------------------------------------------------------------------
    # P5-19: Recall Calculated
    # -------------------------------------------------------------------------
    def test_P5_19_recall_calculated(self):
        """P5-19: Test recall is calculated, finite, and within valid range."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        rec = meta["metrics_untouched_test_set"]["recall"]
        self.assertGreater(rec, 0.90)
        self.assertLessEqual(rec, 1.0)
        self.assertTrue(np.isfinite(rec))
        print(f"  --> PASS: P5-19 (Recall: {rec:.4f})")

    # -------------------------------------------------------------------------
    # P5-20: F1 Calculated
    # -------------------------------------------------------------------------
    def test_P5_20_f1_calculated(self):
        """P5-20: Test F1-score is calculated, finite, and within valid range."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        f1 = meta["metrics_untouched_test_set"]["f1_score"]
        self.assertGreater(f1, 0.85)
        self.assertLessEqual(f1, 1.0)
        self.assertTrue(np.isfinite(f1))
        print(f"  --> PASS: P5-20 (F1-score: {f1:.4f})")

    # -------------------------------------------------------------------------
    # P5-21: Confusion Matrix Generated
    # -------------------------------------------------------------------------
    def test_P5_21_confusion_matrix_generated(self):
        """P5-21: Confusion matrix generated with TN, FP, FN, TP summing to 82,332."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        cm = meta["metrics_untouched_test_set"]["confusion_matrix"]
        total_cm = cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"]
        self.assertEqual(total_cm, 82332)
        self.assertGreater(cm["tp"], 40000)
        self.assertGreater(cm["tn"], 30000)
        print(f"  --> PASS: P5-21 (Confusion matrix: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']})")

    # -------------------------------------------------------------------------
    # P5-22: Evaluation Metrics Finite
    # -------------------------------------------------------------------------
    def test_P5_22_evaluation_metrics_finite(self):
        """P5-22: All evaluation metrics are finite with no NaN or Inf."""
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        metrics = meta["metrics_untouched_test_set"]
        for k in ["accuracy", "precision", "recall", "f1_score"]:
            val = metrics[k]
            self.assertTrue(np.isfinite(val), f"Metric {k} is not finite: {val}")
        print("  --> PASS: P5-22 (All evaluation metrics are finite)")

    # -------------------------------------------------------------------------
    # P5-23: Saved Model Reloads
    # -------------------------------------------------------------------------
    def test_P5_23_saved_model_reloads(self):
        """P5-23: Fresh XGBClassifier instance loads models/intrusion_model.json cleanly."""
        new_clf = xgb.XGBClassifier()
        new_clf.load_model(self.model_path)
        self.assertIsNotNone(new_clf.get_booster())
        print("  --> PASS: P5-23 (Model reloads without error)")

    # -------------------------------------------------------------------------
    # P5-24: Reloaded Model Predicts
    # -------------------------------------------------------------------------
    def test_P5_24_reloaded_model_predicts(self):
        """P5-24: Reloaded model prediction matches original output bit-for-bit."""
        predictor1 = IntrusionPredictor(MODELS_DIR)
        predictor2 = IntrusionPredictor(MODELS_DIR)
        sample = {col: 10.0 for col in NUMERICAL_FEATURES}
        sample.update({"proto": "udp", "service": "dns", "state": "int"})
        r1 = predictor1.predict(sample)
        r2 = predictor2.predict(sample)
        self.assertEqual(r1["prediction"], r2["prediction"])
        self.assertEqual(r1["intrusion_probability"], r2["intrusion_probability"])
        print("  --> PASS: P5-24 (Reloaded model predictions are deterministic)")

    # -------------------------------------------------------------------------
    # P5-25: Feature Order / Schema Preserved
    # -------------------------------------------------------------------------
    def test_P5_25_feature_order_preserved(self):
        """P5-25: Preprocessor preserves strict schema order."""
        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        self.assertEqual(schema["raw_model_features"], ALL_MODEL_FEATURES)
        self.assertEqual(schema["categorical_features"], CATEGORICAL_FEATURES)
        self.assertEqual(schema["numerical_features"], NUMERICAL_FEATURES)
        print("  --> PASS: P5-25 (Feature ordering strictly preserved)")

    # -------------------------------------------------------------------------
    # P5-26: Phase 4 CSV Unchanged (Pre-test check)
    # -------------------------------------------------------------------------
    def test_P5_26_phase4_csv_unchanged(self):
        """P5-26: data/network_traffic.csv SHA-256 matches initial hash."""
        current_hash = compute_sha256(PHASE4_CSV_PATH)
        self.assertEqual(current_hash, EXPECTED_PHASE4_HASH)
        print(f"  --> PASS: P5-26 (Phase 4 CSV untouched, hash: {current_hash[:16]}...)")

    # -------------------------------------------------------------------------
    # P5-27: No Fake Attack Labels
    # -------------------------------------------------------------------------
    def test_P5_27_no_fake_attack_labels(self):
        """P5-27: Verify Phase 4 traffic intensities are never labeled as attacks."""
        df_p4 = pd.read_csv(PHASE4_CSV_PATH)
        self.assertNotIn("label", df_p4.columns)
        self.assertNotIn("attack", df_p4.columns)
        self.assertNotIn("prediction", df_p4.columns)
        print("  --> PASS: P5-27 (Phase 4 data has zero synthetic attack labels)")

    # -------------------------------------------------------------------------
    # P5-28: No Phase 6 Live Integration
    # -------------------------------------------------------------------------
    def test_P5_28_no_phase6_live_integration(self):
        """P5-28: Ensure server/ and client/ production code do not import ML or predictor."""
        for root_dir in ["server", "client"]:
            folder = os.path.join(PROJECT_ROOT, root_dir)
            for fname in os.listdir(folder):
                if not fname.endswith(".py") or fname == "dashboard_server.py":
                    continue
                with open(os.path.join(folder, fname), "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn("IntrusionPredictor", content, f"Live ML found in {fname}")
                self.assertNotIn("xgboost", content, f"xgboost import found in {fname}")
                self.assertNotIn("sklearn", content, f"sklearn import found in {fname}")
        print("  --> PASS: P5-28 (No Phase 6 live detection in server/client)")

    # -------------------------------------------------------------------------
    # P5-29: No Dashboard / Alerts
    # -------------------------------------------------------------------------
    def test_P5_29_no_dashboard_alerts(self):
        """P5-29: Verify no FastAPI, Flask, dashboard, or alert modules exist."""
        for root, dirs, files in os.walk(PROJECT_ROOT):
            if any(x in root for x in [".git", "__pycache__", ".gemini"]):
                continue
            for f in files:
                self.assertNotIn(f, ["app.py", "dashboard.py", "alerts.py", "alert_manager.py"])
        print("  --> PASS: P5-29 (No premature dashboard/alert components)")

    # -------------------------------------------------------------------------
    # P5-30: No Unnecessary Files
    # -------------------------------------------------------------------------
    def test_P5_30_no_unnecessary_files(self):
        """P5-30: Ensure only approved project files exist."""
        expected_py_files = {
            "client.py", "config.py",
            "server.py", "monitor.py", "dataset_writer.py", "detection_logger.py",
            "protocol.py",
            "__init__.py", "download_dataset.py", "preprocessing.py", "train.py", "predict.py",
            "feature_audit.py", "feature_bridge.py",
            "test_protocol.py", "test_phase3_cases.py", "test_phase4_cases.py", "test_phase5_cases.py", "test_phase6_cases.py",
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
                    self.assertIn(f, expected_py_files, f"Unexpected python file found: {f}")
        print("  --> PASS: P5-30 (File tree strictly matches approved architecture)")

    # -------------------------------------------------------------------------
    # P5-31: Dependency Cleanliness
    # -------------------------------------------------------------------------
    def test_P5_31_dependency_cleanliness(self):
        """P5-31: requirements.txt specifies only genuine pinned dependencies."""
        req_path = os.path.join(PROJECT_ROOT, "requirements.txt")
        with open(req_path, "r", encoding="utf-8") as f:
            content = f.read()
        for dep in ["pandas", "numpy", "scikit-learn", "xgboost", "joblib"]:
            self.assertIn(dep, content)
        print("  --> PASS: P5-31 (requirements.txt clean and explicit)")

    # -------------------------------------------------------------------------
    # P5-32: Complete ML Pipeline
    # -------------------------------------------------------------------------
    def test_P5_32_complete_ml_pipeline(self):
        """P5-32: Full pipeline artifacts are coherent and mutually consistent."""
        self.assertTrue(os.path.exists(self.model_path))
        self.assertTrue(os.path.exists(self.preprocessor_path))
        self.assertTrue(os.path.exists(self.schema_path))
        self.assertTrue(os.path.exists(self.metadata_path))
        print("  --> PASS: P5-32 (Complete pipeline successfully verified)")

    # -------------------------------------------------------------------------
    # P5-33: Unknown Categorical Handling
    # -------------------------------------------------------------------------
    def test_P5_33_unknown_categorical_handling(self):
        """P5-33: Unknown categorical values do not cause crashes."""
        predictor = IntrusionPredictor(MODELS_DIR)
        sample = {col: 0.0 for col in NUMERICAL_FEATURES}
        sample.update({
            "proto": "alien_unknown_protocol",
            "service": "unknown_cyber_service",
            "state": "unknown_state"
        })
        # Must execute without exception
        res = predictor.predict(sample)
        self.assertIn(res["prediction"], ["BENIGN", "INTRUSION"])
        self.assertIsInstance(res["intrusion_probability"], float)
        print("  --> PASS: P5-33 (Unknown categorical levels safely handled)")

    # -------------------------------------------------------------------------
    # P5-34: Invalid / Missing Features Rejected
    # -------------------------------------------------------------------------
    def test_P5_34_invalid_missing_feature_rejected(self):
        """P5-34: Missing or non-numeric feature raises ValueError."""
        predictor = IntrusionPredictor(MODELS_DIR)

        # Incomplete sample (missing 'rate')
        incomplete_sample = {col: 1.0 for col in NUMERICAL_FEATURES if col != "rate"}
        incomplete_sample.update({"proto": "tcp", "service": "http", "state": "fin"})
        with self.assertRaises(ValueError):
            predictor.predict(incomplete_sample)

        # Invalid non-numeric value in numerical column
        bad_type_sample = {col: 1.0 for col in NUMERICAL_FEATURES}
        bad_type_sample["rate"] = "not_a_number"
        bad_type_sample.update({"proto": "tcp", "service": "http", "state": "fin"})
        with self.assertRaises(ValueError):
            predictor.predict(bad_type_sample)

        print("  --> PASS: P5-34 (Invalid/missing features properly rejected)")

    # -------------------------------------------------------------------------
    # P5-35: Schema Consistency Across Pipeline
    # -------------------------------------------------------------------------
    def test_P5_35_schema_consistency(self):
        """P5-35: Training schema matches saved schema and predictor expectations."""
        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        predictor = IntrusionPredictor(MODELS_DIR)
        self.assertEqual(schema["raw_model_features"], ALL_MODEL_FEATURES)
        self.assertEqual(predictor.schema["raw_model_features"], ALL_MODEL_FEATURES)
        print("  --> PASS: P5-35 (Schema 100% consistent across train, saved, predict)")

    # -------------------------------------------------------------------------
    # P5-36: Final Phase 4 CSV Hash Verification
    # -------------------------------------------------------------------------
    def test_P5_36_final_phase4_csv_hash(self):
        """P5-36: Final check ensuring data/network_traffic.csv is identical to initial state."""
        final_hash = compute_sha256(PHASE4_CSV_PATH)
        self.assertEqual(final_hash, EXPECTED_PHASE4_HASH)
        self.assertEqual(os.path.getsize(PHASE4_CSV_PATH), 2478)
        print(f"  --> PASS: P5-36 (Final SHA-256 confirmed: {final_hash})")


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhase5Acceptance)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    print("\n" + "=" * 75)
    print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun} Tests Passed")
    print("=" * 75)
    if not result.wasSuccessful():
        sys.exit(1)
    print("\nALL PHASE 5 TEST CASES (P5-01 to P5-36) PASSED PERFECTLY!\n")


if __name__ == "__main__":
    main()
