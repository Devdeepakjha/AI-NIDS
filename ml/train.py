"""
ml/train.py
=============================================================================
Phase 5 ML Training & Evaluation Pipeline:
- Loads UNSW-NB15 training & testing datasets
- Validates labels and reports class distributions
- Enforces strict official train/test separation
- Performs 80/20 stratified train/validation split on the training set
- Fits preprocessing pipeline ONLY on the training split
- Trains XGBoost binary classifier with scale_pos_weight
- Evaluates on untouched official test set (Accuracy, Precision, Recall, F1, Confusion Matrix)
- Persists model artifacts:
    models/intrusion_model.json
    models/preprocessor.pkl
    models/feature_schema.json
    models/training_metadata.json
- Verifies model reload & prediction consistency
=============================================================================
"""

import json
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import time
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import xgboost as xgb

from ml.download_dataset import DATA_DIR, compute_sha256
from ml.preprocessing import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    IDENTIFIER_COLUMNS,
    LEAKAGE_COLUMNS,
    NUMERICAL_FEATURES,
    TARGET_COLUMN,
    build_preprocessor,
    get_feature_schema_dict,
    load_raw_dataset,
)

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))


def run_training_pipeline():
    start_time = time.time()
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("=" * 75)
    print("AI-NIDS PROJECT — PHASE 5: ML INTRUSION CLASSIFIER TRAINING")
    print("=" * 75)

    # 1. Dataset Paths
    train_csv = os.path.join(DATA_DIR, "UNSW_NB15_training-set.csv")
    test_csv = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.csv")

    if not os.path.exists(train_csv) or not os.path.exists(test_csv):
        raise FileNotFoundError(
            f"Dataset files missing in {DATA_DIR}. Run `python ml/download_dataset.py` first."
        )

    train_sha = compute_sha256(train_csv)
    test_sha = compute_sha256(test_csv)
    print(f"[DATASET] Training Set: {train_csv}")
    print(f"          SHA-256:     {train_sha}")
    print(f"[DATASET] Testing Set:  {test_csv}")
    print(f"          SHA-256:     {test_sha}")

    # 2. Load Raw Datasets
    print("\n[STEP 1] Loading raw CSV datasets...")
    X_train_full, y_train_full, df_train_raw = load_raw_dataset(train_csv)
    X_test_final, y_test_final, df_test_raw = load_raw_dataset(test_csv)

    print(f"  Training CSV Records: {len(X_train_full):,}")
    print(f"  Testing CSV Records:  {len(X_test_final):,}")
    print(f"  Raw Model Features:   {len(ALL_MODEL_FEATURES)} ({len(CATEGORICAL_FEATURES)} categorical, {len(NUMERICAL_FEATURES)} numerical)")

    # 3. Label & Class Distribution Inspection
    print("\n[STEP 2] Inspecting Class Distributions...")
    unique_labels_train = set(np.unique(y_train_full))
    unique_labels_test = set(np.unique(y_test_final))
    assert unique_labels_train == {0, 1}, f"Unexpected training labels: {unique_labels_train}"
    assert unique_labels_test == {0, 1}, f"Unexpected testing labels: {unique_labels_test}"

    benign_train = int(np.sum(y_train_full == 0))
    intrusion_train = int(np.sum(y_train_full == 1))
    total_train = len(y_train_full)

    benign_test = int(np.sum(y_test_final == 0))
    intrusion_test = int(np.sum(y_test_final == 1))
    total_test = len(y_test_final)

    print(f"  Training Split:")
    print(f"    Total:     {total_train:,}")
    print(f"    Benign:    {benign_train:,} ({benign_train / total_train * 100:.2f}%)")
    print(f"    Intrusion: {intrusion_train:,} ({intrusion_train / total_train * 100:.2f}%)")
    print(f"  Testing Set (Untouched Benchmark):")
    print(f"    Total:     {total_test:,}")
    print(f"    Benign:    {benign_test:,} ({benign_test / total_test * 100:.2f}%)")
    print(f"    Intrusion: {intrusion_test:,} ({intrusion_test / total_test * 100:.2f}%)")

    # 4. Train / Validation Split on Training Set (80% Train, 20% Val)
    print("\n[STEP 3] Performing Stratified Train/Validation Split (80/20)...")
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.20,
        stratify=y_train_full,
        random_state=42
    )

    n_benign_sub = int(np.sum(y_train == 0))
    n_intrusion_sub = int(np.sum(y_train == 1))
    scale_pos_weight = float(n_benign_sub / n_intrusion_sub)
    print(f"  Train Split:      {len(X_train):,} samples (Benign: {n_benign_sub:,}, Intrusion: {n_intrusion_sub:,})")
    print(f"  Validation Split: {len(X_val):,} samples")
    print(f"  Calculated scale_pos_weight: {scale_pos_weight:.4f}")

    # 5. Fit Preprocessing Pipeline ONLY on Training Data
    print("\n[STEP 4] Fitting Preprocessor on Training Split...")
    preprocessor = build_preprocessor()
    X_train_trans = preprocessor.fit_transform(X_train)
    X_val_trans = preprocessor.transform(X_val)
    X_test_trans = preprocessor.transform(X_test_final)

    transformed_dim = X_train_trans.shape[1]
    print(f"  Transformed Feature Dimension: {transformed_dim} columns")

    # Verify no NaN or Inf
    assert not np.isnan(X_train_trans).any(), "NaN found in X_train_trans"
    assert not np.isnan(X_val_trans).any(), "NaN found in X_val_trans"
    assert not np.isnan(X_test_trans).any(), "NaN found in X_test_trans"
    assert np.isfinite(X_train_trans).all(), "Inf found in X_train_trans"
    assert np.isfinite(X_val_trans).all(), "Inf found in X_val_trans"
    assert np.isfinite(X_test_trans).all(), "Inf found in X_test_trans"
    print("  [OK] Zero NaN / Inf values in preprocessed matrices.")

    # 6. Train XGBoost Binary Classifier
    print("\n[STEP 5] Training XGBoost Binary Classifier...")
    model_params = {
        "n_estimators": 200,
        "max_depth": 6,
        "learning_rate": 0.1,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "scale_pos_weight": scale_pos_weight,
        "random_state": 42,
        "n_jobs": -1,
        "tree_method": "hist",
        "early_stopping_rounds": 15,
    }

    clf = xgb.XGBClassifier(**model_params)
    clf.fit(
        X_train_trans,
        y_train,
        eval_set=[(X_val_trans, y_val)],
        verbose=50
    )
    best_iteration = clf.best_iteration if hasattr(clf, "best_iteration") else 200
    print(f"  Training finished. Best iteration: {best_iteration}")

    # 7. Evaluate on UNTOUCHED Official Test Set
    print("\n[STEP 6] Evaluating on Official Untouched Test Set...")
    y_test_pred = clf.predict(X_test_trans)
    y_test_proba = clf.predict_proba(X_test_trans)[:, 1]

    acc = float(accuracy_score(y_test_final, y_test_pred))
    prec = float(precision_score(y_test_final, y_test_pred, zero_division=0))
    rec = float(recall_score(y_test_final, y_test_pred, zero_division=0))
    f1 = float(f1_score(y_test_final, y_test_pred, zero_division=0))
    cm = confusion_matrix(y_test_final, y_test_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("=" * 55)
    print("OFFICIAL TEST SET EVALUATION METRICS (82,332 samples)")
    print("=" * 55)
    print(f"  Accuracy:         {acc:.4f} ({acc * 100:.2f}%)")
    print(f"  Precision:        {prec:.4f} ({prec * 100:.2f}%)")
    print(f"  Recall:           {rec:.4f} ({rec * 100:.2f}%)")
    print(f"  F1-Score:         {f1:.4f} ({f1 * 100:.2f}%)")
    print("-" * 55)
    print(f"  Confusion Matrix:")
    print(f"    True Negatives (TN):   {tn:6d}  [Correctly identified Benign]")
    print(f"    False Positives (FP):  {fp:6d}  [Benign flagged as Intrusion]")
    print(f"    False Negatives (FN):  {fn:6d}  [CRITICAL: Missed Intrusion]")
    print(f"    True Positives (TP):   {tp:6d}  [Correctly caught Intrusion]")
    print("=" * 55)

    # 8. Save Artifacts
    print("\n[STEP 7] Persisting Model Artifacts to models/...")
    model_path = os.path.join(MODELS_DIR, "intrusion_model.json")
    preprocessor_path = os.path.join(MODELS_DIR, "preprocessor.pkl")
    schema_path = os.path.join(MODELS_DIR, "feature_schema.json")
    metadata_path = os.path.join(MODELS_DIR, "training_metadata.json")

    # A. Save model
    clf.save_model(model_path)
    print(f"  Saved XGBoost model: {model_path} ({os.path.getsize(model_path):,} bytes)")

    # B. Save preprocessor
    joblib.dump(preprocessor, preprocessor_path)
    print(f"  Saved Preprocessor:  {preprocessor_path} ({os.path.getsize(preprocessor_path):,} bytes)")

    # C. Save feature schema
    schema_dict = get_feature_schema_dict(preprocessor)
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema_dict, f, indent=2)
    print(f"  Saved Feature Schema: {schema_path}")

    # D. Save training metadata
    metadata_dict = {
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(time.time() - start_time, 2),
        "dataset": {
            "name": "UNSW-NB15",
            "source": "ACCS / UNSW Canberra Cyber via HuggingFace mirror Mouwiya/UNSW-NB15-small",
            "training_file": "UNSW_NB15_training-set.csv",
            "training_sha256": train_sha,
            "testing_file": "UNSW_NB15_testing-set.csv",
            "testing_sha256": test_sha,
            "total_samples": total_train + total_test,
            "train_samples_full": total_train,
            "test_samples_untouched": total_test,
            "train_split_80pct": len(X_train),
            "val_split_20pct": len(X_val)
        },
        "features": {
            "raw_feature_count": len(ALL_MODEL_FEATURES),
            "categorical_features": CATEGORICAL_FEATURES,
            "numerical_features": NUMERICAL_FEATURES,
            "excluded_leakage": LEAKAGE_COLUMNS,
            "excluded_identifier": IDENTIFIER_COLUMNS,
            "transformed_feature_count": transformed_dim
        },
        "model": {
            "framework": "XGBoost",
            "version": xgb.__version__,
            "hyperparameters": model_params,
            "best_iteration": int(best_iteration),
            "scale_pos_weight": round(scale_pos_weight, 4)
        },
        "metrics_untouched_test_set": {
            "accuracy": round(acc, 6),
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "f1_score": round(f1, 6),
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            }
        },
        "phase6_bridge_status": "NOT IMPLEMENTED in Phase 5."
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)
    print(f"  Saved Training Metadata: {metadata_path}")

    # 9. Model Reload Verification
    print("\n[STEP 8] Verifying Model Reload and Determinism...")
    reloaded_clf = xgb.XGBClassifier()
    reloaded_clf.load_model(model_path)
    sample_sub = X_test_trans[:100]
    preds_original = clf.predict_proba(sample_sub)
    preds_reloaded = reloaded_clf.predict_proba(sample_sub)
    diff = np.max(np.abs(preds_original - preds_reloaded))
    assert diff < 1e-6, f"Reloaded model outputs differ by {diff}!"
    print(f"  [OK] Reload verification passed! Max prediction difference: {diff:.2e}")

    print("\n" + "=" * 75)
    print("PHASE 5 MODEL TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 75)
    return metadata_dict


if __name__ == "__main__":
    run_training_pipeline()
