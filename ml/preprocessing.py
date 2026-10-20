"""
ml/preprocessing.py
=============================================================================
Defines the schema and preprocessing pipeline for the UNSW-NB15 dataset.
Implements leak-free preprocessing:
- Numerical median imputation (replaces Inf/NaN)
- Categorical imputation + OneHotEncoder(handle_unknown="ignore")
- Fitted exclusively on training data
=============================================================================
"""

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

# Identifier / Index column to drop (prevent sequential leakage)
IDENTIFIER_COLUMNS = ["id"]

# Target column definition
TARGET_COLUMN = "label"

# Label-derived leakage column to drop
LEAKAGE_COLUMNS = ["attack_cat"]

# Categorical input features
CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "state",
]

# 39 Numerical input features
NUMERICAL_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src",
    "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
]

ALL_MODEL_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans DataFrame:
    - Strips whitespace from string/column headers
    - Replaces positive/negative infinities with NaN in numerical columns
    """
    df = df.copy()
    # Strip potential whitespace/BOM in column names
    df.columns = [c.strip().replace('\ufeff', '') for c in df.columns]

    # Replace Inf with NaN in numerical columns
    for col in NUMERICAL_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)

    # Clean string columns
    for col in CATEGORICAL_FEATURES:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.lower()

    return df


def load_raw_dataset(csv_path: str):
    """
    Loads raw CSV and returns (X, y, df_clean).
    X contains only the 42 model features (no id, attack_cat, or label).
    y contains the binary integer target.
    """
    df = pd.read_csv(csv_path, low_memory=False)
    df = clean_dataframe(df)

    # Validate target presence
    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Target column '{TARGET_COLUMN}' not found in {csv_path}")

    # Separate X and y
    y = df[TARGET_COLUMN].astype(int).to_numpy()

    # Drop target, leakage, and identifier columns
    drop_cols = set(IDENTIFIER_COLUMNS + LEAKAGE_COLUMNS + [TARGET_COLUMN])
    available_cols = [c for c in df.columns if c not in drop_cols]

    # Verify all 42 model features are present
    missing_features = [f for f in ALL_MODEL_FEATURES if f not in available_cols]
    if missing_features:
        raise ValueError(f"Missing required model features in {csv_path}: {missing_features}")

    X = df[ALL_MODEL_FEATURES].copy()
    return X, y, df


def build_preprocessor() -> ColumnTransformer:
    """
    Constructs an unfitted ColumnTransformer:
    - Numerical: SimpleImputer(median)
    - Categorical: SimpleImputer(constant) -> OneHotEncoder(ignore unknown)
    """
    num_pipeline = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
    ])

    cat_pipeline = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", num_pipeline, NUMERICAL_FEATURES),
            ("cat", cat_pipeline, CATEGORICAL_FEATURES),
        ],
        remainder="drop"
    )
    return preprocessor


def get_feature_schema_dict(preprocessor: ColumnTransformer = None) -> dict:
    """
    Returns the schema specification dictionary for models/feature_schema.json.
    """
    transformed_feature_names = []
    if preprocessor is not None and hasattr(preprocessor, "get_feature_names_out"):
        transformed_feature_names = list(preprocessor.get_feature_names_out())

    return {
        "dataset_name": "UNSW-NB15",
        "raw_model_features": ALL_MODEL_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "numerical_features": NUMERICAL_FEATURES,
        "excluded_leakage_columns": LEAKAGE_COLUMNS,
        "excluded_identifier_columns": IDENTIFIER_COLUMNS,
        "target_column": TARGET_COLUMN,
        "label_mapping": {
            "0": "BENIGN",
            "1": "INTRUSION"
        },
        "transformed_feature_count": len(transformed_feature_names),
        "transformed_feature_names": transformed_feature_names,
        "phase4_bridge_status": "NOT IMPLEMENTED in Phase 5. Live feature extraction and bridging to the model feature vector belongs to Phase 6."
    }
