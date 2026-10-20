"""
ml/predict.py
=============================================================================
Reusable IntrusionPredictor interface.
Loads saved artifacts from models/ and provides single-sample / batch
prediction capabilities.

Prediction interface requirements:
- validate required features
- reject missing features
- reject invalid values where appropriate
- handle unknown categorical values safely
- preserve schema
- validate probability range [0, 1]
- use the saved preprocessing artifact
- use the saved model
- never silently invent missing features
=============================================================================
"""

import json
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from ml.preprocessing import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
    clean_dataframe,
)


class IntrusionPredictor:
    """
    Inference interface for the trained Network Intrusion Detection model.
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = os.path.abspath(model_dir)
        self.model_path = os.path.join(self.model_dir, "intrusion_model.json")
        self.preprocessor_path = os.path.join(self.model_dir, "preprocessor.pkl")
        self.schema_path = os.path.join(self.model_dir, "feature_schema.json")

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model artifact not found at: {self.model_path}")
        if not os.path.exists(self.preprocessor_path):
            raise FileNotFoundError(f"Preprocessor artifact not found at: {self.preprocessor_path}")
        if not os.path.exists(self.schema_path):
            raise FileNotFoundError(f"Schema artifact not found at: {self.schema_path}")

        # Load feature schema
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

        # Load preprocessor
        self.preprocessor = joblib.load(self.preprocessor_path)

        # Load XGBoost model
        self.model = xgb.XGBClassifier()
        self.model.load_model(self.model_path)

    def validate_features(self, features: dict) -> None:
        """
        Validates that all required 42 features are present and numerical types are valid.
        Raises ValueError if any feature is missing or invalid.
        """
        if not isinstance(features, dict):
            raise TypeError(f"Features must be a dictionary, got {type(features).__name__}")

        # Check for missing features
        missing = [f for f in ALL_MODEL_FEATURES if f not in features]
        if missing:
            raise ValueError(f"Missing required model features ({len(missing)} missing): {missing}")

        # Validate numerical features are convertible to float and not NaN
        for col in NUMERICAL_FEATURES:
            val = features[col]
            if val is None:
                raise ValueError(f"Numerical feature '{col}' cannot be None")
            try:
                fval = float(val)
                if np.isnan(fval):
                    raise ValueError(f"Numerical feature '{col}' cannot be NaN")
            except (ValueError, TypeError):
                raise ValueError(f"Numerical feature '{col}' has invalid non-numeric value: {val!r}")

    def predict(self, features: dict) -> dict:
        """
        Performs inference on a single observation.
        
        Args:
            features: Dictionary containing all 42 required raw UNSW-NB15 features.
            
        Returns:
            {
                "prediction": "BENIGN" or "INTRUSION",
                "intrusion_probability": float in [0.0, 1.0]
            }
        """
        self.validate_features(features)

        # Convert dictionary to DataFrame with single row matching schema order
        row_dict = {col: [features[col]] for col in ALL_MODEL_FEATURES}
        df_row = pd.DataFrame(row_dict)
        df_row = clean_dataframe(df_row)

        # Preprocess features
        X_trans = self.preprocessor.transform(df_row)

        # Predict probability of intrusion (class 1)
        prob_array = self.model.predict_proba(X_trans)
        intrusion_prob = float(prob_array[0, 1])

        # Validate probability range
        if not (0.0 <= intrusion_prob <= 1.0):
            raise ValueError(f"Invalid probability produced: {intrusion_prob}")

        pred_label = "INTRUSION" if intrusion_prob >= 0.5 else "BENIGN"

        return {
            "prediction": pred_label,
            "intrusion_probability": round(intrusion_prob, 6)
        }
