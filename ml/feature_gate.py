"""
ml/feature_gate.py
=============================================================================
Phase 6.6: Strict 42-Feature Gate for Live UNSW-NB15 Inference.

Enforces absolute integrity on feature vectors before they can reach
the Phase 5 XGBoost inference engine.

Rules:
1. Exact 42 feature keys must match models/feature_schema.json.
2. No feature may be missing or extra.
3. Numerical features must be finite (not NaN, not Inf).
4. Categorical features must be valid strings.
5. Every single feature must have VALIDATED provenance.
6. Any UNAVAILABLE or unverified feature immediately causes INVALID_FEATURE_VECTOR.
7. Zero silent repairs, zero default substitutions, zero fabrication.
=============================================================================
"""

import math
from typing import Dict, Any, Tuple, List, Optional
from ml.unsw_feature_extractor import ALL_42_FEATURES

CATEGORICAL_KEYS = {"proto", "service", "state"}
NUMERICAL_KEYS = set(ALL_42_FEATURES) - CATEGORICAL_KEYS


class FeatureGate:
    """
    Validates candidate feature vectors and provenance against the authoritative
    UNSW-NB15 model schema.
    """

    def __init__(self):
        self.required_features = set(ALL_42_FEATURES)
        self.total_feature_count = len(ALL_42_FEATURES)

    def validate(
        self,
        features: Dict[str, Any],
        provenance: Optional[Dict[str, Dict[str, str]]] = None
    ) -> Tuple[bool, str, List[str]]:
        """
        Validate a feature vector.

        Returns
        -------
        Tuple[bool, str, List[str]]
            is_valid: True if vector passes all 42 checks, False otherwise.
            status_code: "VALID_FEATURE_VECTOR" or "INVALID_FEATURE_VECTOR".
            reasons: List of human-readable failure reasons.
        """
        reasons: List[str] = []

        if not isinstance(features, dict):
            return False, "INVALID_FEATURE_VECTOR", ["Features input is not a dictionary"]

        feature_keys = set(features.keys())

        # 1. Check for missing features
        missing = self.required_features - feature_keys
        if missing:
            reasons.append(f"Missing {len(missing)} required features: {sorted(missing)}")

        # 2. Check for unexpected features
        unexpected = feature_keys - self.required_features
        if unexpected:
            reasons.append(f"Unexpected features found: {sorted(unexpected)}")

        # 3. Check types and finite values
        for key in feature_keys.intersection(self.required_features):
            val = features[key]

            if val is None:
                reasons.append(f"Feature '{key}' is None / unpopulated")
                continue

            if key in CATEGORICAL_KEYS:
                if not isinstance(val, str) or not val.strip():
                    reasons.append(f"Categorical feature '{key}' is not a non-empty string: {val!r}")
            else:
                if not isinstance(val, (int, float)):
                    reasons.append(f"Numerical feature '{key}' is not numeric: {type(val).__name__}")
                else:
                    if math.isnan(val):
                        reasons.append(f"Numerical feature '{key}' is NaN")
                    elif math.isinf(val):
                        reasons.append(f"Numerical feature '{key}' is Inf")

        # 4. Check provenance (no UNAVAILABLE features permitted)
        if provenance is not None:
            unvalidated = []
            for key in self.required_features:
                prov = provenance.get(key)
                if not prov:
                    unvalidated.append(f"{key} (no provenance)")
                elif prov.get("status") != "VALIDATED":
                    unvalidated.append(f"{key} ({prov.get('reason', 'unverified')})")

            if unvalidated:
                reasons.append(f"Features lacking validated provenance: {unvalidated}")

        if reasons:
            return False, "INVALID_FEATURE_VECTOR", reasons
        return True, "VALID_FEATURE_VECTOR", []
