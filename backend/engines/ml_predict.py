"""
PhishLens — ML Prediction Engine

Loads the trained baseline model (Random Forest) ONCE at module import
time and provides a predict_ml() function for real-time inference.

The model file is loaded from ml/models/baseline_model.pkl and the
StandardScaler from ml/models/baseline_scaler.pkl.

No imports from database.py, models.py, or schemas.py.
"""

import time
from pathlib import Path

import joblib
import numpy as np
from loguru import logger

# ──────────────────────────────────────────────────────────────────────
# Load model + scaler ONCE at import time (not on every call)
# ──────────────────────────────────────────────────────────────────────
_MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "ml" / "models"
_MODEL_PATH = _MODEL_DIR / "baseline_model.pkl"
_SCALER_PATH = _MODEL_DIR / "baseline_scaler.pkl"

# The exact features the model expects, in order
EXPECTED_FEATURES = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "entropy_score",
    "has_suspicious_keywords",
    "has_punycode_or_homoglyph",
    "lexical_score",
]

MODEL_VERSION = "baseline_lexical_v1"
MODEL_NAME = "RandomForest"

# Load at import time — if the model files don't exist, log a warning
# and set to None so predict_ml can return a graceful fallback.
try:
    _model = joblib.load(_MODEL_PATH)
    _scaler = joblib.load(_SCALER_PATH)
    logger.info("[ML] Loaded model from {} (version: {})", _MODEL_PATH.name, MODEL_VERSION)
except Exception as e:
    logger.warning("[ML] Could not load model: {} — ML predictions will be disabled", e)
    _model = None
    _scaler = None


def predict_ml(lexical_features: dict) -> dict:
    """
    Run the trained ML model on lexical features and return a prediction.

    Parameters
    ----------
    lexical_features : dict
        The output of analyze_lexical() — must contain all keys in
        EXPECTED_FEATURES.

    Returns
    -------
    dict with keys:
        prediction : str ("phishing" or "legitimate")
        confidence : float (0.0 to 1.0)
        model_version : str
        ml_score : float (0-100, for use in combined risk score)
    """
    start = time.perf_counter()
    logger.info("[ML] Starting prediction…")

    if _model is None or _scaler is None:
        logger.warning("[ML] Model not loaded — returning default prediction")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "model_version": MODEL_VERSION,
            "ml_score": 0.0,
        }

    # Build the feature vector in the expected order
    feature_vector = np.array([[
        lexical_features[f] for f in EXPECTED_FEATURES
    ]])

    # Scale using the same scaler from training
    feature_vector_scaled = _scaler.transform(feature_vector)

    # Predict
    pred = _model.predict(feature_vector_scaled)[0]
    proba = _model.predict_proba(feature_vector_scaled)[0]

    prediction = "phishing" if pred == 1 else "legitimate"
    confidence = float(max(proba))

    # ML score: confidence mapped to 0-100, directionally aligned with
    # risk (higher = more suspicious, like the other engines).
    # If prediction is phishing, ml_score = confidence * 100
    # If prediction is legitimate, ml_score = (1 - confidence) * 100
    if pred == 1:
        ml_score = round(confidence * 100, 1)
    else:
        ml_score = round((1 - confidence) * 100, 1)

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("[ML] Completed in {:.1f}ms — {} (conf: {:.2%}, score: {})",
                elapsed_ms, prediction, confidence, ml_score)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "model_version": MODEL_VERSION,
        "ml_score": ml_score,
    }
