"""
PhishLens — ML Prediction Engine

Loads TWO trained models ONCE at module import time:
  1. Classical Random Forest baseline (from baseline_model.pkl)
  2. Character-level CNN deep model (from deep_model.onnx via ONNX Runtime)

Provides:
  - predict_ml()   → classical baseline prediction
  - predict_deep()  → deep CNN prediction (raw URL text, no hand-crafted features)
  - ensemble_ml_predictions() → weighted combination of both models

No imports from database.py, models.py, or schemas.py.
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
from loguru import logger

# ──────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────
_MODEL_DIR = Path(__file__).resolve().parent.parent / "ml" / "models"

# ──────────────────────────────────────────────────────────────────────
# 1. Classical Baseline — Random Forest
# ──────────────────────────────────────────────────────────────────────
_MODEL_PATH = _MODEL_DIR / "baseline_model.pkl"
_SCALER_PATH = _MODEL_DIR / "baseline_scaler.pkl"

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

try:
    _model = joblib.load(_MODEL_PATH)
    _scaler = joblib.load(_SCALER_PATH)
    logger.info("[ML] Loaded baseline model from {} (version: {})", _MODEL_PATH.name, MODEL_VERSION)
except Exception as e:
    logger.warning("[ML] Could not load baseline model: {} — baseline predictions disabled", e)
    _model = None
    _scaler = None

# ──────────────────────────────────────────────────────────────────────
# 2. Deep Learning — Character-level CNN (via ONNX Runtime)
# ──────────────────────────────────────────────────────────────────────
_DEEP_ONNX_PATH = _MODEL_DIR / "deep_model.onnx"
_VOCAB_PATH = _MODEL_DIR / "char_vocab.json"

DEEP_MODEL_VERSION = "deep_cnn_v1"
DEEP_MODEL_NAME = "CharCNN"

try:
    import onnxruntime as ort
    _deep_session = ort.InferenceSession(str(_DEEP_ONNX_PATH))
    _deep_input_name = _deep_session.get_inputs()[0].name

    with open(_VOCAB_PATH) as f:
        _vocab_data = json.load(f)
    _char_to_idx = _vocab_data["char_to_idx"]
    _max_url_len = _vocab_data["max_url_len"]

    logger.info("[ML] Loaded deep CNN model from {} (version: {})", _DEEP_ONNX_PATH.name, DEEP_MODEL_VERSION)
except Exception as e:
    logger.warning("[ML] Could not load deep model: {} — deep predictions disabled", e)
    _deep_session = None
    _char_to_idx = None
    _max_url_len = 200


def _encode_url(url: str) -> np.ndarray:
    """Encode a URL string into a fixed-length integer array for the CNN."""
    encoded = [_char_to_idx.get(ch, 0) for ch in url[:_max_url_len]]
    if len(encoded) < _max_url_len:
        encoded += [0] * (_max_url_len - len(encoded))
    return np.array(encoded, dtype=np.int32)


# ──────────────────────────────────────────────────────────────────────
# Prediction Functions
# ──────────────────────────────────────────────────────────────────────

def predict_ml(lexical_features: dict) -> dict:
    """
    Run the classical Random Forest baseline on lexical features.

    Returns dict with: prediction, confidence, model_version, ml_score
    """
    start = time.perf_counter()
    logger.info("[ML-RF] Starting prediction…")

    if _model is None or _scaler is None:
        logger.warning("[ML-RF] Model not loaded — returning default prediction")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "model_version": MODEL_VERSION,
            "ml_score": 0.0,
        }

    feature_vector = np.array([[
        lexical_features[f] for f in EXPECTED_FEATURES
    ]])
    feature_vector_scaled = _scaler.transform(feature_vector)

    pred = _model.predict(feature_vector_scaled)[0]
    proba = _model.predict_proba(feature_vector_scaled)[0]

    prediction = "phishing" if pred == 1 else "legitimate"
    confidence = float(max(proba))

    if pred == 1:
        ml_score = round(confidence * 100, 1)
    else:
        ml_score = round((1 - confidence) * 100, 1)

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("[ML-RF] Completed in {:.1f}ms — {} (conf: {:.2%}, score: {})",
                elapsed_ms, prediction, confidence, ml_score)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "model_version": MODEL_VERSION,
        "ml_score": ml_score,
    }


def predict_deep(url: str) -> dict:
    """
    Run the character-level CNN on the raw URL string.

    Returns dict with: prediction, confidence, model_version, ml_score
    """
    start = time.perf_counter()
    logger.info("[ML-CNN] Starting prediction…")

    if _deep_session is None:
        logger.warning("[ML-CNN] Model not loaded — returning default prediction")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "model_version": DEEP_MODEL_VERSION,
            "ml_score": 0.0,
        }

    encoded = _encode_url(url)
    input_batch = encoded.reshape(1, -1)

    outputs = _deep_session.run(None, {_deep_input_name: input_batch})
    phishing_prob = float(outputs[0][0][0])

    prediction = "phishing" if phishing_prob >= 0.5 else "legitimate"
    confidence = phishing_prob if phishing_prob >= 0.5 else 1.0 - phishing_prob

    # ml_score: higher = more suspicious (aligned with other engines)
    ml_score = round(phishing_prob * 100, 1)

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("[ML-CNN] Completed in {:.1f}ms — {} (conf: {:.2%}, score: {})",
                elapsed_ms, prediction, confidence, ml_score)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "model_version": DEEP_MODEL_VERSION,
        "ml_score": ml_score,
    }


def ensemble_ml_predictions(rf_data: dict, cnn_data: dict) -> dict:
    """
    Combine the Random Forest and CNN predictions into a single ML signal.

    Rules:
    - If both AGREE on prediction: average their ml_scores.
    - If they DISAGREE: weight CNN higher (0.7 CNN + 0.3 RF) since it has
      better overall metrics, and log the disagreement.

    Returns dict with:
        prediction, confidence, model_version, ml_score, models_agreed (bool)
    """
    rf_pred = rf_data["prediction"]
    cnn_pred = cnn_data["prediction"]

    models_agreed = (rf_pred == cnn_pred)

    if models_agreed:
        # Average the scores
        ensemble_score = round((rf_data["ml_score"] + cnn_data["ml_score"]) / 2.0, 1)
        ensemble_confidence = (rf_data["confidence"] + cnn_data["confidence"]) / 2.0
        ensemble_prediction = cnn_pred
        logger.info("[ML-Ensemble] Models AGREE: {} (RF: {:.1f}, CNN: {:.1f} → avg: {:.1f})",
                    ensemble_prediction, rf_data["ml_score"], cnn_data["ml_score"], ensemble_score)
    else:
        # Disagreement: weight CNN 0.7, RF 0.3
        ensemble_score = round(cnn_data["ml_score"] * 0.7 + rf_data["ml_score"] * 0.3, 1)
        ensemble_confidence = cnn_data["confidence"] * 0.7 + rf_data["confidence"] * 0.3
        # Use ensemble_score to decide final prediction
        ensemble_prediction = "phishing" if ensemble_score >= 50.0 else "legitimate"
        logger.warning(
            "[ML-Ensemble] Models DISAGREE — RF: {} ({:.1f}), CNN: {} ({:.1f}) "
            "→ weighted ensemble: {} ({:.1f})  [CNN weighted 0.7]",
            rf_pred, rf_data["ml_score"], cnn_pred, cnn_data["ml_score"],
            ensemble_prediction, ensemble_score,
        )

    return {
        "prediction": ensemble_prediction,
        "confidence": round(ensemble_confidence, 4),
        "model_version": f"ensemble({MODEL_VERSION}+{DEEP_MODEL_VERSION})",
        "ml_score": ensemble_score,
        "models_agreed": models_agreed,
        "rf_prediction": rf_pred,
        "rf_confidence": rf_data["confidence"],
        "rf_score": rf_data["ml_score"],
        "cnn_prediction": cnn_pred,
        "cnn_confidence": cnn_data["confidence"],
        "cnn_score": cnn_data["ml_score"],
    }

