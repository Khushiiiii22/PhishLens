"""
PhishLens — ONNX Conversion and Parity Verification

1. Converts ml/models/deep_model.h5 to ml/models/deep_model.onnx using tf2onnx
   with opset 15 (reproducible conversion script).
2. Runs the held-out 20% test split from ml/data/raw_urls.csv through both
   deep_model.h5 (via TensorFlow/Keras) and deep_model.onnx (via ONNX Runtime).
3. Verifies numerical parity:
   - Maximum absolute difference in predicted probability
   - Accuracy, Precision, Recall, F1-Score, FPR, and ROC-AUC for both models.
   - Asserts ONNX metrics match training metrics (0.9226 / 0.9220 / 0.07).

Usage:
    ml/venv/bin/python ml/convert_and_verify_onnx.py [--convert]
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("onnx_parity")

# Paths
ML_DIR = Path(__file__).resolve().parent
MODELS_DIR = ML_DIR / "models"
DATA_DIR = ML_DIR / "data"

RAW_CSV = DATA_DIR / "raw_urls.csv"
H5_PATH = MODELS_DIR / "deep_model.h5"
ONNX_PATH = MODELS_DIR / "deep_model.onnx"
VOCAB_PATH = MODELS_DIR / "char_vocab.json"
METADATA_PATH = MODELS_DIR / "deep_metadata.json"

RANDOM_STATE = 42
MAX_URL_LEN = 200


def false_positive_rate(y_true, y_pred) -> float:
    """FPR = FP / (FP + TN)"""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0


def encode_url(url: str, char_map: dict, max_len: int) -> np.ndarray:
    """Encode a single URL string into a fixed-length integer array."""
    encoded = [char_map.get(ch, 0) for ch in str(url)[:max_len]]
    if len(encoded) < max_len:
        encoded += [0] * (max_len - len(encoded))
    return np.array(encoded, dtype=np.int32)


def convert_h5_to_onnx(h5_path: Path, onnx_path: Path):
    """Convert Keras H5 model to ONNX using tf2onnx."""
    logger.info(f"Converting {h5_path} -> {onnx_path}")
    import tensorflow as tf
    import tf2onnx

    model = tf.keras.models.load_model(str(h5_path))
    input_spec = (tf.TensorSpec((None, MAX_URL_LEN), tf.int32, name="input_1"),)

    model_proto, _ = tf2onnx.convert.from_keras(
        model,
        input_signature=input_spec,
        opset=15,
        output_path=str(onnx_path),
    )
    logger.info(f"ONNX model saved successfully to {onnx_path} (size: {onnx_path.stat().st_size} bytes)")
    return model_proto


def run_parity_check():
    """Load dataset, evaluate both H5 and ONNX models, and assert parity."""
    # 1. Load Vocabulary
    logger.info(f"Loading vocabulary from {VOCAB_PATH}")
    with open(VOCAB_PATH) as f:
        vocab_data = json.load(f)
    char_to_idx = vocab_data["char_to_idx"]

    # 2. Load Dataset
    logger.info(f"Loading dataset from {RAW_CSV}")
    df = pd.read_csv(RAW_CSV)
    logger.info(f"Dataset loaded: {len(df)} rows")

    X = np.array([encode_url(u, char_to_idx, MAX_URL_LEN) for u in df["url"]], dtype=np.int32)
    y = df["label"].values.astype(int)

    # 3. Held-out 20% test split (identical to training: random_state=42, stratify=y)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )
    logger.info(f"Test split size: {len(X_test)} samples ({int(np.sum(y_test == 1))} phishing, {int(np.sum(y_test == 0))} legit)")

    # 4. Predict using TensorFlow (H5)
    logger.info(f"Loading H5 model: {H5_PATH}")
    import tensorflow as tf
    keras_model = tf.keras.models.load_model(str(H5_PATH))
    y_proba_h5 = keras_model.predict(X_test, batch_size=64, verbose=0).flatten()

    # 5. Predict using ONNX Runtime (ONNX)
    logger.info(f"Loading ONNX model: {ONNX_PATH}")
    import onnxruntime as ort
    ort_session = ort.InferenceSession(str(ONNX_PATH))
    input_name = ort_session.get_inputs()[0].name
    outputs = ort_session.run(None, {input_name: X_test})
    y_proba_onnx = outputs[0].flatten()

    # 6. Numerical Parity Check
    abs_diff = np.abs(y_proba_h5 - y_proba_onnx)
    max_abs_diff = float(np.max(abs_diff))
    mean_abs_diff = float(np.mean(abs_diff))

    logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info("Numerical Probability Parity:")
    logger.info(f"  Max absolute difference:  {max_abs_diff:.8e}")
    logger.info(f"  Mean absolute difference: {mean_abs_diff:.8e}")
    logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # 7. Compute Metrics for both
    y_pred_h5 = (y_proba_h5 >= 0.5).astype(int)
    y_pred_onnx = (y_proba_onnx >= 0.5).astype(int)

    def compute_metrics(y_true, y_pred, y_proba):
        return {
            "Accuracy": float(accuracy_score(y_true, y_pred)),
            "Precision": float(precision_score(y_true, y_pred)),
            "Recall": float(recall_score(y_true, y_pred)),
            "F1-Score": float(f1_score(y_true, y_pred)),
            "FPR": float(false_positive_rate(y_true, y_pred)),
            "ROC-AUC": float(roc_auc_score(y_true, y_proba)),
        }

    metrics_h5 = compute_metrics(y_test, y_pred_h5, y_proba_h5)
    metrics_onnx = compute_metrics(y_test, y_pred_onnx, y_proba_onnx)

    print("\n" + "=" * 65)
    print("  ONNX vs H5 MODEL PARITY REPORT — Held-out 20% Test Split")
    print(f"  Test Samples: {len(X_test)} | Random State: 42 | Stratified: Yes")
    print("=" * 65)
    print(f"  {'Metric':<14} {'H5 (Keras)':>12} {'ONNX':>12} {'Target/Train':>14} {'Match?':>8}")
    print("  " + "-" * 62)

    targets = {
        "Accuracy": 0.9226,
        "F1-Score": 0.9220,
        "FPR": 0.0700,
    }

    for metric in ["Accuracy", "Precision", "Recall", "F1-Score", "FPR", "ROC-AUC"]:
        h5_val = metrics_h5[metric]
        onnx_val = metrics_onnx[metric]
        target_val = targets.get(metric)
        target_str = f"{target_val:.4f}" if target_val is not None else "—"
        
        matches = abs(h5_val - onnx_val) < 1e-4
        match_str = "YES" if matches else "DIFF"
        print(f"  {metric:<14} {h5_val:>12.4f} {onnx_val:>12.4f} {target_str:>14} {match_str:>8}")

    print("  " + "-" * 62)
    print(f"  Max Absolute Probability Difference: {max_abs_diff:.6e}")
    print(f"  Mean Absolute Probability Difference: {mean_abs_diff:.6e}")
    print("=" * 65 + "\n")

    # Assertions for verification
    assert max_abs_diff < 1e-4, f"Max difference too large: {max_abs_diff}"
    assert round(metrics_onnx["Accuracy"], 4) == 0.9226, f"Accuracy mismatch: {metrics_onnx['Accuracy']}"
    assert round(metrics_onnx["F1-Score"], 4) == 0.9220, f"F1-Score mismatch: {metrics_onnx['F1-Score']}"
    assert round(metrics_onnx["FPR"], 2) == 0.07, f"FPR mismatch: {metrics_onnx['FPR']}"
    logger.info(" All ONNX parity checks PASSED successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--convert", action="store_true", help="Re-convert H5 to ONNX before running parity check")
    args = parser.parse_args()

    if args.convert:
        convert_h5_to_onnx(H5_PATH, ONNX_PATH)

    run_parity_check()
