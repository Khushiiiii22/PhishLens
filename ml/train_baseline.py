"""
PhishLens — Lexical-Only Baseline Model Training

Trains three classifiers on the 9 lexical features extracted by our
Lexical Analysis Engine, evaluates them on a held-out 20% test set,
and saves the best model (by F1-score) to ml/models/.

Features used (9):
    url_length, dot_count, hyphen_count, digit_count, special_char_count,
    entropy_score, has_suspicious_keywords, has_punycode_or_homoglyph,
    lexical_score

Label: 0 = legitimate, 1 = phishing

Usage:
    source backend/venv/bin/activate
    python ml/train_baseline.py
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from xgboost import XGBClassifier
from loguru import logger

# ──────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
MODELS_DIR = SCRIPT_DIR / "models"
FEATURES_CSV = DATA_DIR / "features.csv"

# The 9 lexical features our engine produces
LEXICAL_FEATURES = [
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


def false_positive_rate(y_true, y_pred):
    """FPR = FP / (FP + TN)"""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def train_and_evaluate():
    # ── 1. Load data ──
    logger.info("Loading features from {}", FEATURES_CSV)
    df = pd.read_csv(FEATURES_CSV)
    logger.info("Dataset: {} rows, {} phishing, {} legit",
                len(df), (df["label"] == 1).sum(), (df["label"] == 0).sum())

    X = df[LEXICAL_FEATURES].values
    y = df["label"].values

    # ── 2. Train/test split (80/20, stratified) ──
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y,
    )
    logger.info("Train: {} samples, Test: {} samples", len(X_train), len(X_test))

    # ── 3. Scale features (helps Logistic Regression converge) ──
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ── 4. Define models ──
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42, solver="lbfgs",
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=15, random_state=42, n_jobs=-1,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            random_state=42, eval_metric="logloss", verbosity=0,
        ),
    }

    # ── 5. Train & evaluate each ──
    results = {}
    trained_models = {}

    for name, model in models.items():
        logger.info("━━━ Training: {} ━━━", name)
        t0 = time.perf_counter()

        # Logistic Regression benefits from scaling; tree models don't need it
        # but it doesn't hurt, so use scaled for all for consistency
        model.fit(X_train_scaled, y_train)
        train_time = time.perf_counter() - t0

        y_pred = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        fpr = false_positive_rate(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)

        results[name] = {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "FPR": fpr,
            "ROC-AUC": auc,
            "Train Time": f"{train_time:.2f}s",
        }
        trained_models[name] = model

        logger.info("  Accuracy:  {:.4f}", acc)
        logger.info("  Precision: {:.4f}", prec)
        logger.info("  Recall:    {:.4f}", rec)
        logger.info("  F1-Score:  {:.4f}", f1)
        logger.info("  FPR:       {:.4f}", fpr)
        logger.info("  ROC-AUC:   {:.4f}", auc)
        logger.info("  Time:      {:.2f}s", train_time)

    # ── 6. Print comparison table ──
    print()
    print("=" * 95)
    print("  LEXICAL-ONLY BASELINE — Model Comparison")
    print("  Dataset: 11,430 URLs (50/50 phishing/legit) | Split: 80/20 stratified")
    print("  Features: 9 lexical features from analyze_lexical()")
    print("=" * 95)
    print()

    header = f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'FPR':>10} {'ROC-AUC':>10} {'Time':>8}"
    print(header)
    print("-" * 95)

    for name, metrics in results.items():
        print(
            f"{name:<25} "
            f"{metrics['Accuracy']:>10.4f} "
            f"{metrics['Precision']:>10.4f} "
            f"{metrics['Recall']:>10.4f} "
            f"{metrics['F1-Score']:>10.4f} "
            f"{metrics['FPR']:>10.4f} "
            f"{metrics['ROC-AUC']:>10.4f} "
            f"{metrics['Train Time']:>8}"
        )

    print("-" * 95)

    # ── 7. Pick the best model by F1-score ──
    best_name = max(results, key=lambda k: results[k]["F1-Score"])
    best_f1 = results[best_name]["F1-Score"]
    best_model = trained_models[best_name]

    print()
    print(f"  ★ Best model: {best_name} (F1 = {best_f1:.4f})")
    print()

    # ── 8. Show feature importances for the best model ──
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]
        print("  Feature Importances:")
        for i in sorted_idx:
            bar = "█" * int(importances[i] * 50)
            print(f"    {LEXICAL_FEATURES[i]:<30} {importances[i]:.4f}  {bar}")
        print()

    # ── 9. Save the best model + scaler + metadata ──
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODELS_DIR / "baseline_model.pkl"
    scaler_path = MODELS_DIR / "baseline_scaler.pkl"
    meta_path = MODELS_DIR / "baseline_metadata.json"

    joblib.dump(best_model, model_path)
    joblib.dump(scaler, scaler_path)

    metadata = {
        "model_name": best_name,
        "model_type": "lexical-only-baseline",
        "description": (
            "Lexical-only baseline model trained on 9 URL structure features. "
            "This is a placeholder until domain + behavior features are added."
        ),
        "features": LEXICAL_FEATURES,
        "feature_count": len(LEXICAL_FEATURES),
        "feature_order": "Features must be provided in exactly this order",
        "label_encoding": {"legitimate": 0, "phishing": 1},
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "metrics": {k: round(v, 4) if isinstance(v, float) else v
                    for k, v in results[best_name].items()},
        "all_model_results": {
            name: {k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()}
            for name, m in results.items()
        },
        "scaler": "baseline_scaler.pkl (StandardScaler, must be applied before prediction)",
        "files": {
            "model": "baseline_model.pkl",
            "scaler": "baseline_scaler.pkl",
            "metadata": "baseline_metadata.json",
        },
    }

    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Saved best model to:   {}", model_path)
    logger.info("Saved scaler to:       {}", scaler_path)
    logger.info("Saved metadata to:     {}", meta_path)

    # ── 10. Quick inference test ──
    print()
    print("  Quick inference test (predict on a sample URL):")
    import sys
    sys.path.insert(0, str(SCRIPT_DIR.parent / "backend"))
    from engines.lexical import analyze_lexical  # noqa: E402

    test_urls = [
        ("https://www.google.com", "should be legit"),
        ("http://mybank-login-secure.verify-account.com", "should be phishing"),
        ("https://xn--pple-43d.com", "punycode, should be phishing"),
    ]

    loaded_model = joblib.load(model_path)
    loaded_scaler = joblib.load(scaler_path)

    for url, expected in test_urls:
        lex = analyze_lexical(url)
        features = np.array([[lex[f] for f in LEXICAL_FEATURES]])
        features_scaled = loaded_scaler.transform(features)
        pred = loaded_model.predict(features_scaled)[0]
        proba = loaded_model.predict_proba(features_scaled)[0]
        verdict = "PHISHING" if pred == 1 else "LEGIT"
        print(f"    {url:<55} → {verdict:<10} (conf: {max(proba):.2%})  [{expected}]")

    print()
    print("=" * 95)


if __name__ == "__main__":
    train_and_evaluate()
