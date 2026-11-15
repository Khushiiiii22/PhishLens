"""
PhishLens — Evaluation Runner

Calls all 5 PhishLens detection engines directly on the test set:
1. Lexical Analysis
2. Domain Intelligence
3. Website Behavior (Playwright headless Chromium inside container)
4. ML Ensemble (Random Forest + Character-Level CNN)
5. Threat Intelligence (VirusTotal — 20 random URLs per class, others marked "not_run")

Fuses scores using the identical weighted fusion formula as the live endpoint.
Caches each completed evaluation in eval/results.jsonl so runs are resumable.
"""

import os
import sys
import json
import time
import random
from pathlib import Path
import pandas as pd
from loguru import logger

# Add backend directory to sys.path
EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Import engines and fusion router
from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain
from engines.behavior import analyze_behavior
from engines.ml_predict import predict_ml, predict_deep, ensemble_ml_predictions
from engines.threat_intel import check_threat_intel
from routers.scan import calculate_weighted_fusion

TESTSET_CSV = EVAL_DIR / "testset.csv"
RESULTS_JSONL = EVAL_DIR / "results.jsonl"
VT_SAMPLE_FILE = EVAL_DIR / "vt_sampled_urls.json"

SEED = 42


def select_vt_urls(df: pd.DataFrame) -> set[str]:
    """Select 20 random URLs per class (label 0 and label 1) for VirusTotal threat intel."""
    if VT_SAMPLE_FILE.exists():
        logger.info("Loading existing VT sample selection from {}", VT_SAMPLE_FILE)
        data = json.loads(VT_SAMPLE_FILE.read_text(encoding="utf-8"))
        return set(data["vt_urls"])

    rng = random.Random(SEED)
    legit_urls = df[df["label"] == 0]["url"].tolist()
    phish_urls = df[df["label"] == 1]["url"].tolist()

    selected_legit = rng.sample(legit_urls, min(20, len(legit_urls)))
    selected_phish = rng.sample(phish_urls, min(20, len(phish_urls)))
    vt_urls = set(selected_legit + selected_phish)

    VT_SAMPLE_FILE.write_text(json.dumps({
        "seed": SEED,
        "count_legit": len(selected_legit),
        "count_phish": len(selected_phish),
        "total": len(vt_urls),
        "vt_urls": list(vt_urls),
    }, indent=2), encoding="utf-8")
    logger.info("Sampled {} URLs for VirusTotal (20 legit, 20 phish), saved to {}", len(vt_urls), VT_SAMPLE_FILE)
    return vt_urls


def load_cached_results() -> dict[str, dict]:
    """Load already evaluated URLs from results.jsonl."""
    cached = {}
    if not RESULTS_JSONL.exists():
        return cached

    with open(RESULTS_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                cached[rec["url"]] = rec
            except Exception as e:
                logger.warning("Skipping corrupted cache line: {}", e)
    logger.info("Loaded {} cached evaluation results from {}", len(cached), RESULTS_JSONL)
    return cached


def evaluate_single_url(url: str, label: int, source: str, collected_at: str, run_vt: bool) -> dict:
    """Run all 5 detection engines on a URL and compute weighted fusion."""
    start_time = time.perf_counter()
    logger.info("════════ Evaluation started for: {} (label={}, VT={}) ════════", url, label, run_vt)

    # 1. Lexical Analysis
    lex_start = time.perf_counter()
    lexical_data = analyze_lexical(url)
    lex_time = time.perf_counter() - lex_start

    # 2. Domain Intelligence
    dom_start = time.perf_counter()
    domain_data = analyze_domain(url)
    dom_time = time.perf_counter() - dom_start

    # 3. Website Behavior (Playwright headless Chromium)
    beh_start = time.perf_counter()
    behavior_data = analyze_behavior(url)
    beh_time = time.perf_counter() - beh_start

    # 4. ML Ensemble (RF + CNN)
    ml_start = time.perf_counter()
    rf_data = predict_ml(lexical_data)
    cnn_data = predict_deep(url)
    ml_data = ensemble_ml_predictions(rf_data, cnn_data)
    ml_time = time.perf_counter() - ml_start

    ml_record = {
        "prediction": ml_data.get("prediction"),
        "confidence": ml_data.get("confidence"),
        "model_version": ml_data.get("model_version"),
        "ml_score": ml_data.get("ml_score"),
        "models_agreed": ml_data.get("models_agreed"),
        "rf_prediction": rf_data.get("prediction"),
        "rf_confidence": rf_data.get("confidence"),
        "rf_score": rf_data.get("rf_score"),
        "cnn_prediction": cnn_data.get("prediction"),
        "cnn_confidence": cnn_data.get("confidence"),
        "cnn_score": cnn_data.get("cnn_score"),
    }

    # 5. Threat Intelligence
    ti_start = time.perf_counter()
    if run_vt:
        ti_data = check_threat_intel(url)
        ti_data["status"] = "completed"
    else:
        ti_data = {
            "status": "not_run",
            "total_engines_flagged": 0,
            "total_engines_checked": 0,
            "threat_score": 0.0,
            "threat_intel_failed": False,
            "never_seen_before": False,
            "rate_limited_incomplete": False,
        }
    ti_time = time.perf_counter() - ti_start

    # 6. Weighted Fusion (Exact endpoint formula)
    threat_intel_has_real_data = (
        ti_data.get("status") != "not_run"
        and ti_data.get("total_engines_checked", 0) > 0
        and not ti_data.get("threat_intel_failed", False)
        and not ti_data.get("never_seen_before", False)
        and not ti_data.get("rate_limited_incomplete", False)
    )

    failed_engines = []
    incomplete_engines = []

    if behavior_data.get("behavior_analysis_failed", False):
        failed_engines.append("behavior")

    if ti_data.get("status") == "not_run":
        incomplete_engines.append("threat_intel")
    elif ti_data.get("threat_intel_failed", False):
        failed_engines.append("threat_intel")
    elif ti_data.get("never_seen_before", False) or ti_data.get("rate_limited_incomplete", False):
        incomplete_engines.append("threat_intel")

    engine_scores = {
        "lexical": lexical_data.get("lexical_score", 0.0),
        "domain": domain_data.get("domain_score", 0.0),
        "behavior": behavior_data.get("behavior_score", 0.0),
        "ml": ml_data.get("ml_score", 0.0),
        "threat_intel": ti_data.get("threat_score", 0.0),
    }

    final_risk_score, engines_used, engines_failed, engines_incomplete, final_weights = calculate_weighted_fusion(
        engine_scores=engine_scores,
        failed_engines=failed_engines,
        incomplete_engines=incomplete_engines,
        threat_intel_has_real_data=threat_intel_has_real_data,
    )

    total_time = time.perf_counter() - start_time
    logger.info(
        "Scan complete in {:.1f}s — Final Score: {} | Engines Used: {} | Weights: {}",
        total_time, final_risk_score, engines_used, final_weights
    )

    return {
        "url": url,
        "label": label,
        "source": source,
        "collected_at": collected_at,
        "timing_seconds": {
            "lexical": round(lex_time, 3),
            "domain": round(dom_time, 3),
            "behavior": round(beh_time, 3),
            "ml": round(ml_time, 3),
            "threat_intel": round(ti_time, 3),
            "total": round(total_time, 3),
        },
        "lexical": lexical_data,
        "domain": domain_data,
        "behavior": behavior_data,
        "ml": ml_record,
        "threat_intel": ti_data,
        "fusion": {
            "final_risk_score": final_risk_score,
            "engines_used": engines_used,
            "engines_failed": engines_failed,
            "engines_incomplete": engines_incomplete,
            "final_weights": final_weights,
            "threat_intel_has_real_data": threat_intel_has_real_data,
            "fusion_method": "weighted",
        },
    }


def run_evaluation():
    if not TESTSET_CSV.exists():
        logger.error("Testset not found at {}. Please run build_testset.py first.", TESTSET_CSV)
        sys.exit(1)

    df = pd.read_csv(TESTSET_CSV)
    logger.info("Loaded {} test URLs from {}", len(df), TESTSET_CSV)

    vt_urls = select_vt_urls(df)
    cached = load_cached_results()

    total = len(df)
    logger.info("Beginning evaluation: {} total URLs, {} already cached, {} to run",
                total, len(cached), total - len(cached))

    # Append mode for results file
    with open(RESULTS_JSONL, "a", encoding="utf-8") as out_f:
        for idx, row in df.iterrows():
            url = row["url"]
            label = int(row["label"])
            source = str(row["source"])
            collected_at = str(row["collected_at"])

            if url in cached:
                logger.info("[{}/{}] Using CACHED result for: {}", idx + 1, total, url)
                continue

            run_vt = url in vt_urls
            logger.info("[{}/{}] Running evaluation on: {}", idx + 1, total, url)

            try:
                result = evaluate_single_url(
                    url=url,
                    label=label,
                    source=source,
                    collected_at=collected_at,
                    run_vt=run_vt
                )
                out_f.write(json.dumps(result) + "\n")
                out_f.flush()
                cached[url] = result
            except Exception as e:
                logger.exception("Unexpected fatal error evaluating {}: {}", url, e)

    logger.info("Evaluation complete! {} total results in {}", len(cached), RESULTS_JSONL)


if __name__ == "__main__":
    run_evaluation()

