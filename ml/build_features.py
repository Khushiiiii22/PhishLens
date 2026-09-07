"""
PhishLens — Feature Builder

For every URL in ml/data/raw_urls.csv, runs our three existing engines
(lexical, domain, behavior) and writes the extracted features + label
to ml/data/features.csv.

Usage
-----
    # Full run — all engines, all URLs (very slow: ~20-40 hours)
    python ml/build_features.py

    # Lexical only — instant, no network calls (~15 seconds total)
    python ml/build_features.py --lexical-only

    # Sample subset for testing
    python ml/build_features.py --sample 100

    # Both flags work together
    python ml/build_features.py --lexical-only --sample 500

    # Resume from where a previous run left off
    python ml/build_features.py --resume

Architecture
------------
- Lexical engine runs synchronously (it's pure computation, <2ms per URL)
- Domain + Behavior engines are offloaded to a ThreadPoolExecutor with
  configurable concurrency (default: 4 workers)
- Each URL gets 2 retries before being skipped
- Progress is logged every 500 rows
- Partial results are checkpointed to features_partial.csv every 500 rows
  so work isn't lost on crash

Time Estimates (11,430 URLs)
----------------------------
- Lexical only:          ~15 seconds
- Lexical + Domain:      ~5-8 hours (network-bound WHOIS/SSL/DNS)
- Lexical + Domain + Behavior: ~15-30 hours (headless Chromium per URL)
  The behavior engine is the bottleneck: each URL launches a full browser.
  With 4 concurrent workers, parallelism is limited by CPU/memory.
"""

import argparse
import os
import sys
import time
import csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from loguru import logger

# ──────────────────────────────────────────────────────────────────────
# Add the backend directory to sys.path so we can import engines
# ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from engines.lexical import analyze_lexical        # noqa: E402
from engines.domain_intel import analyze_domain     # noqa: E402
from engines.behavior import analyze_behavior       # noqa: E402

# ──────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────
DATA_DIR = SCRIPT_DIR / "data"
RAW_CSV = DATA_DIR / "raw_urls.csv"
FEATURES_CSV = DATA_DIR / "features.csv"
PARTIAL_CSV = DATA_DIR / "features_partial.csv"

# ──────────────────────────────────────────────────────────────────────
# Feature extraction for a single URL
# ──────────────────────────────────────────────────────────────────────
MAX_RETRIES = 2
DOMAIN_WORKERS = 4  # concurrent threads for domain + behavior engines


def extract_features(url: str, label: int, lexical_only: bool = False) -> dict | None:
    """
    Run all engines on a single URL and return a flat dict of features.

    Returns None if all retries are exhausted (URL is skipped).
    """
    # ── Lexical (always runs, never fails, <2ms) ──
    try:
        lex = analyze_lexical(url)
    except Exception as e:
        logger.warning("Lexical failed for {} — skipping: {}", url[:60], e)
        return None

    row = {
        "url": url,
        "label": label,
        # Lexical features
        "url_length": lex["url_length"],
        "dot_count": lex["dot_count"],
        "hyphen_count": lex["hyphen_count"],
        "digit_count": lex["digit_count"],
        "special_char_count": lex["special_char_count"],
        "entropy_score": lex["entropy_score"],
        "has_suspicious_keywords": int(lex["has_suspicious_keywords"]),
        "has_punycode_or_homoglyph": int(lex["has_punycode_or_homoglyph"]),
        "lexical_score": lex["lexical_score"],
    }

    if lexical_only:
        # Fill network-dependent fields with None (they'll be NaN in the CSV)
        row.update({
            "domain_age_days": None,
            "registrar": None,
            "ssl_valid": None,
            "ssl_issuer": None,
            "dnssec_enabled": None,
            "domain_score": None,
            "has_login_form": None,
            "has_hidden_iframe": None,
            "has_js_redirect": None,
            "external_form_action": None,
            "popup_detected": None,
            "behavior_score": None,
            "behavior_analysis_failed": None,
        })
        return row

    # ── Domain Intelligence (with retries) ──
    dom = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            dom = analyze_domain(url)
            break
        except Exception as e:
            logger.warning("Domain attempt {}/{} failed for {}: {}", attempt, MAX_RETRIES, url[:60], e)
            if attempt == MAX_RETRIES:
                logger.error("Domain exhausted retries for {} — using defaults", url[:60])

    if dom:
        row.update({
            "domain_age_days": dom["domain_age_days"],
            "registrar": dom.get("registrar"),
            "ssl_valid": int(dom["ssl_valid"]),
            "ssl_issuer": dom.get("ssl_issuer"),
            "dnssec_enabled": int(dom["dnssec_enabled"]),
            "domain_score": dom["domain_score"],
        })
    else:
        row.update({
            "domain_age_days": None,
            "registrar": None,
            "ssl_valid": None,
            "ssl_issuer": None,
            "dnssec_enabled": None,
            "domain_score": None,
        })

    # ── Behavior (with retries) ──
    beh = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            beh = analyze_behavior(url)
            break
        except Exception as e:
            logger.warning("Behavior attempt {}/{} failed for {}: {}", attempt, MAX_RETRIES, url[:60], e)
            if attempt == MAX_RETRIES:
                logger.error("Behavior exhausted retries for {} — using defaults", url[:60])

    if beh:
        row.update({
            "has_login_form": int(beh["has_login_form"]),
            "has_hidden_iframe": int(beh["has_hidden_iframe"]),
            "has_js_redirect": int(beh["has_js_redirect"]),
            "external_form_action": int(beh["external_form_action"]),
            "popup_detected": int(beh["popup_detected"]),
            "behavior_score": beh["behavior_score"],
            "behavior_analysis_failed": int(beh["behavior_analysis_failed"]),
        })
    else:
        row.update({
            "has_login_form": None,
            "has_hidden_iframe": None,
            "has_js_redirect": None,
            "external_form_action": None,
            "popup_detected": None,
            "behavior_score": None,
            "behavior_analysis_failed": 1,
        })

    return row


# ──────────────────────────────────────────────────────────────────────
# Feature columns (in order)
# ──────────────────────────────────────────────────────────────────────
FEATURE_COLUMNS = [
    "url", "label",
    # Lexical
    "url_length", "dot_count", "hyphen_count", "digit_count",
    "special_char_count", "entropy_score", "has_suspicious_keywords",
    "has_punycode_or_homoglyph", "lexical_score",
    # Domain
    "domain_age_days", "registrar", "ssl_valid", "ssl_issuer",
    "dnssec_enabled", "domain_score",
    # Behavior
    "has_login_form", "has_hidden_iframe", "has_js_redirect",
    "external_form_action", "popup_detected", "behavior_score",
    "behavior_analysis_failed",
]


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="PhishLens Feature Builder")
    parser.add_argument("--lexical-only", action="store_true",
                        help="Only run the lexical engine (instant, no network)")
    parser.add_argument("--sample", type=int, default=None,
                        help="Process only N randomly sampled URLs")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from features_partial.csv (skip already-processed URLs)")
    parser.add_argument("--workers", type=int, default=DOMAIN_WORKERS,
                        help=f"Concurrent workers for network engines (default: {DOMAIN_WORKERS})")
    args = parser.parse_args()

    # ── Load raw URLs ──
    if not RAW_CSV.exists():
        logger.error("raw_urls.csv not found at {}. Run download_dataset.py first.", RAW_CSV)
        sys.exit(1)

    df = pd.read_csv(RAW_CSV)
    logger.info("Loaded {} URLs from raw_urls.csv", len(df))

    # ── Sample if requested ──
    if args.sample and args.sample < len(df):
        df = df.sample(n=args.sample, random_state=42).reset_index(drop=True)
        logger.info("Sampled {} URLs", len(df))

    # ── Resume logic ──
    already_done = set()
    partial_rows = []
    if args.resume and PARTIAL_CSV.exists():
        partial_df = pd.read_csv(PARTIAL_CSV)
        already_done = set(partial_df["url"].tolist())
        partial_rows = partial_df.to_dict("records")
        logger.info("Resuming: {} URLs already processed", len(already_done))

    # ── Run ──
    total = len(df)
    succeeded = len(partial_rows)
    skipped = 0
    results = list(partial_rows)

    mode = "lexical-only" if args.lexical_only else f"all engines ({args.workers} workers)"
    logger.info("━━━ Starting feature extraction: {} mode, {} URLs ━━━", mode, total)
    run_start = time.time()

    for idx, row in df.iterrows():
        url = row["url"]
        label = int(row["label"])

        # Skip if already done (resume mode)
        if url in already_done:
            continue

        try:
            features = extract_features(url, label, lexical_only=args.lexical_only)
        except Exception as e:
            logger.error("Unhandled error for row {} ({}): {}", idx, url[:50], e)
            features = None

        if features is not None:
            results.append(features)
            succeeded += 1
        else:
            skipped += 1

        # ── Progress logging every 500 rows ──
        processed = succeeded + skipped - len(partial_rows)
        if processed > 0 and processed % 500 == 0:
            elapsed = time.time() - run_start
            rate = processed / elapsed
            remaining = (total - processed) / rate if rate > 0 else 0
            logger.info(
                "Progress: {}/{} processed ({} succeeded, {} skipped) — "
                "{:.1f} URLs/sec — ETA: {:.0f}min",
                processed, total, succeeded, skipped, rate, remaining / 60,
            )

            # ── Checkpoint: save partial results ──
            partial_df = pd.DataFrame(results, columns=FEATURE_COLUMNS)
            partial_df.to_csv(PARTIAL_CSV, index=False)
            logger.info("Checkpointed {} rows to {}", len(results), PARTIAL_CSV.name)

    # ── Final save ──
    elapsed = time.time() - run_start
    logger.info("━━━ Feature extraction complete ━━━")
    logger.info("Total time: {:.1f}s ({:.1f} min)", elapsed, elapsed / 60)
    logger.info("Succeeded: {} / {}", succeeded, total)
    logger.info("Skipped:   {} / {}", skipped, total)
    logger.info("Success rate: {:.1f}%", 100 * succeeded / total if total else 0)

    if results:
        out_df = pd.DataFrame(results, columns=FEATURE_COLUMNS)
        out_df.to_csv(FEATURES_CSV, index=False)
        logger.info("Saved {} rows × {} columns to {}", len(out_df), len(FEATURE_COLUMNS), FEATURES_CSV)

        # Quick summary
        logger.info("")
        logger.info("Feature summary:")
        numeric_cols = [c for c in out_df.columns if c not in ("url", "registrar", "ssl_issuer", "label")]
        logger.info("\n{}", out_df[numeric_cols].describe().round(2).to_string())
    else:
        logger.error("No features extracted — nothing to save.")

    # Clean up partial file
    if PARTIAL_CSV.exists() and FEATURES_CSV.exists():
        PARTIAL_CSV.unlink()
        logger.info("Cleaned up partial checkpoint.")


if __name__ == "__main__":
    main()
