"""
PhishLens — Testset Builder for Pre-Expo Evaluation

Dataset composition:
1. 40 legitimate URLs sampled at random from top 5,000 domains of the Tranco list.
2. 10 well-known login pages as hard negatives (e.g. gitlab, atlassian, reddit, slack, etc.).
3. 40 recent phishing URLs from OpenPhish's free community feed.

Deduplication / Contamination prevention:
- Any URL or domain that appears in ml/data/raw_urls.csv (training data) is dropped.

OpenPhish Community Feed Terms of Use:
--------------------------------------
The OpenPhish Free Community Feed is provided strictly for personal, independent,
or academic research use only. Commercial use (including security operations,
commercial threat intelligence, detection automation, or customer protection) is
prohibited without prior written license from OpenPhish. The data is provided "AS IS"
and updates every 12 hours. Redistribution is restricted.
This evaluation uses the feed purely for non-commercial benchmark verification.
"""

import os
import sys
import json
import random
import zipfile
import io
import datetime
from pathlib import Path
from urllib.parse import urlparse
import requests
import pandas as pd
from loguru import logger

# Paths
EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent
RAW_TRAIN_CSV = REPO_ROOT / "ml" / "data" / "raw_urls.csv"
OUTPUT_TESTSET_CSV = EVAL_DIR / "testset.csv"
RAW_OPENPHISH_TXT = EVAL_DIR / "openphish_raw.txt"
RAW_OPENPHISH_META = EVAL_DIR / "openphish_meta.json"
RAW_TRANCO_CSV = EVAL_DIR / "tranco_top5k.csv"

# Sources
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
TRANCO_TOP1M_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"

HARD_NEGATIVE_LOGIN_CANDIDATES = [
    "https://gitlab.com/users/sign_in",
    "https://id.atlassian.com/login",
    "https://auth.docker.com/login",
    "https://app.slack.com/login",
    "https://discord.com/login",
    "https://www.reddit.com/login",
    "https://login.salesforce.com",
    "https://auth0.com/auth/login",
    "https://zoom.us/signin",
    "https://www.notion.so/login",
    "https://account.apple.com",
    "https://login.proton.me",
    "https://app.hubspot.com/login",
    "https://login.oracle.com",
    "https://signin.aws.amazon.com",
    "https://bitbucket.org/account/signin/",
    "https://www.paypal.com/signin",
    "https://login.yahoo.com",
]

SEED = 42


def normalize_domain(url_or_domain: str) -> str:
    """Extract clean domain/host (lowercase, no port, no leading www.)."""
    raw = url_or_domain.strip().lower()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        host = parsed.netloc.split(":")[0].strip()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def load_training_exclusions() -> tuple[set[str], set[str]]:
    """Load training URLs and domains to guarantee zero data leakage."""
    if not RAW_TRAIN_CSV.exists():
        logger.warning("Training CSV not found at {}. Exclusion set is empty.", RAW_TRAIN_CSV)
        return set(), set()

    df_train = pd.read_csv(RAW_TRAIN_CSV)
    train_urls = set(df_train["url"].astype(str).str.strip().str.lower())
    train_domains = set()
    for u in train_urls:
        dom = normalize_domain(u)
        if dom:
            train_domains.add(dom)

    logger.info("Loaded {} training URLs spanning {} unique domains from {}",
                len(train_urls), len(train_domains), RAW_TRAIN_CSV)
    return train_urls, train_domains


def download_openphish_feed() -> list[str]:
    """Download OpenPhish community feed, save raw copy and metadata."""
    logger.info("Downloading OpenPhish community feed from {}", OPENPHISH_FEED_URL)
    download_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    headers = {"User-Agent": "PhishLens-Academic-Evaluation/1.0"}
    resp = requests.get(OPENPHISH_FEED_URL, headers=headers, timeout=30)
    resp.raise_for_status()

    raw_text = resp.text
    RAW_OPENPHISH_TXT.write_text(raw_text, encoding="utf-8")

    meta = {
        "source": "OpenPhish Free Community Feed",
        "url": OPENPHISH_FEED_URL,
        "download_time_utc": download_time,
        "http_status": resp.status_code,
        "raw_lines": len(raw_text.splitlines()),
        "terms_of_use_summary": (
            "OpenPhish Community Feed is provided solely for personal, independent, "
            "or academic research use on an AS-IS basis. Commercial use and redistribution "
            "are prohibited without prior written permission from OpenPhish."
        ),
    }
    RAW_OPENPHISH_META.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info("Saved raw OpenPhish feed to {} (downloaded at {})", RAW_OPENPHISH_TXT, download_time)

    urls = [line.strip() for line in raw_text.splitlines() if line.strip() and line.strip().startswith("http")]
    logger.info("Parsed {} raw phishing URLs from OpenPhish", len(urls))
    return urls


def download_tranco_top5k() -> list[str]:
    """Download Tranco list and extract top 5,000 domains."""
    if RAW_TRANCO_CSV.exists():
        logger.info("Tranco top 5k already exists at {}", RAW_TRANCO_CSV)
        df_tranco = pd.read_csv(RAW_TRANCO_CSV)
        return df_tranco["domain"].tolist()

    logger.info("Downloading Tranco top-1M list from {}", TRANCO_TOP1M_ZIP_URL)
    resp = requests.get(TRANCO_TOP1M_ZIP_URL, timeout=60)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_filename = [n for n in zf.namelist() if n.endswith(".csv")][0]
        with zf.open(csv_filename) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=5000)

    df.to_csv(RAW_TRANCO_CSV, index=False)
    logger.info("Saved Tranco top 5,000 domains to {}", RAW_TRANCO_CSV)
    return df["domain"].tolist()


def build_testset():
    random.seed(SEED)
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    train_urls, train_domains = load_training_exclusions()

    # 1. Tranco Legitimate URLs (40)
    tranco_domains = download_tranco_top5k()
    clean_tranco = []
    for d in tranco_domains:
        norm = normalize_domain(d)
        if norm and norm not in train_domains:
            clean_tranco.append(f"https://{d}")

    logger.info("Eligible Tranco domains (after dropping training domains): {}", len(clean_tranco))
    if len(clean_tranco) < 40:
        raise ValueError(f"Not enough Tranco domains after filtering: {len(clean_tranco)}")

    selected_tranco = random.sample(clean_tranco, 40)

    # 2. Hard Negative Login Pages (10)
    clean_login = []
    for u in HARD_NEGATIVE_LOGIN_CANDIDATES:
        dom = normalize_domain(u)
        if u.lower() not in train_urls and dom not in train_domains:
            clean_login.append(u)

    logger.info("Eligible login candidates (not in training): {}", len(clean_login))
    if len(clean_login) < 10:
        raise ValueError(f"Need 10 hard negative login pages, but only found {len(clean_login)}")

    selected_login = clean_login[:10]

    # 3. Phishing URLs from OpenPhish (40)
    openphish_urls = download_openphish_feed()
    clean_phishing = []
    for u in openphish_urls:
        dom = normalize_domain(u)
        if u.lower() not in train_urls and dom not in train_domains:
            clean_phishing.append(u)

    logger.info("Eligible OpenPhish URLs (not in training): {}", len(clean_phishing))
    if len(clean_phishing) < 40:
        raise ValueError(f"Not enough clean OpenPhish URLs: {len(clean_phishing)}")

    # Deterministic sample of 40 recent phishing URLs
    selected_phishing = random.sample(clean_phishing, 40)

    # Assemble dataset
    rows = []
    for u in selected_tranco:
        rows.append({
            "url": u,
            "label": 0,
            "source": "tranco_top5k",
            "collected_at": collected_at,
        })

    for u in selected_login:
        rows.append({
            "url": u,
            "label": 0,
            "source": "hard_negative_login",
            "collected_at": collected_at,
        })

    for u in selected_phishing:
        rows.append({
            "url": u,
            "label": 1,
            "source": "openphish_community",
            "collected_at": collected_at,
        })

    df_testset = pd.DataFrame(rows)
    df_testset.to_csv(OUTPUT_TESTSET_CSV, index=False)
    logger.info("Successfully built testset at {}:", OUTPUT_TESTSET_CSV)
    logger.info("Total rows: {}", len(df_testset))
    logger.info("Breakdown by label:\n{}", df_testset["label"].value_counts().to_string())
    logger.info("Breakdown by source:\n{}", df_testset["source"].value_counts().to_string())


if __name__ == "__main__":
    build_testset()

