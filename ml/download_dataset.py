"""
PhishLens — Dataset Download Script

Downloads the "Web page Phishing Detection" dataset by Shashwat Tiwari
from Kaggle (shashwatwork/web-page-phishing-detection-dataset).

This dataset contains 11,430 URLs — balanced 50/50 between phishing and
legitimate — with 87 pre-extracted features PLUS the raw `url` column
and a `status` label column ("phishing" / "legitimate").

We keep the raw URL and the label, discard the 87 pre-computed features
(because our goal is to generate PhishLens-specific features using our
own engines), and save the result as ml/data/raw_urls.csv.

Setup
-----
1. pip install -r ml/requirements.txt
2. Either:
   a. Set the KAGGLE_USERNAME and KAGGLE_KEY env vars, OR
   b. Place a kaggle.json file at ~/.kaggle/kaggle.json
      (download from https://www.kaggle.com/settings → "Create New Token")
3. python ml/download_dataset.py

Output
------
ml/data/raw_urls.csv  — columns: [url, label]
   • label = 1 for phishing, 0 for legitimate
"""

import os
import sys
import shutil
from pathlib import Path

import pandas as pd
from loguru import logger

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
RAW_CSV = DATA_DIR / "raw_urls.csv"

KAGGLE_DATASET = "shashwatwork/web-page-phishing-detection-dataset"


def download_with_kagglehub() -> Path:
    """Download via kagglehub (handles auth + caching automatically)."""
    import kagglehub
    dataset_path = kagglehub.dataset_download(KAGGLE_DATASET)
    return Path(dataset_path)


def download_with_kaggle_cli() -> Path:
    """Fallback: download via the kaggle CLI."""
    import subprocess
    tmp = DATA_DIR / "_kaggle_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["kaggle", "datasets", "download", "-d", KAGGLE_DATASET,
         "--unzip", "-p", str(tmp)],
        check=True,
    )
    return tmp


def find_csv(directory: Path) -> Path:
    """Find the main CSV file in the downloaded dataset directory."""
    candidates = list(directory.rglob("*.csv"))
    if not candidates:
        raise FileNotFoundError(f"No CSV files found in {directory}")

    # Prefer dataset files, skip things named "features" or "sample"
    for c in candidates:
        name = c.name.lower()
        if "phishing" in name or "dataset" in name:
            return c

    # Fall back to the largest CSV
    return max(candidates, key=lambda p: p.stat().st_size)


def process_dataset(csv_path: Path) -> pd.DataFrame:
    """
    Load the raw Kaggle CSV and extract only [url, label].

    The dataset has an `url` column and a `status` column.
    We map status → binary label: "phishing" → 1, "legitimate" → 0.
    """
    logger.info("Loading CSV from: {}", csv_path)
    df = pd.read_csv(csv_path)

    logger.info("Raw shape: {} rows × {} columns", *df.shape)
    logger.info("Columns: {}", list(df.columns[:10]))

    # --- Locate the URL column ---
    url_col = None
    for col in df.columns:
        if col.strip().lower() == "url":
            url_col = col
            break

    if url_col is None:
        logger.error("Could not find a 'url' column. Available: {}", list(df.columns))
        sys.exit(1)

    # --- Locate the label column ---
    label_col = None
    for col in df.columns:
        if col.strip().lower() in ("status", "label", "class", "result", "type"):
            label_col = col
            break

    if label_col is None:
        logger.error("Could not find a label column. Available: {}", list(df.columns))
        sys.exit(1)

    logger.info("URL column: '{}', Label column: '{}'", url_col, label_col)

    # Build the output DataFrame
    out = pd.DataFrame()
    out["url"] = df[url_col].astype(str).str.strip()

    # Map labels to binary (handle various encodings)
    raw_labels = df[label_col].astype(str).str.strip().str.lower()
    label_map = {
        "phishing": 1, "1": 1, "1.0": 1, "bad": 1, "malicious": 1,
        "legitimate": 0, "0": 0, "0.0": 0, "good": 0, "benign": 0,
        "-1": 0,  # Some datasets use -1 for legitimate
    }
    out["label"] = raw_labels.map(label_map)

    unmapped = out["label"].isna().sum()
    if unmapped > 0:
        logger.warning("{} rows had unmappable labels — dropping them", unmapped)
        unique_unmapped = raw_labels[out["label"].isna()].unique()[:10]
        logger.warning("Unmapped values: {}", list(unique_unmapped))
        out = out.dropna(subset=["label"])

    out["label"] = out["label"].astype(int)

    # Drop rows with empty/invalid URLs
    out = out[out["url"].str.len() > 5].reset_index(drop=True)

    logger.info("Final dataset: {} rows", len(out))
    logger.info("Label distribution:\n{}", out["label"].value_counts().to_string())

    return out


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if RAW_CSV.exists():
        logger.info("raw_urls.csv already exists ({}). Delete it to re-download.", RAW_CSV)
        df = pd.read_csv(RAW_CSV)
        logger.info("Loaded {} rows. Labels: {}", len(df), df["label"].value_counts().to_dict())
        return

    # Try kagglehub first, fall back to CLI
    logger.info("Downloading dataset: {}", KAGGLE_DATASET)
    dataset_dir = None

    try:
        dataset_dir = download_with_kagglehub()
        logger.info("Downloaded via kagglehub to: {}", dataset_dir)
    except Exception as e:
        logger.warning("kagglehub download failed ({}), trying kaggle CLI...", e)
        try:
            dataset_dir = download_with_kaggle_cli()
            logger.info("Downloaded via kaggle CLI to: {}", dataset_dir)
        except Exception as e2:
            logger.error("Both download methods failed.")
            logger.error("kagglehub error: {}", e)
            logger.error("kaggle CLI error: {}", e2)
            logger.info("")
            logger.info("━━━ Manual Download Instructions ━━━")
            logger.info("1. Go to: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
            logger.info("2. Click 'Download' (requires free Kaggle account)")
            logger.info("3. Unzip and place the CSV file in: {}", DATA_DIR)
            logger.info("4. Rename it to 'dataset.csv' and re-run this script")
            logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            # Check if user already placed a file manually
            manual = list(DATA_DIR.glob("*.csv"))
            if manual:
                logger.info("Found manually placed CSV: {}", manual[0])
                dataset_dir = DATA_DIR
            else:
                sys.exit(1)

    # Find and process the CSV
    csv_path = find_csv(dataset_dir)
    df = process_dataset(csv_path)

    # Save
    df.to_csv(RAW_CSV, index=False)
    logger.info("Saved to: {}", RAW_CSV)

    # Cleanup temp download dir if applicable
    tmp = DATA_DIR / "_kaggle_tmp"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
