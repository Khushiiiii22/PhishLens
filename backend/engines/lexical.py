"""
PhishLens — Lexical Analysis Engine

Pure-function URL analysis. No network calls, no database calls.
Takes a raw URL string and extracts heuristic features from its structure.
"""

import math
import re
from collections import Counter

# Keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "credential", "suspend",
    "authenticate", "wallet", "paypal", "ebay", "alert",
]

# Characters considered "normal" in a URL — everything else is special
_NORMAL_URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/:")


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string, rounded to 3 decimals."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return round(entropy, 3)


def _count_special_chars(url: str) -> int:
    """Count characters that are NOT alphanumeric, '.', '-', '/', or ':'."""
    return sum(1 for ch in url if ch not in _NORMAL_URL_CHARS)


def _compute_lexical_score(
    url_length: int,
    dot_count: int,
    hyphen_count: int,
    digit_count: int,
    special_char_count: int,
    entropy_score: float,
    has_suspicious_keywords: bool,
) -> float:
    """
    Combine lexical signals into a single 0-100 risk score.

    Higher score = more suspicious. The weights below were chosen so that
    a perfectly normal URL like "https://www.google.com" lands near 5-15,
    while a long, keyword-stuffed, high-entropy URL pushes toward 80-100.
    """
    score = 0.0

    # --- URL length ---
    # Very short URLs are fine; above 75 chars starts being suspicious
    if url_length > 75:
        score += min((url_length - 75) * 0.3, 20)  # max +20
    elif url_length > 54:
        score += (url_length - 54) * 0.15  # mild bump

    # --- Dot count ---
    # More than 3 dots is unusual (subdomains used to impersonate)
    if dot_count > 3:
        score += min((dot_count - 3) * 3, 12)  # max +12

    # --- Hyphen density ---
    # Phishing domains often chain hyphens: "secure-login-verify.example.com"
    if hyphen_count > 1:
        score += min((hyphen_count - 1) * 3, 12)  # max +12

    # --- Digit density ---
    # Lots of digits (IP-like URLs, random-looking domains)
    if url_length > 0:
        digit_ratio = digit_count / url_length
        if digit_ratio > 0.1:
            score += min(digit_ratio * 80, 15)  # max +15

    # --- Special characters ---
    if special_char_count > 2:
        score += min((special_char_count - 2) * 2.5, 10)  # max +10

    # --- Entropy ---
    # High entropy means the string looks random / encoded
    if entropy_score > 4.0:
        score += min((entropy_score - 4.0) * 8, 16)  # max +16

    # --- Suspicious keywords ---
    if has_suspicious_keywords:
        score += 15  # flat +15

    # Clamp to [0, 100] and round
    return round(max(0.0, min(score, 100.0)), 1)


def analyze_lexical(url: str) -> dict:
    """
    Analyze a URL string and return a dictionary of lexical features.

    Parameters
    ----------
    url : str
        The full URL to analyze (e.g. "https://example.com/path?q=1").

    Returns
    -------
    dict with keys:
        url_length, dot_count, hyphen_count, digit_count,
        special_char_count, entropy_score, has_suspicious_keywords,
        lexical_score
    """
    url_length = len(url)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    digit_count = sum(ch.isdigit() for ch in url)
    special_char_count = _count_special_chars(url)
    entropy_score = _shannon_entropy(url)

    url_lower = url.lower()
    has_suspicious_keywords = any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

    lexical_score = _compute_lexical_score(
        url_length=url_length,
        dot_count=dot_count,
        hyphen_count=hyphen_count,
        digit_count=digit_count,
        special_char_count=special_char_count,
        entropy_score=entropy_score,
        has_suspicious_keywords=has_suspicious_keywords,
    )

    return {
        "url_length": url_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "entropy_score": entropy_score,
        "has_suspicious_keywords": has_suspicious_keywords,
        "lexical_score": lexical_score,
    }
