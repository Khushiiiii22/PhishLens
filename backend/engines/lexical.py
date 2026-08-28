"""
PhishLens — Lexical Analysis Engine

Pure-function URL analysis. No network calls, no database calls.
Takes a raw URL string and extracts heuristic features from its structure.
"""

import math
import re
import unicodedata
from collections import Counter
from urllib.parse import urlparse
import time

from loguru import logger

# Keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "credential", "suspend",
    "authenticate", "wallet", "paypal", "ebay", "alert",
]

# Characters considered "normal" in a URL — everything else is special
_NORMAL_URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/:")

# Common Cyrillic characters that visually resemble Latin letters
# Map: Cyrillic → Latin look-alike
_HOMOGLYPH_CHARS = {
    '\u0430': 'a',  # Cyrillic а → Latin a
    '\u0435': 'e',  # Cyrillic е → Latin e
    '\u043e': 'o',  # Cyrillic о → Latin o
    '\u0440': 'p',  # Cyrillic р → Latin p
    '\u0441': 'c',  # Cyrillic с → Latin c
    '\u0443': 'y',  # Cyrillic у → Latin y
    '\u0445': 'x',  # Cyrillic х → Latin x
    '\u0456': 'i',  # Cyrillic і → Latin i
    '\u0455': 's',  # Cyrillic ѕ → Latin s
    '\u04bb': 'h',  # Cyrillic һ → Latin h
    '\u0501': 'd',  # Cyrillic ԁ → Latin d
    '\u051b': 'q',  # Cyrillic ԛ → Latin q
    '\u0261': 'g',  # Latin small letter script g (used as homoglyph)
}


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


def _check_punycode_or_homoglyph(url: str) -> bool:
    """
    Check if the domain portion of a URL uses punycode (xn-- prefix) or
    contains characters from non-Latin scripts that visually resemble
    Latin letters (homoglyph attack).

    This is a strong phishing signal — attackers register domains like
    "аpple.com" (Cyrillic 'а') that look identical to "apple.com".
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path.split("/")[0]
        if not hostname:
            return False

        # Check 1: Punycode — the domain contains "xn--" labels after
        # ASCII encoding (this is how IDN domains are stored in DNS).
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
            if "xn--" in ascii_hostname:
                return True
        except (UnicodeError, UnicodeDecodeError):
            # If IDNA encoding itself fails, the hostname likely has
            # unusual Unicode — treat as suspicious
            return True

        # Check 2: Direct homoglyph characters in the hostname
        for ch in hostname:
            if ch in _HOMOGLYPH_CHARS:
                return True

        # Check 3: Mixed-script detection — if the hostname contains
        # characters from multiple Unicode scripts (e.g. Latin + Cyrillic),
        # that's a strong homoglyph indicator.
        scripts = set()
        for ch in hostname:
            if ch in '.-':
                continue
            cat = unicodedata.category(ch)
            if cat.startswith('L'):  # Letter category
                # Get the script by checking the Unicode name
                try:
                    name = unicodedata.name(ch, '')
                    if 'CYRILLIC' in name:
                        scripts.add('Cyrillic')
                    elif 'LATIN' in name:
                        scripts.add('Latin')
                    elif 'GREEK' in name:
                        scripts.add('Greek')
                    else:
                        scripts.add(name.split()[0] if name else 'Unknown')
                except ValueError:
                    pass

        # Multiple letter scripts in one hostname is suspicious
        letter_scripts = scripts - {'Unknown'}
        if len(letter_scripts) > 1:
            return True

    except Exception:
        pass

    return False


def _compute_lexical_score(
    url_length: int,
    dot_count: int,
    hyphen_count: int,
    digit_count: int,
    special_char_count: int,
    entropy_score: float,
    has_suspicious_keywords: bool,
    has_punycode_or_homoglyph: bool,
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

    # --- Punycode / Homoglyph ---
    # This is a very strong phishing signal on its own. Legitimate sites
    # rarely use IDN domains that encode to punycode, and homoglyph
    # characters are almost exclusively used for impersonation.
    if has_punycode_or_homoglyph:
        score += 25  # flat +25

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
        has_punycode_or_homoglyph, lexical_score
    """
    start = time.perf_counter()
    logger.info("[Lexical] Starting analysis for: {}", url)

    url_length = len(url)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    digit_count = sum(ch.isdigit() for ch in url)
    special_char_count = _count_special_chars(url)
    entropy_score = _shannon_entropy(url)

    url_lower = url.lower()
    has_suspicious_keywords = any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

    has_punycode_or_homoglyph = _check_punycode_or_homoglyph(url)

    lexical_score = _compute_lexical_score(
        url_length=url_length,
        dot_count=dot_count,
        hyphen_count=hyphen_count,
        digit_count=digit_count,
        special_char_count=special_char_count,
        entropy_score=entropy_score,
        has_suspicious_keywords=has_suspicious_keywords,
        has_punycode_or_homoglyph=has_punycode_or_homoglyph,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("[Lexical] Completed in {:.1f}ms — score: {}", elapsed_ms, lexical_score)

    return {
        "url_length": url_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "entropy_score": entropy_score,
        "has_suspicious_keywords": has_suspicious_keywords,
        "has_punycode_or_homoglyph": has_punycode_or_homoglyph,
        "lexical_score": lexical_score,
    }
