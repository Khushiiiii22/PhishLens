"""
Quick sanity-check for the lexical analysis engine.
Run:  python engines/test_lexical.py   (from backend/)
"""

from lexical import analyze_lexical
import json

TEST_URLS = [
    # 1 — Clearly legitimate
    "https://www.google.com",

    # 2 — Long, suspicious-looking with many subdomains and hyphens
    "https://secure-login-verify.account-update.long-subdomain.example.com/auth/token?session=abc123def456ghi789",

    # 3 — Contains a suspicious keyword but shorter
    "https://mybank-login.com/verify-account",

    # 4 — Random garbage-looking domain (high entropy, lots of digits)
    "http://192.168.45.12/x7k9q2m4j8w1p5r3/a0b6c?d=e&f=8472hg#zz",
]

if __name__ == "__main__":
    for url in TEST_URLS:
        result = analyze_lexical(url)
        print(f"\n{'='*70}")
        print(f"URL: {url}")
        print(f"{'='*70}")
        for key, value in result.items():
            print(f"  {key:30s} : {value}")
    print()
