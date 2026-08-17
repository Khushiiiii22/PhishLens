"""
Quick sanity-check for the Domain Intelligence engine.
Run:  python engines/test_domain_intel.py   (from backend/)
"""

from domain_intel import analyze_domain

TEST_URLS = [
    # 1 — Old, trusted domain with valid SSL (should score very low)
    "https://www.google.com",

    # 2 — Known domain but HTTP-only variant (SSL check will still work
    #     because we connect to port 443 regardless of the URL scheme)
    "https://github.com",

    # 3 — A domain that almost certainly has no valid SSL / is very new
    #     or doesn't exist at all — tests the graceful-failure paths
    "http://xz7q9fake-phish-domain.xyz/login",
]

if __name__ == "__main__":
    for url in TEST_URLS:
        print(f"\n{'='*70}")
        print(f"URL: {url}")
        print(f"{'='*70}")
        result = analyze_domain(url)
        for key, value in result.items():
            print(f"  {key:20s} : {value}")
    print()
