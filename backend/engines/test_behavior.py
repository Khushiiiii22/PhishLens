"""
Quick sanity-check for the Website Behavior Analysis engine.
Run:  python engines/test_behavior.py   (from backend/)
"""

from behavior import analyze_behavior

TEST_URLS = [
    # 1 — Real login form (GitHub login page)
    "https://github.com/login",

    # 2 — Simple page with no login forms (Google homepage)
    "https://www.google.com",

    # 3 — Obviously invalid URL — tests the failure/graceful-exit path
    "https://this-domain-definitely-does-not-exist-xz99.invalid/nope",
]

if __name__ == "__main__":
    for url in TEST_URLS:
        print(f"\n{'='*70}")
        print(f"URL: {url}")
        print(f"{'='*70}")
        result = analyze_behavior(url)
        for key, value in result.items():
            print(f"  {key:30s} : {value}")
    print()
