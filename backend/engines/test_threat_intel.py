import os
import json
from dotenv import load_dotenv
from loguru import logger
from threat_intel import check_threat_intel

# Load environment variables (e.g. VIRUSTOTAL_API_KEY)
load_dotenv(dotenv_path="../.env")
load_dotenv(dotenv_path="../../.env")

def run_tests():
    urls_to_test = [
        "https://www.google.com",
        # Known malicious url
        "http://malware.testing.google.test/testing/malware/",
        # A completely new, never scanned domain
        "https://yet-another-random-domain-rate-limit-test-1234.com/login"
    ]

    for url in urls_to_test:
        print(f"\n{'='*60}")
        print(f"Testing URL: {url}")
        print(f"{'='*60}")

        result = check_threat_intel(url)

        print("\n--- SUMMARY ---")
        if result["threat_intel_failed"]:
            print("Status: 🔴 ACTUAL FAILURE (threat_intel_failed=True)")
            print("Reason: VirusTotal was unreachable, rate-limited (HTTP 429), or API key missing.")
        elif result.get("rate_limited_incomplete"):
            print("Status: 🟠 INCOMPLETE / RATE LIMITED (rate_limited_incomplete=True)")
            print("Reason: We gave up polling because of our rate limit queue.")
        elif result.get("never_seen_before"):
            print("Status: 🟡 NEVER SEEN BEFORE (never_seen_before=True)")
            print("Reason: VT definitively responded with 404 — URL has no prior record.")
        else:
            print("Status: 🟢 NORMAL RESULT")
            print(f"Total Engines Checked: {result['total_engines_checked']}")
            print(f"Total Engines Flagged: {result['total_engines_flagged']}")
            print(f"Threat Score: {result['threat_score']}")

        print("\nRaw Output Dictionary:")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    run_tests()
