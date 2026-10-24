import os
import json
import time
from dotenv import load_dotenv
from threat_intel import check_threat_intel

load_dotenv(dotenv_path="../../.env")

def run_tests():
    # Only test a brand new URL so we don't hit rate limits and can test the 8s timeout correctly
    url = f"https://zero-day-test-domain-{int(time.time())}.com/login"
    
    print(f"\n{'='*60}")
    print(f"Testing URL: {url}")
    print(f"{'='*60}")
    
    result = check_threat_intel(url)
    
    print("\n--- SUMMARY ---")
    if result["threat_intel_failed"]:
        print("Status: 🔴 ACTUAL FAILURE (threat_intel_failed=True)")
    elif result["zero_day_no_data"]:
        print("Status: 🟡 ZERO-DAY / NO DATA (zero_day_no_data=True)")
    else:
        print("Status: 🟢 NORMAL RESULT")
        print(f"Total Engines Checked: {result['total_engines_checked']}")
        print(f"Total Engines Flagged: {result['total_engines_flagged']}")
        print(f"Threat Score: {result['threat_score']}%")
    
    print("\nRaw Output Dictionary:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    run_tests()
