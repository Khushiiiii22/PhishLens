import requests
import sys

urls = [
    "https://www.google.com",
    "http://mybank-login-secure.com",
    "https://xn--pple-43d.com"
]

for url in urls:
    print(f"Scanning {url}...")
    try:
        response = requests.post("http://127.0.0.1:8000/scan", json={"url": url, "source": "email"}, timeout=30)
        if response.status_code == 200:
            data = response.json()
            print(f"Final Score: {data.get('final_risk_score')}")
            print(f"Fusion Method: {data.get('fusion_method')}")
            print("-" * 30)
        else:
            print(f"Failed to scan {url}: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
