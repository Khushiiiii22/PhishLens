import requests
import json

urls = [
    "https://www.google.com",
    "http://mybank-login-secure.verify-account.com",
    "http://secure-paypal-login.com",
    "https://xn--pple-43d.com"
]

for url in urls:
    print(f"\n--- Scanning {url} ---")
    resp = requests.post("http://localhost:8000/scan", json={"url": url, "source": "email"})
    if resp.status_code == 200:
        if url == "https://xn--pple-43d.com":
            print(json.dumps(resp.json(), indent=2))
        else:
            print("Status: 200")
    else:
        print(f"Status: {resp.status_code}")
        print(resp.text)
