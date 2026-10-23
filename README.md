# PhishLens XAI
A multi-engine explainable AI phishing detection platform.

## Architecture & Analysis Engines
- **Lexical Engine**: Evaluates URL length, Shannon entropy, character distribution, Punycode/homoglyphs, and suspicious keyword patterns.
- **Domain Intelligence**: Inspects domain age (WHOIS), SSL certificate validity and issuer, and DNSSEC status.
- **Website Behavior**: Uses headless Chromium (Playwright) to detect credential harvesting forms, external form actions, hidden iframes, JavaScript redirects, and popups.
- **Machine Learning**: An ensemble combining a classical Random Forest model and a deep character-level 1D-CNN (ONNX Runtime) with consensus voting.
- **Threat Intelligence**: VirusTotal multi-engine consensus with dedicated handling for clean, never-seen, rate-limited, and malicious states.

## Security & Target Guarding (SSRF Protection)
PhishLens includes strict SSRF defenses to prevent scanning engines from accessing internal infrastructure:
- **Pre-Launch Guard**: Blocks loopback (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, RFC 4193 `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), and cloud metadata IP addresses (`169.254.169.254`, `100.100.100.200`, `metadata.google.internal`).
- **Route Interception**: Headless browser requests (`page.route("**/*")`) inspect all main navigation, redirects, iframes, scripts, XHRs, and media requests. Requests to non-public addresses are intercepted and aborted before leaving the host. Sub-requests targeting internal addresses increment `blocked_private_requests` and penalize the behavior risk score while allowing analysis to finish.

### Known Limitations
- **DNS Rebinding**: While the URL guard verifies IP addresses at resolution time and intercepts all browser subresources before dispatch, **DNS rebinding is not fully mitigated**. An attacker controlling an authoritative nameserver with a 0-second TTL could return a legitimate public IP during initial inspection and subsequently resolve to an internal/private IP during low-level browser socket re-establishment. Full mitigation against DNS rebinding requires network-level egress firewalls or forward proxy enforcement with pinned destination IPs at the transport layer.

