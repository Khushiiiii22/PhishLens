# PhishLens XAI

PhishLens XAI is a multi-engine explainable phishing detection platform. It inspects URLs across multiple independent analysis dimensions, derives component risk scores, and aggregates them via a transparent, weighted scoring model with breakdown attribution.

---

## 🏛️ System Architecture

PhishLens consists of three core components:
1. **FastAPI Backend (`backend/`)**: Orchestrates 5 detection engines, handles rate limiting, SSRF guardrails, and persists scan results to PostgreSQL/Supabase.
2. **React Dashboard (`frontend/`)**: Vite + React + Tailwind CSS dashboard providing interactive risk gauges, engine breakdowns, and score compositions.
3. **Chrome Extension (`extension/`)**: Manifest V3 extension supporting right-click context menu scanning, active tab inspection with redirect unwrapping, and an inline popup dashboard.

```
                    ┌───────────────────────────────────┐
                    │      Browser / Extension (MV3)    │
                    │   - Context Menu Link Scanner     │
                    │   - Popup (Inline 5-Engine View)  │
                    └─────────────────┬─────────────────┘
                                      │
                                      ▼
                    ┌───────────────────────────────────┐
                    │     Frontend (React + Vite)       │
                    │   - Risk Gauge & Engine Breakdown │
                    │   - Query param deep-linking      │
                    └─────────────────┬─────────────────┘
                                      │ POST /scan
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                                 │
│  - SSRF URL Guard (blocks private IPs, CGNAT, metadata endpoints)     │
│  - Concurrency Semaphore (1 scan at a time)                            │
│  - Rate Limiter (per-IP sliding window, configurable)                 │
├──────────────┬──────────────┬──────────────┬─────────────┬─────────────┤
│   Lexical    │ Domain Intel │   Behavior   │ ML Ensemble │Threat Intel │
│  (Heuristic) │(WHOIS/SSL/DS)│ (Playwright) │ (RF + CNN)  │(VirusTotal) │
└──────────────┴──────────────┴──────────────┴─────────────┴─────────────┘
                                      │
                                      ▼
                    ┌───────────────────────────────────┐
                    │     Transparent Weighted Fusion   │
                    │   - Fixed expert baseline weights │
                    │   - Dynamic redistribution on     │
                    │     engine failure / timeout      │
                    └─────────────────┬─────────────────┘
                                      │
                                      ▼
                    ┌───────────────────────────────────┐
                    │     Database (PostgreSQL)         │
                    │   - Scan & component breakdowns   │
                    └───────────────────────────────────┘
```

---

## 🔍 The 5 Analysis Engines

1. **Lexical Analysis Engine (`engines/lexical.py`)**:
   - Computes Shannon entropy, URL length, dot/hyphen/digit/special character ratios.
   - Detects suspicious keyword patterns (e.g., login, verify, account, banking).
   - Flags Punycode and Unicode homoglyphs (Cyrillic look-alikes, mixed-script).
   - Fast, deterministic, in-memory execution without network I/O.

2. **Domain Intelligence Engine (`engines/domain_intel.py`)**:
   - Queries WHOIS for domain registration age and registrar details.
   - Verifies TLS/SSL certificate validity, expiration, and issuer.
   - Checks DNSSEC deployment via DS records.

3. **Website Behavior Engine (`engines/behavior.py`)**:
   - Launches headless Chromium (Playwright) to inspect dynamic runtime behavior.
   - Detects credential inputs (password fields inside forms), external form actions, hidden iframes (`display: none` or 0px), cross-domain JavaScript redirects, and popups.
   - Enforces strict SSRF route interception (`page.route("**/*")`) to block subresources attempting to reach internal or cloud-metadata IPs.

4. **Machine Learning Ensemble (`engines/ml_predict.py`)**:
   - **Random Forest**: Classical model trained on extracted lexical features.
   - **Character-Level CNN**: 1D-CNN (ONNX Runtime) operating directly on raw URL text representations without manual feature engineering.
   - **Consensus Voting**: Averages model outputs when both agree; dynamically weights the CNN higher when predictions diverge.

5. **Threat Intelligence Engine (`engines/threat_intel.py`)**:
   - Queries VirusTotal API v3 for known multi-vendor security detections.
   - Differentiates between benign, confirmed malicious, `never_seen_before` (unindexed URLs), and `rate_limited_incomplete` states.

---

## ⚖️ Transparent Weighted Fusion

PhishLens aggregates engine scores using a transparent, rule-based weighted sum:
- **Baseline Weights (without Threat Intel record)**:
  - Domain Intel: `28%`
  - ML Ensemble: `30%`
  - Lexical: `21%`
  - Behavior: `21%`
- **When Threat Intel has data**: Threat Intel receives `15%`, and remaining weights are scaled by `0.85`.
- **Dynamic Weight Redistribution**: If an engine fails (e.g. Playwright timeout, DNS failure) or is incomplete (e.g. VirusTotal unindexed / rate-limited), that engine is excluded and the remaining weights are rescaled to sum to `1.0`.

---

## 🚀 How to Run

### Prerequisites
- Python 3.12+ (or 3.14)
- Node.js 18+ and npm
- Google Chrome (for the extension)

---

### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright Chromium browser binary
playwright install chromium

# Set up environment variables
cp .env.example .env
```

Edit `.env` to configure your settings:
```ini
DATABASE_URL=sqlite:///./test.db  # or PostgreSQL connection string
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ALLOWED_ORIGIN=http://localhost:5173
RATE_LIMIT_PER_HOUR=10           # Set to 500 for local demo/expo
TRUSTED_PROXY_HOPS=2             # Proxy hops for Render / CDN
ALLOW_PRIVATE_TARGETS=false      # Set true ONLY for offline local testing
```

Start the FastAPI development server:
```bash
uvicorn main:app --reload --port 8000
```
API docs available at `http://localhost:8000/docs`.

---

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start the Vite development server
npm run dev
```

The web dashboard runs at `http://localhost:5173`.  
By default it points to `http://127.0.0.1:8000`. To point to another backend, create `.env.local`:
```ini
VITE_API_URL=http://localhost:8000
```

---

### 3. Chrome Extension Setup

1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** on in the top-right corner.
3. Click **Load unpacked** and select the `extension/` directory from this repository.
4. **Configuration & Usage**:
   - Click the extension icon in your browser toolbar to inspect the current tab URL.
   - Click **Scan this page** to initiate an on-demand scan.
   - Right-click any link on a web page and select **Check with PhishLens** to scan links directly.
   - Open extension **Options** to switch the target backend between `http://localhost:8000` and the hosted Render instance.

> [!IMPORTANT]
> **Chrome Web Store Submission Notice**: The `http://localhost:8000/*` entry in `manifest.json` under `host_permissions` is strictly for local development and offline expo testing. It **must be removed** before submitting the extension package to the Chrome Web Store, leaving only the production backend domain (`https://phishlens-1-27oz.onrender.com/*`).

---

## 🧪 Running Tests

### Backend Test Suite
```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

### Chrome Extension Test Suite
```bash
cd extension
node --test test/urls.test.js
```

---

## ⚠️ Known Limitations & Scope

- **Heuristic Weighted Fusion**: Risk scoring utilizes fixed, expert-configured heuristic weights, dynamically redistributed upon engine failure. It is **not** a learned meta-classifier or stacking model.
- **Explainability Scope**: "Explainable AI" in PhishLens refers to full visibility into component engine outputs, individual feature flags (e.g. detected password fields, domain age, Punycode detection), and arithmetic score attribution. It does **not** employ SHAP, LIME, or neural gradient-based feature attribution maps.
- **Accuracy Bounds**: No claim is made of absolute or universal system accuracy across all web traffic. Detection efficacy depends on URL availability, third-party API quotas, and the quality of runtime signals.
- **Headless Browser Overhead & Concurrency**: Spawning headless Chromium instances per scan is compute- and memory-intensive. A concurrency semaphore restricts simultaneous browser executions (default 1 concurrent scan) to prevent server exhaustion.
- **DNS Rebinding**: While the URL guard validates resolved IPs and intercepts subresource requests, full mitigation against DNS rebinding (e.g. 0-second TTL race conditions during low-level socket re-establishment) requires transport-layer egress firewall enforcement or pinned IP forward proxies.
- **Ephemeral Rate Limiter**: The sliding-window IP rate limiter stores requests in-memory (capped at 10,000 keys with hourly eviction). Server restarts reset the tracking state unless backed by persistent external caching (such as Redis).
