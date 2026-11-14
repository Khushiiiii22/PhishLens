# PhishLens XAI — Decoy Demo & Walkthrough

This directory contains three harmless, self-contained static HTML pages designed for testing and live demonstrations of PhishLens's behavioral, lexical, and domain analysis engines.

**All pages are completely harmless and send data nowhere.**

---

## 📂 The Three Decoy Pages (`demo/decoy/`)

| Page | URL Path | Key Characteristics | Target Engine Behavioral Trigger |
|---|---|---|---|
| **Credential Harvester** | `/login-verify.html` | Fake "Acme Test Portal" sign-in with password input, form action targeting `http://example.org/collect`, and a hidden 1x1 iframe | `has_login_form = True`<br>`external_form_action = True`<br>`has_hidden_iframe = True`<br>Behavior Score: **85.0/100** |
| **Clean Page** | `/clean.html` | Static documentation page with plain prose text and zero forms or scripts | All behavioral flags **False**<br>Behavior Score: **0.0/100** |
| **Cross-Domain Redirect** | `/redirect.html` | Immediate meta-refresh redirect to `http://example.org/` | Cross-domain navigation detected<br>`has_js_redirect = True`<br>Behavior Score: **10.0/100** |

---

## 🚀 How to Run the Demo Locally

### Step 1: Serve the Decoy Pages

From the repository root, start Python's built-in HTTP server on port **9000**:

```bash
cd demo/decoy
python3 -m http.server 9000
```

The pages are now accessible at:
- `http://127.0.0.1:9000/login-verify.html`
- `http://127.0.0.1:9000/clean.html`
- `http://127.0.0.1:9000/redirect.html`

---

### Step 2: Start the Backend with `ALLOW_PRIVATE_TARGETS=true`

> [!WARNING]
> **SSRF Protection Bypass Notice**:  
> By default, PhishLens blocks all loopback (`127.0.0.1`, `localhost`), RFC 1918 private subnets, and cloud metadata endpoints to prevent Server-Side Request Forgery (SSRF).  
> To allow PhishLens to scan pages served on `127.0.0.1:9000`, set `ALLOW_PRIVATE_TARGETS=true`.  
> **This flag is strictly for local offline demonstrations and must NEVER be enabled on production servers (e.g. Render).**

In a separate terminal:

```bash
cd backend
source venv/bin/activate

# Launch backend with private targets explicitly permitted
ALLOW_PRIVATE_TARGETS=true RATE_LIMIT_PER_HOUR=500 uvicorn main:app --port 8000 --reload
```

---

### Step 3: Scan the URLs

You can scan the pages via any of the three interfaces:

#### Option A: Via the Web Dashboard
1. Start the frontend: `cd frontend && npm run dev`
2. Open `http://localhost:5173`
3. Enter `http://127.0.0.1:9000/login-verify.html` and click **Analyze URL**.

#### Option B: Via the Chrome Extension
1. Open the page in Chrome: `http://127.0.0.1:9000/login-verify.html`
2. Click the **PhishLens XAI** extension icon.
3. Click **Scan this page**.

#### Option C: Via cURL / API
```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:9000/login-verify.html", "source": "email"}'
```

---

## 🔍 Expected Results per Engine

### 1. `login-verify.html` (Credential Harvesting Decoy)
* **Website Behavior (85.0/100)**:
  - `has_login_form: true` (detected password input inside form)
  - `external_form_action: true` (form action targets `example.org` while host is `127.0.0.1`)
  - `has_hidden_iframe: true` (1x1 telemetry decoy iframe detected)
  - Signals credential harvesting pattern (+70) + hidden frame (+15)
* **Lexical Engine**:
  - `has_suspicious_keywords: true` (flags `login` and `verify`)
* **Domain Intelligence**:
  - Unencrypted plain HTTP (SSL invalid) on loopback IP.
* **Verdict**: High / Medium Risk warning with clear behavioral attribution.

### 2. `clean.html` (Benign Static Document)
* **Website Behavior (0.0/100)**:
  - `has_login_form: false`
  - `external_form_action: false`
  - `has_hidden_iframe: false`
  - `has_js_redirect: false`
* **Lexical Engine**:
  - Low entropy, no keywords, standard lexical distribution.
* **Verdict**: Low behavioral risk, no credential harvesting red flags.

### 3. `redirect.html` (Automated Redirection Decoy)
* **Website Behavior (10.0/100)**:
  - `has_js_redirect: true` (browser tracks navigation hop from `127.0.0.1` to `http://example.org/`)
  - `has_login_form: false`
* **Verdict**: Explains automated navigation / redirection behavior.

