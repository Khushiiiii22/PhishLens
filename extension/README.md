# PhishLens XAI — Chrome Extension (Manifest V3)

A lightweight Manifest V3 companion extension for PhishLens XAI. Provides:
- **Active Tab Inspection**: Inspects the current page URL with redirect unwrapping (Google, Outlook SafeLinks, Facebook, LinkedIn).
- **On-Demand Scanning**: Scans are initiated exclusively when the user clicks **Scan this page**.
- **Context Menu Integration**: Right-click any link on any page and click **Check with PhishLens** to scan link targets.
- **Options Management**: Configure backend API Base URL and Web Dashboard endpoints.

---

## ⚠️ Manifest Notes & Chrome Web Store Submission

In `manifest.json`:

```json
  "host_permissions": [
    "https://phishlens-doyc.onrender.com/*",
    "http://localhost:8000/*"
  ]
```

> **IMPORTANT**:  
> The `http://localhost:8000/*` host permission is intended **strictly for local development and offline expo demonstrations**.  
> **It MUST be removed from `manifest.json` before any submission to the Chrome Web Store.**  
> For production store releases, `host_permissions` must contain only the verified production backend origin (`https://phishlens-doyc.onrender.com/*`), and never `<all_urls>`.

---

## Security Model
- **No Injected Scripts / Content Scripts**: The extension does not inject content scripts into web pages.
- **No Background Polling**: Sends zero network requests on popup load or tab switch.
- **No `web_accessible_resources`**: `popup.html` and extension assets are completely inaccessible from arbitrary web origins.
- **Safe Dynamic Errors**: Rate-limit errors (HTTP 429) dynamically display the backend's configured response detail.

---

## Running Extension Tests
```bash
node --test test/urls.test.js
```

