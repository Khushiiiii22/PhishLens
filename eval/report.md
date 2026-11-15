# PhishLens XAI — Empirical Evaluation & Forensic Audit Report

**Evaluation Date:** 2026-11-13 (Audited & Updated: 2026-11-14)  
**Total Sample Size:** $N = 90$ ($N_{\text{phish}} = 40$, $N_{\text{legit}} = 50$)  
**Benchmark Integrity:** 0% contamination against training set `ml/data/raw_urls.csv` (8,113 training domains excluded). Raw phishing URLs sanitized to SHA-256 hashes per OpenPhish redistribution guidelines.  

---

## 1. Apples-to-Apples Fusion & Sub-Model Comparison

To understand the genuine contribution of multi-engine fusion versus stand-alone ML, we compare:
1. **Fusion with Threat Intelligence EXCLUDED** across all $N=90$ URLs (reflecting pure offline zero-day / un-indexed capability).
2. **Fusion with Threat Intelligence INCLUDED** on the 40-URL VirusTotal subset ($N=40$: 20 legit, 20 phish).
3. **CNN Alone, RF Alone, and ML Ensemble Alone** across the identical 90 URLs.

| Model / Configuration | Threshold | $N$ | TP | FP | TN | FN | Recall [95% Wilson CI] | FPR [95% Wilson CI] | Precision [95% CI] | F1 Score |
|---|---|---|---|---|---|---|---|---|---|---|
| **Fusion (Threat Intel Excluded)** | `>=31` | 90 | 20 | 10 | 40 | 20 | 50.0% [35.2%, 64.8%] | 20.0% [11.2%, 33.0%] | 66.7% [48.8%, 80.8%] | 57.1% |
| **Fusion (With Threat Intel, VT Subset)** | `>=31` | 40 | 16 | 4 | 16 | 4 | 80.0% [58.4%, 91.9%] | 20.0% [8.1%, 41.6%] | 80.0% [58.4%, 91.9%] | 80.0% |
| **Deep CNN Alone** | `>=50` | 90 | 32 | 9 | 41 | 8 | 80.0% [65.2%, 89.5%] | 18.0% [9.8%, 30.8%] | 78.0% [63.3%, 88.0%] | 79.0% |
| **Random Forest Alone** | `>=50` | 90 | 23 | 18 | 32 | 17 | 57.5% [42.2%, 71.5%] | 36.0% [24.1%, 49.9%] | 56.1% [41.0%, 70.1%] | 56.8% |
| **ML Ensemble Alone** | `>=50` | 90 | 30 | 10 | 40 | 10 | 75.0% [59.8%, 85.8%] | 20.0% [11.2%, 33.0%] | 75.0% [59.8%, 85.8%] | 75.0% |

### Exact McNemar Test: Offline Fusion (a) vs. Deep CNN Alone

We evaluated statistical significance between **Offline Fusion (Threat Intel Excluded)** (decision threshold $\ge 31$) and the **Deep Character-Level CNN** alone (decision threshold $\ge 50$) across the identical 90 test URLs.

#### $2 \times 2$ Contingency Table
```
                               Deep CNN Correct    Deep CNN Incorrect    Total
Offline Fusion Correct              57 (a)               3 (b)            60
Offline Fusion Incorrect            16 (c)              14 (d)            30
Total                               73                  17            90
```

- **Discordant Pairs:** $b = 3$ (Fusion correct, CNN incorrect), $c = 16$ (CNN correct, Fusion incorrect); total discordant = 19.
- **Exact Two-Sided Binomial Test:** $p = \mathbf{0.0044}$ ($p < 0.01$).
- **Continuity-Corrected McNemar $\chi^2$:** $\chi^2 = \frac{(|3 - 16| - 1)^2}{3 + 16} = \frac{144}{19} = 7.5789$, $p = \mathbf{0.0059}$.

> **Statistical Takeaway:** The Deep CNN alone is **better at these settings on this sample (exact McNemar p = 0.0044)** than the 4-engine heuristic fusion without threat intelligence on this benchmark. Note that the McNemar comparison uses different flag thresholds (31 and 50), so it describes those settings on this sample; an AUC comparison would be fairer. Heuristic fusion dilutes the CNN's signal when Behavior scores 0.0 on dead/blocked phishing pages and Domain WHOIS fails on shared hosting platforms.

---

## 2. In-Depth Error Analysis (Threshold $\ge 31$)

At the system operational threshold of $\ge 31$, the evaluation produced **9 False Positives** (out of 50 legitimate URLs) and **14 False Negatives** (out of 40 phishing URLs).

### False Positives ($N_{\text{FP}} = 9$)

| Hashed ID | Legitimate URL | Lex | Dom | Beh | ML (RF / CNN) | TI | Final Score | URL Category / Primary Driving Factor |
|---|---|---|---|---|---|---|---|---|
| `5c24eadfd4` | `https://verify.hn` | 15.0 | 40.0 | 0.0 | 53.1 (90.1 / 37.3) | 0.0 | **31.33** | Unusual ccTLD (.hn) + keyword 'verify'. Behavior failed (DNS error), reallocating weight to Domain (40) and ML RF (90.1). |
| `f8269504d6` | `https://xhamster2.com` | 0.0 | 40.0 | 0.0 | 87.8 (89.3 / 86.3) | 25.0 | **43.41** | Adult streaming mirror domain with trailing digit. Pushed by ML (87.8) and 1 VT vendor flag (25.0). |
| `bee4462c1b` | `https://msftconnecttest.com` | 0.0 | 40.0 | 0.0 | 46.2 (30.0 / 53.2) | 0.0 | **31.72** | Windows network probe endpoint. Returns 200 text/plain, no HTML. Behavior failed, inflating Domain (40) & ML (46.2). |
| `0081d43c52` | `https://windowsupdate.com` | 15.0 | 40.0 | 0.0 | 34.7 (68.3 / 20.3) | 0.0 | **31.34** | OS update service redirect. Lexical keyword (15) and Domain (40). Behavior failed. |
| `8d759f992e` | `https://myworkdayjobs.com` | 0.4 | 80.0 | 0.0 | 34.7 (79.4 / 15.6) | 0.0 | **34.04** | Enterprise HR recruitment platform. High domain score (80.0 due to privacy WHOIS redaction) + RF (79.4). |
| `e89fd7b6fa` | `https://id.atlassian.com/login` | 15.0 | 10.0 | 0.0 | 85.7 (76.5 / 94.9) | 0.0 | **31.66** | Hard negative login page. ML models heavily triggered by login path (CNN: 94.9, RF: 76.5) and Lexical (15). |
| `a9d734e304` | `https://auth.docker.com/login` | 16.3 | 10.0 | 30.0 | 94.9 (98.9 / 90.9) | 0.0 | **40.99** | Hard negative login page. ML (94.9), Behavior detected real login form (30.0), Lexical (16.3). |
| `050d10191c` | `https://app.slack.com/login` | 15.0 | 10.0 | 0.0 | 85.4 (71.8 / 99.1) | 0.0 | **31.57** | Hard negative login page. ML CNN flagged at 99.1% confidence due to lexical login patterns. |
| `be24b4d14f` | `https://auth0.com/auth/login` | 15.0 | 10.0 | 20.0 | 85.2 (94.3 / 76.2) | 0.0 | **35.71** | Hard negative login page. ML (85.2), Behavior form detection (20.0), Lexical (15.0). |

### False Negatives ($N_{\text{FN}} = 14$)

| Hashed ID | Class | Lex | Dom | Beh | ML (RF / CNN) | TI | Final Score | Why Fusion Missed (Threshold $\ge 31$) |
|---|---|---|---|---|---|---|---|---|
| `2eb9ce77d3` | Phishing | 0.0 | 10.0 | 0.0 | 32.2 (23.6 / 40.7) | 80.0 | **22.59** | Cloudflare blocked page (403). Beh=0.0 & Lex=0.0 pulled score down despite TI=80.0. |
| `3147917fc4` | Phishing | 9.3 | 25.0 | 0.0 | 36.1 (3.2 / 50.2) | 0.0 | **19.78** | Hosted on pages.dev. No live form detected (Beh=0.0). TI not run. Dom=25 & ML=36.1 suppressed. |
| `27852490e1` | Phishing | 1.4 | 25.0 | 0.0 | 30.7 (85.9 / 7.0) | 0.0 | **16.5** | Blogspot scam. Beh=0.0, Lex=1.4. CNN (7.0) disagreed with RF (85.9). |
| `1ffd6e36e4` | Phishing | 0.0 | 25.0 | 0.0 | 73.2 (83.6 / 62.8) | 0.0 | **28.96** | Blogspot scam. Strong ML (73.2), but zero lexical and zero behavior signals held it at 28.96. |
| `22d7f3327b` | Phishing | 0.0 | 25.0 | 0.0 | 42.8 (78.1 / 27.7) | 80.0 | **28.86** | TI had 80.0, but zero lexical (0.0) and zero behavior (0.0) pulled final score under 31. |
| `71eef02fd9` | Phishing | 4.7 | 25.0 | 10.0 | 17.1 (21.2 / 13.0) | 0.0 | **15.22** | Render-hosted lure. Weak lexical patterns (4.7) and low ML (17.1). |
| `2dd8d3f5e3` | Phishing | 10.8 | 25.0 | 0.0 | 53.9 (45.6 / 57.5) | 0.0 | **25.44** | Pages.dev Cloudflare phishing block (403). Beh=0.0 diluted moderate ML (53.9). |
| `1ca30f6a40` | Phishing | 10.3 | 25.0 | 0.0 | 65.8 (54.7 / 77.0) | 0.0 | **28.9** | Blogspot scam. CNN flagged 77.0, ML ensemble 65.8, but Beh=0.0 suppressed final score to 28.90. |
| `6ab0834b95` | Phishing | 0.4 | 10.0 | 0.0 | 65.3 (49.0 / 72.3) | 0.0 | **22.47** | Gitbook crypto lure. Inherited old gitbook domain age (Dom=10). Beh=0.0 suppressed ML (65.3). |
| `3c46240198` | Phishing | 0.7 | 10.0 | 0.0 | 75.6 (32.9 / 93.9) | 0.0 | **25.63** | Gitbook lure. CNN was 93.9, ML 75.6. Suppressed by Dom=10 and Beh=0.0. |
| `b4a9ab9d19` | Phishing | 2.4 | 25.0 | 0.0 | 36.6 (58.9 / 27.0) | 100.0 | **30.71** | 404 Blog removed. VT gave 100.0, but Lex=2.4 and Beh=0.0 left final score at 30.71 (missed by 0.29!). |
| `9260a89908` | Phishing | 12.3 | 25.0 | 0.0 | 41.4 (1.4 / 58.6) | 0.0 | **22.0** | Pages.dev crypto lure. No form detected. Beh=0.0 and RF=1.4 pulled score down. |
| `f3c990233d` | Phishing | 0.3 | 25.0 | 0.0 | 45.6 (72.1 / 34.2) | 0.0 | **20.74** | Blogspot lottery lure. Lex=0.3, Beh=0.0. |
| `73a45b5839` | Phishing | 3.0 | 25.0 | 0.0 | 31.8 (27.7 / 35.9) | 100.0 | **29.59** | Cloudflare blocked phishing (403). VT was 100.0, but Lex=3.0, Beh=0.0, ML=31.8 capped score at 29.59. |

---

## 3. Website Behavior Engine Telemetry

The Behavior Engine navigates live targets using Playwright headless Chromium inside a sandboxed Docker container. Below is the full telemetry breakdown across the **39 phishing pages analyzed** (1 excluded due to DNS failure) and the **50 legitimate pages**.

### Behavior Category Summary

| Category | Phishing Pages ($N=39$) | Legitimate Pages ($N=50$) | Forensic Meaning |
|---|---|---|---|
| **Bot-Check / Captcha Interstitial** | **13 (33.3%)** | 2 (4.0%) | Cloudflare `Suspected Phishing` (HTTP 403) or anti-bot challenge blocked automated rendering. |
| **Takedown or Error Page** | **6 (15.4%)** | 16 (32.0%) | HTTP 404, blog removed, account suspended, or connection timeout. |
| **Live Phishing / Login Form** | **2 (5.1%)** | 4 (8.0%) | Active HTML `<form>` with password inputs and credential capture mechanisms. |
| **Benign or Cloaked Page** | **18 (46.2%)** | 28 (56.0%) | Rendered 200 OK without login forms (static text lures, cloaked redirects, or normal homepages). |

### Key Telemetry Indicators

| Telemetry Signal | Phishing Count ($N=39$) | Legit Count ($N=50$) | Analysis |
|---|---|---|---|
| `has_login_form` | 3 (7.7%) | 4 (8.0%) | Phishing pages rarely render raw login forms to headless bots due to Cloudflare blocks and takedowns. |
| `external_form_action` | 0 (0.0%) | 2 (4.0%) | Modern phishing submits via AJAX/fetch or relative backend endpoints (`/loginbaru`). |
| `has_hidden_iframe` | 2 (5.1%) | 12 (24.0%) | Common on high-traffic benign sites for analytics / ad tracking; rare on ephemeral phishing. |
| `has_js_redirect` | 1 (2.6%) | 7 (14.0%) | Frequently used by legitimate CDNs and SSO gateways. |
| Redirect Occurred | 9 (23.1%) | 22 (44.0%) | HTTP 301/302 redirects to HTTPS or authentication landing pages. |

### Detailed Phishing Behavior Telemetry ($N=39$)

| Hashed ID | HTTP Status | Redirected | Title Snippet | Login Form | Ext Action | Iframe | JS Redir | Category |
|---|---|---|---|---|---|---|---|---|
| `sha256:2eb9ce77` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:3147917f` | 200 | False | Coinbase Advanced | False | False | False | False | `benign or cloaked page` |
| `sha256:df5924a3` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:3e4a9433` | 404 | False | Site not found &middot; GitHub | True | False | False | False | `takedown or error page` |
| `sha256:8dee31ea` | 200 | True | Get Free Robux | False | False | False | False | `benign or cloaked page` |
| `sha256:a8df4dfa` | 403 | False | Suspected Malware | Cloudflare | False | False | False | False | `bot-check/captcha` |
| `sha256:9fbbf7a6` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:27852490` | 200 | True | SHOPEE | False | False | False | False | `benign or cloaked page` |
| `sha256:aa54de02` | 403 | False | Suspected Malware | Cloudflare | False | False | False | False | `bot-check/captcha` |
| `sha256:1ffd6e36` | 404 | False | Blog not found | False | False | False | False | `takedown or error page` |
| `sha256:9e82dd2f` | 404 | False | Blog not found | False | False | False | False | `takedown or error page` |
| `sha256:8b5a8b12` | 403 | False | Suspected Malware | Cloudflare | False | False | False | False | `bot-check/captcha` |
| `sha256:0da859a4` | 404 | False | This app isn&#39;t live yet | False | False | False | False | `takedown or error page` |
| `sha256:4c9c1e40` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:22d7f332` | 200 | True | SHOPEE INDONESIA | False | False | False | False | `benign or cloaked page` |
| `sha256:6bdf93fa` | 200 | False | Netflix | True | False | True | False | `live phishing form` |
| `sha256:71eef02f` | 200 | False | Meta | Community Standards Vio | False | False | False | True | `benign or cloaked page` |
| `sha256:a4039730` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:2dd8d3f5` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:1ca30f6a` | 200 | True | shopee | False | False | False | False | `benign or cloaked page` |
| `sha256:6ab0834b` | 200 | True | Blockchain Login | Buy Bitcoin | False | False | False | False | `benign or cloaked page` |
| `sha256:e49ef82c` | 200 | True | joe smith | False | False | False | False | `benign or cloaked page` |
| `sha256:bfd0858d` | 200 | True | facebook | False | False | False | False | `benign or cloaked page` |
| `sha256:f51a5aae` | 404 | False | Blog not found | False | False | False | False | `takedown or error page` |
| `sha256:f9935193` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:3c462401` | 200 | True | 𝗠𝗲𝘁å𝗺å𝘀𝗸 @ 𝗟𝗼𝗴𝗶𝗻 | False | False | False | False | `benign or cloaked page` |
| `sha256:40513673` | 200 | False | DIxanPoarninaYT - Roblox | False | False | False | False | `benign or cloaked page` |
| `sha256:6a27f3f9` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:b4a9ab9d` | 404 | False | Blog not found | False | False | False | False | `takedown or error page` |
| `sha256:5b7fb9fc` | 200 | False | Dante - Roblox | False | False | True | False | `benign or cloaked page` |
| `sha256:eaf75d2f` | 200 | False | Netflix India - Watch TV Shows | False | False | False | False | `benign or cloaked page` |
| `sha256:9260a899` | 200 | False | Coinbase Advanced | False | False | False | False | `benign or cloaked page` |
| `sha256:91ea20bf` | 200 | False | Webmail Sign-in | True | False | False | False | `live phishing form` |
| `sha256:dca92b57` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:5aa554a1` | 200 | False | HADIAH RESMI SHOPEE 2023 | False | False | False | False | `benign or cloaked page` |
| `sha256:f3c99023` | 200 | True | shopee | False | False | False | False | `benign or cloaked page` |
| `sha256:73a45b58` | 403 | False | Suspected Phishing | Cloudflar | False | False | False | False | `bot-check/captcha` |
| `sha256:72124120` | 200 | False | Online Hardware and Software R | False | False | False | False | `benign or cloaked page` |
| `sha256:d6e89cee` | 451 | False | Deployment Unavailable | False | False | False | False | `benign or cloaked page` |

### Detailed Legitimate Behavior Telemetry ($N=50$)

| URL | HTTP Status | Redirected | Title Snippet | Login Form | Ext Action | Iframe | JS Redir | Category |
|---|---|---|---|---|---|---|---|---|
| `https://inkuai.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://xiaomi.com` | 200 | True | Xiaomi India | Smartphone | Ta | False | False | False | True | `benign or cloaked page` |
| `https://verify.hn` | 0 | False | Error: ConnectTimeout | False | False | False | False | `takedown or error page` |
| `https://people.com.cn` | 200 | True | 人民网_网上的人民日报 | False | False | False | False | `benign or cloaked page` |
| `https://dpbosssss.mobi` | 200 | False | DPBOSS | SATTA MATKA | KALYAN  | False | False | False | False | `benign or cloaked page` |
| `https://xhamster2.com` | 200 | False | Free Porn Videos &amp; XXX Mov | False | False | False | False | `benign or cloaked page` |
| `https://lg.com` | 403 | True | Access Denied | False | False | False | False | `benign or cloaked page` |
| `https://china.com.cn` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://2gis.com` | 200 | True | 2GIS | False | False | False | True | `benign or cloaked page` |
| `https://avg.com` | 200 | True | AVG 2026 | FREE Antivirus, VPN | False | False | False | False | `benign or cloaked page` |
| `https://steampowered.com` | 200 | True | Welcome to Steam | False | False | False | False | `benign or cloaked page` |
| `https://slack.com` | 200 | True | Slack | AI work platform and p | False | False | True | False | `benign or cloaked page` |
| `https://ddns.net` | 0 | False | Error: ConnectTimeout | False | False | False | False | `takedown or error page` |
| `https://egramswaraj.gov.in` | 200 | False | eGramSwaraj-222-2 | False | False | False | False | `benign or cloaked page` |
| `https://hetzner.com` | 200 | True | Dedicated Servers, Cloud &amp; | False | False | False | False | `benign or cloaked page` |
| `https://ualberta.ca` | 200 | True | University of Alberta | False | False | True | False | `benign or cloaked page` |
| `https://msftconnecttest.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://wondershare.com` | 200 | True | Wondershare - The Creator's Er | False | False | True | False | `benign or cloaked page` |
| `https://packzy.com` | 200 | False | Steadfast Courier Ltd | Fastes | False | False | False | False | `benign or cloaked page` |
| `https://chapturist.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://wikidot.com` | 200 | True | Wikidot - Free and Pro Wiki Ho | True | False | True | False | `live login form` |
| `https://apdcdn.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://feverup.com` | 200 | True | Discover the best Events in yo | False | False | False | False | `benign or cloaked page` |
| `https://uhc.com` | 200 | True | Health insurance plans | Unite | False | True | True | False | `benign or cloaked page` |
| `https://windowsupdate.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://adroll.com` | 200 | True | Multichannel Advertising & Acc | False | False | True | False | `benign or cloaked page` |
| `https://awsdns-51.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://unisoc.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://hpe.com` | 0 | False | Error: ReadTimeout | False | False | False | False | `takedown or error page` |
| `https://riotcdn.net` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://gree.jp` | 200 | False | GREE（グリー） | False | False | False | False | `benign or cloaked page` |
| `https://mheducation.com` | 200 | True | McGraw Hill | False | False | True | False | `benign or cloaked page` |
| `https://pornhub.com` | 0 | False | Error: ConnectError | False | False | True | True | `takedown or error page` |
| `https://fiverr.com` | 403 | True | It needs a human touch | False | False | True | False | `benign or cloaked page` |
| `https://tufts.edu` | 200 | True | Tufts University | False | False | True | False | `benign or cloaked page` |
| `https://wb.ru` | 498 | True | ... | False | False | False | True | `benign or cloaked page` |
| `https://myworkdayjobs.com` | 0 | False | Error: ConnectError | False | False | False | False | `takedown or error page` |
| `https://blismedia.com` | 403 | False | Just a moment... | False | True | False | True | `bot-check/captcha` |
| `https://lin.ee` | 404 | False | *(none)* | False | False | False | False | `takedown or error page` |
| `https://live-video.net` | 200 | False | Amazon.com Property | False | False | False | False | `benign or cloaked page` |
| `https://gitlab.com/users/sign_in` | 403 | False | Just a moment... | False | False | False | False | `bot-check/captcha` |
| `https://id.atlassian.com/login` | 202 | False | *(none)* | False | False | False | False | `benign or cloaked page` |
| `https://auth.docker.com/login` | 200 | True | *(none)* | True | False | False | True | `live login form` |
| `https://app.slack.com/login` | 404 | False | There’s been a glitch… | Slack | False | False | False | False | `takedown or error page` |
| `https://discord.com/login` | 200 | False | Discord | True | False | True | False | `live login form` |
| `https://www.reddit.com/login` | 200 | True | Reddit | False | False | False | False | `benign or cloaked page` |
| `https://login.salesforce.com` | 200 | False | Log In with Email | Salesforce | False | False | False | False | `benign or cloaked page` |
| `https://auth0.com/auth/login` | 200 | True | Log in | Auth0 Website | True | False | False | False | `live login form` |
| `https://zoom.us/signin` | 200 | False | Sign In | Zoom | False | False | True | False | `benign or cloaked page` |
| `https://www.notion.so/login` | 200 | True | Notion | False | False | False | True | `benign or cloaked page` |

---

## 4. Domain Intelligence & Infrastructure Analysis

Phishing campaigns have shifted dramatically toward legitimate cloud and free hosting providers to evade lexical filters and domain age penalties.

### Shared Hosting Platform Distribution ($N=40$ Phishing URLs)

| Hosting / PaaS Provider | Subdomain Pattern | Count | Percentage | Primary Evasion Vector |
|---|---|---|---|---|
| **Cloudflare Pages** | `*.pages.dev` | 12 | 30.0% | Free SSL, high-reputation CDN, Cloudflare automated protection against bots |
| **Google Blogger** | `*.blogspot.com` | 10 | 25.0% | High-reputation Google parent domain, trusted by email providers |
| **Cloudflare Workers** | `*.workers.dev` | 3 | 7.5% | Serverless backend with custom edge routing |
| **Vercel** | `*.vercel.app` | 2 | 5.0% | Instant static deployments with automatic TLS |
| **GitBook** | `*.gitbook.io` | 2 | 5.0% | Inherits 4,600+ day domain age from `gitbook.io` |
| **Replit** | `*.replit.app` | 1 | 2.5% | Live cloud-hosted app environment |
| **Firebase Hosting** | `*.web.app` | 1 | 2.5% | Google-backed CDN domain |
| **GitHub Pages** | `*.github.io` | 1 | 2.5% | Developer-trusted hosting reputation |
| **Render** | `*.onrender.com` | 1 | 2.5% | Cloud platform deployment |
| **Total on Shared Hosting** | | **33 / 40** | **82.5%** | **Massive reliance on shared cloud infrastructure** |

### WHOIS Failure Breakdown
- **WHOIS Lookup Failed / Unavailable:** **33 / 40 (82.5%)** phishing URLs.
- **Root Cause:** Standard WHOIS servers query root registrar domains (`pages.dev`, `blogspot.com`, `workers.dev`). Subdomains do not possess independent registration records. Furthermore, ccTLDs (.so, .site, .rw) frequently redact or rate-limit automated WHOIS queries.
- **WHOIS Succeeded:** Only 7 / 40 phishing URLs returned a valid domain registration age: 2 were freshly registered lookalikes (`roblox.co` - 3 days old, `roblox.rw` - 41 days old), 1 was a staging pastebin (`sharemyhtml.com` - 237 days old), and 4 inherited the multi-year age of parent platforms (`gitbook.io`, `apper.so`, `cpanel.site`).

---

## 5. Threat Intelligence & VirusTotal Vendor Breakdown

For the 20 phishing URLs queried against the VirusTotal v3 API (`/api/v3/urls/{id}`):
- **OpenPhish Presence on VirusTotal:** OpenPhish **is an active threat intelligence vendor** on VirusTotal (`engine_name: "OpenPhish"`, `method: "blacklist"`).
- **OpenPhish Detection Rate:** OpenPhish alone flagged **19 out of the 20 (95.0%)** phishing URLs.

### Vendor Detection Ranking Across the 20 Phishing URLs

| Rank | Security Vendor / Engine | URLs Flagged (out of 20) | Detection Rate | Primary Classification Category |
|---|---|---|---|---|
| 1 | **G-Data** | 20 / 20 | 100.0% | `malicious` / `phishing` |
| 2 | **Webroot** | 20 / 20 | 100.0% | `malicious` / `phishing` |
| 3 | **Lionic** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 4 | **Fortinet** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 5 | **Gridinsoft** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 6 | **OpenPhish** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 7 | **SOCRadar** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 8 | **Sophos** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 9 | **Forcepoint ThreatSeeker** | 19 / 20 | 95.0% | `malicious` / `phishing` |
| 10 | **BitDefender** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 11 | **ESET** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 12 | **Kaspersky** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 13 | **Cluster25** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 14 | **Emsisoft** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 15 | **Netcraft** | 18 / 20 | 90.0% | `malicious` / `phishing` |
| 16 | **URLQuery** | 16 / 20 | 80.0% | `malicious` / `phishing` |
| 17 | **alphaMountain.ai** | 16 / 20 | 80.0% | `malicious` / `phishing` |
| 18 | **DNS8** | 13 / 20 | 65.0% | `malicious` / `phishing` |
| 19 | **LevelBlue** | 12 / 20 | 60.0% | `malicious` / `phishing` |
| 20 | **VIPRE** | 11 / 20 | 55.0% | `malicious` / `phishing` |

> **Forensic Implication:** Testing OpenPhish-sourced URLs against VirusTotal is not an independent zero-day test because OpenPhish directly feeds VirusTotal's vendor consensus. A true zero-day phishing benchmark must utilize freshly observed URLs before any feed ingestion.

---

## 6. What This Benchmark Does and Does Not Show

### What This Does NOT Show
1. **No Zero-Day Phishing Evidence:** The original zero-day hypothesis (that PhishLens detects phishing pages unknown to VirusTotal) was not substantiated here. Exactly **0 of the 20** phishing URLs tested on VirusTotal returned a 404 `never_seen_before` response. Every tested phishing URL had already been indexed by VirusTotal.
2. **No High-Risk Categorization (>=61):** Zero phishing URLs ($0/40$) reached the high-risk warning threshold (>=61). The system's heuristic fusion weights (0.21 lexical, 0.28 domain, 0.21 behavior, 0.30 ML) excessively dilute the ML prediction when behavior returns 0.0 on dead/blocked sites and domain WHOIS fails.
3. **Severe Distribution Shift vs. In-Distribution (92%):** The models achieved ~92% accuracy on synthetic/historical datasets, but when confronted with live in-the-wild OpenPhish feeds, offline recall dropped to **50.0% [35.2%, 64.8%]**.
4. **Small Sample Limits:** $N = 90$ yields wide confidence intervals (e.g. $[49.5\%, 77.9\%]$ for fusion recall). While mathematically rigorous, the sample size cannot provide sub-percent error bounds.
5. **Infrastructure Domain Bias & Unreachable Pages:** The legitimate sample includes infrastructure domains users never click (e.g., `msftconnecttest.com`, `windowsupdate.com`, `awsdns-51.com`), and 16 of 50 legitimate pages were error, takedown or timeouts.

### What This Benchmark DOES Show
1. **Character-Level Deep CNN is Resilient:** Stand-alone Deep CNN achieved **80.0% recall** and **18.0% FPR**, better at these settings on this sample (exact McNemar p = 0.0044) than heuristic fusion. Note that the McNemar comparison uses different flag thresholds (31 and 50), so it describes those settings on this sample; an AUC comparison would be fairer.
2. **Domain & Behavior Vulnerability to Modern Infrastructure:** 82.5% of modern phishing relies on shared cloud providers (`pages.dev`, `blogspot.com`, `workers.dev`), completely neutralizing domain age signals and evading headless browser scrapers through Cloudflare interstitial challenges.
3. **Hard Negative Login Pages Challenge ML:** Well-known enterprise authentication portals (`auth.docker.com`, `auth0.com`, `id.atlassian.com`, `app.slack.com`) trigger false positive alerts due to lexical keyword overlap (`/login`, `auth`).

---

## 7. The Base-Rate Caveat: Real-World Precision at 1% Phishing Prevalence

Benchmark metrics computed on a balanced or semi-balanced test set (40 phishing / 50 legitimate) drastically overstate the real-world precision experienced by users.

In live consumer web browsing and enterprise email environments, using an assumed illustrative prevalence of 1% (not measured) ($P(\text{Phish}) = 0.01$, $P(\text{Legit}) = 0.99$):

### Bayes' Theorem Formulation
$$\text{Precision}_{1\%} = \frac{\text{Recall} \times P(\text{Phish})}{(\text{Recall} \times P(\text{Phish})) + (\text{FPR} \times P(\text{Legit}))}$$

### Projected Real-World Precision Table

| Model / Configuration | Test Recall | Test FPR | Test Precision (50/40) | **Real-World Precision (1% Base Rate)** | Expected False Alarm Ratio |
|---|---|---|---|---|---|
| **Fusion >=31 (Threat Intel Excluded)** | 50.0% | 20.0% | 66.7% | **2.46%** | ~40 false alarms per 1 true phish |
| **Fusion >=31 (Standard Full)** | 65.0% | 18.0% | 74.3% | **3.52%** | ~27 false alarms per 1 true phish |
| **Deep CNN Alone (>=50)** | 80.0% | 18.0% | 78.0% | **4.30%** | ~22 false alarms per 1 true phish |
| **ML Ensemble Alone (>=50)** | 75.0% | 20.0% | 75.0% | **3.65%** | ~26 false alarms per 1 true phish |
| **Random Forest Alone (>=50)** | 57.5% | 36.0% | 56.1% | **1.59%** | ~62 false alarms per 1 true phish |

> **Critical Operational Conclusion:** Even with an apparent 74.3% precision on a curated benchmark, an 18% false positive rate at a 1% base rate results in a real-world precision of only **3.52%**. Out of every 100 browser extension warnings displayed to a user, **approximately 96 to 97 will be false alarms** unless an explicit allowlist or high-confidence domain reputation filter is placed ahead of heuristic evaluation.
