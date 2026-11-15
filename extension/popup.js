import { isScannable, unwrapRedirect, sourceFor, buildDashboardUrl } from "./lib/urls.js";

const DEFAULT_API_URL = "https://phishlens-doyc.onrender.com";
const DEFAULT_DASHBOARD_URL = "http://localhost:5173";

const SOURCE_LABELS = {
  email: "Email",
  social_media: "Social Media",
  message: "Message"
};

const SCAN_STEPS = [
  "Extracting lexical URL features…",
  "Checking WHOIS domain intelligence…",
  "Evaluating website security & forms…",
  "Running Random Forest & Deep CNN models…",
  "Querying VirusTotal threat intelligence…",
  "Computing explainable weighted fusion…"
];

document.addEventListener("DOMContentLoaded", async () => {
  // Views
  const viewInitial = document.getElementById("view-initial");
  const viewLoading = document.getElementById("view-loading");
  const viewResults = document.getElementById("view-results");
  const viewError = document.getElementById("view-error");

  // Initial view elements
  const urlDisplay = document.getElementById("active-url");
  const sourceBadge = document.getElementById("source-badge");
  const unwrappedContainer = document.getElementById("unwrapped-container");
  const unwrappedUrlDisplay = document.getElementById("unwrapped-url");
  const warningBox = document.getElementById("warning-message");
  const scanBtn = document.getElementById("scan-btn");

  // Loading elements
  const loadingStepText = document.getElementById("loading-step-text");

  // Results elements
  const resScoreCircle = document.getElementById("res-score-circle");
  const resScoreValue = document.getElementById("res-score-value");
  const resVerdictTitle = document.getElementById("res-verdict-title");
  const resVerdictGuarantee = document.getElementById("res-verdict-guarantee");
  const resVerdictMeta = document.getElementById("res-verdict-meta");

  const engLexicalScore = document.getElementById("eng-lexical-score");
  const engLexicalLen = document.getElementById("eng-lexical-len");
  const engLexicalEntropy = document.getElementById("eng-lexical-entropy");
  const engLexicalKeywords = document.getElementById("eng-lexical-keywords");
  const engLexicalRow = document.getElementById("eng-lexical");

  const engDomainScore = document.getElementById("eng-domain-score");
  const engDomainAge = document.getElementById("eng-domain-age");
  const engDomainSsl = document.getElementById("eng-domain-ssl");
  const engDomainReg = document.getElementById("eng-domain-reg");
  const engDomainRow = document.getElementById("eng-domain");

  const engBehaviorScore = document.getElementById("eng-behavior-score");
  const engBehaviorLogin = document.getElementById("eng-behavior-login");
  const engBehaviorRedirect = document.getElementById("eng-behavior-redirect");
  const engBehaviorRow = document.getElementById("eng-behavior");

  const engMlScore = document.getElementById("eng-ml-score");
  const engMlPred = document.getElementById("eng-ml-pred");
  const engMlAgree = document.getElementById("eng-ml-agree");
  const engMlConf = document.getElementById("eng-ml-conf");
  const engMlRow = document.getElementById("eng-ml");

  const engTiScore = document.getElementById("eng-ti-score");
  const engTiEngines = document.getElementById("eng-ti-engines");
  const engTiRow = document.getElementById("eng-ti");

  const resScanAnotherBtn = document.getElementById("res-scan-another-btn");
  const resOpenDashboardBtn = document.getElementById("res-open-dashboard-btn");

  // Error elements
  const errorTitle = document.getElementById("error-title");
  const errorText = document.getElementById("error-text");
  const errRetryBtn = document.getElementById("err-retry-btn");
  const errBackBtn = document.getElementById("err-back-btn");

  // Navigation
  const optionsBtn = document.getElementById("open-options-btn");
  const optionsLink = document.getElementById("options-link");

  let stepInterval = null;
  let targetScanUrl = "";
  let targetSource = null;

  function setView(viewName) {
    viewInitial.style.display = viewName === "initial" ? "block" : "none";
    viewLoading.style.display = viewName === "loading" ? "block" : "none";
    viewResults.style.display = viewName === "results" ? "block" : "none";
    viewError.style.display = viewName === "error" ? "block" : "none";
  }

  const openOptions = () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL("options.html"));
    }
  };

  optionsBtn?.addEventListener("click", openOptions);
  optionsLink?.addEventListener("click", (e) => {
    e.preventDefault();
    openOptions();
  });

  // Query Active Tab (or read ?url= if provided for testing)
  const searchParams = new URLSearchParams(window.location.search);
  let rawUrl = searchParams.get("url");
  if (!rawUrl) {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    rawUrl = activeTab?.url || "";
  }

  urlDisplay.textContent = rawUrl || "No active tab URL found";
  urlDisplay.title = rawUrl;

  const unwrappedUrl = unwrapRedirect(rawUrl);
  const isUnwrapped = unwrappedUrl !== rawUrl;

  if (isUnwrapped) {
    unwrappedContainer.style.display = "block";
    unwrappedUrlDisplay.textContent = unwrappedUrl;
    unwrappedUrlDisplay.title = unwrappedUrl;
  } else {
    unwrappedContainer.style.display = "none";
  }

  targetScanUrl = unwrappedUrl;
  targetSource = sourceFor(rawUrl) || "email";

  if (targetSource && SOURCE_LABELS[targetSource]) {
    sourceBadge.textContent = SOURCE_LABELS[targetSource];
    sourceBadge.classList.add("active");
  } else {
    sourceBadge.textContent = "Direct / Web";
    sourceBadge.classList.remove("active");
  }

  const scannable = isScannable(unwrappedUrl);
  if (!scannable) {
    scanBtn.disabled = true;
    warningBox.style.display = "block";
    if (rawUrl.length > 2048) {
      warningBox.textContent = "URL exceeds 2048 characters limit and cannot be scanned.";
    } else {
      warningBox.textContent = "Only http:// and https:// pages can be scanned. Browser, system, and local file pages are not supported.";
    }
  } else {
    scanBtn.disabled = false;
    warningBox.style.display = "none";
  }

  function startStepAnimation() {
    let index = 0;
    loadingStepText.textContent = SCAN_STEPS[0];
    stepInterval = setInterval(() => {
      index = (index + 1) % SCAN_STEPS.length;
      loadingStepText.textContent = SCAN_STEPS[index];
    }, 1400);
  }

  function stopStepAnimation() {
    if (stepInterval) {
      clearInterval(stepInterval);
      stepInterval = null;
    }
  }

  function renderResults(data) {
    const finalScore = Math.max(0, Math.min(100, Math.round(data.final_risk_score ?? 0)));
    resScoreValue.textContent = String(finalScore);

    // Score Bands: 0-30 LOW RISK, 31-60 MEDIUM RISK, 61-100 HIGH RISK
    // Never use words "safe" or "legitimate" as a verdict!
    resScoreCircle.className = "score-circle";
    resVerdictTitle.className = "verdict-title";

    if (finalScore <= 30) {
      resScoreCircle.classList.add("low");
      resVerdictTitle.classList.add("low");
      resVerdictTitle.textContent = "LOW RISK";
      resVerdictGuarantee.textContent = "No red flags found. This is not a guarantee.";
      resVerdictGuarantee.style.display = "block";
    } else if (finalScore <= 60) {
      resScoreCircle.classList.add("medium");
      resVerdictTitle.classList.add("medium");
      resVerdictTitle.textContent = "MEDIUM RISK";
      resVerdictGuarantee.textContent = "Suspicious indicators detected.";
      resVerdictGuarantee.style.display = "block";
    } else {
      resScoreCircle.classList.add("high");
      resVerdictTitle.classList.add("high");
      resVerdictTitle.textContent = "HIGH RISK";
      resVerdictGuarantee.textContent = "High probability of phishing or malicious activity.";
      resVerdictGuarantee.style.display = "block";
    }

    // Score calculated from X of Y engines note
    const hasFailed = (data.engines_failed && data.engines_failed.length > 0) ||
                      (data.engines_incomplete && data.engines_incomplete.length > 0);
    const enginesUsedCount = data.engines_used ? data.engines_used.length : 5;

    if (hasFailed) {
      resVerdictMeta.textContent = `Score calculated from ${enginesUsedCount} of 5 engines`;
    } else {
      resVerdictMeta.textContent = "Score calculated from 5 engines";
    }

    // 1. Lexical Analysis
    if (data.lexical_analysis) {
      const lex = data.lexical_analysis;
      const score = Math.round(lex.lexical_score);
      engLexicalScore.textContent = `${score}/100`;
      engLexicalScore.className = "engine-score";
      engLexicalLen.textContent = `Length: ${lex.url_length} chars`;
      engLexicalEntropy.textContent = `Entropy: ${lex.entropy_score.toFixed(2)}`;
      engLexicalKeywords.textContent = lex.has_suspicious_keywords ? "⚠️ Suspicious keywords" : "No suspicious keywords";
      engLexicalRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 2. Domain Intelligence
    if (data.domain_analysis) {
      const dom = data.domain_analysis;
      const score = Math.round(dom.domain_score);
      engDomainScore.textContent = `${score}/100`;
      engDomainScore.className = "engine-score";
      const ageDays = dom.domain_age_days;
      engDomainAge.textContent = ageDays !== null ? (ageDays >= 365 ? `Age: ${Math.floor(ageDays/365)} yrs` : `Age: ${ageDays} days`) : "Age: Unknown";
      engDomainSsl.textContent = dom.ssl_valid ? "SSL: Valid" : "SSL: Invalid";
      engDomainReg.textContent = dom.registrar ? `Reg: ${dom.registrar.split(/[,.]/)[0]}` : "Reg: Unknown";
      engDomainRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 3. Website Behavior
    if (data.behavior_analysis) {
      const beh = data.behavior_analysis;
      if (beh.behavior_analysis_failed) {
        // Greyed out with N/A and reason (NEVER a green 0/100)
        engBehaviorScore.textContent = "N/A";
        engBehaviorScore.className = "engine-score na";
        engBehaviorRow.className = "engine-row failed";

        let reasonText = "Analysis failed — site blocked automated access or timed out";
        if (beh.behavior_failure_reason === "dns_failure") {
          reasonText = "Analysis failed — domain unreachable";
        } else if (beh.behavior_failure_reason === "timeout") {
          reasonText = "Analysis failed — request timed out";
        } else if (beh.behavior_failure_reason === "blocked") {
          reasonText = "Analysis failed — site blocked automated access";
        } else if (beh.behavior_failure_reason === "blocked_private_address") {
          reasonText = "Analysis blocked — target resolves to a private/internal address";
        }
        engBehaviorLogin.textContent = reasonText;
        engBehaviorRedirect.textContent = "";
      } else {
        const score = Math.round(beh.behavior_score);
        engBehaviorScore.textContent = `${score}/100`;
        engBehaviorScore.className = "engine-score";
        engBehaviorLogin.textContent = beh.has_login_form ? "⚠️ Login form found" : "No login form";
        engBehaviorRedirect.textContent = beh.has_js_redirect ? "⚠️ Redirects detected" : "No redirects";
        engBehaviorRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
      }
    }

    // 4. ML Ensemble
    if (data.ml_analysis) {
      const ml = data.ml_analysis;
      const score = Math.round(ml.ml_score);
      engMlScore.textContent = `${score}/100`;
      engMlScore.className = "engine-score";
      engMlPred.textContent = ml.prediction === "phishing" ? "RF/CNN: Phishing flag" : "RF/CNN: Baseline flag clear";
      engMlAgree.textContent = ml.models_agreed ? "Models agree" : "Disagree — CNN weighted";
      engMlConf.textContent = `${((ml.confidence ?? 0.9) * 100).toFixed(0)}% conf`;
      engMlRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 5. Threat Intelligence
    if (data.threat_intelligence_analysis) {
      const ti = data.threat_intelligence_analysis;
      if (ti.never_seen_before) {
        // Never seen before: sky blue, N/A score
        engTiScore.textContent = "N/A";
        engTiScore.className = "engine-score na";
        engTiEngines.textContent = "No prior reports — URL never seen by VirusTotal";
        engTiRow.className = "engine-row sky";
      } else if (ti.rate_limited_incomplete) {
        // Rate limited: amber, N/A score
        engTiScore.textContent = "N/A";
        engTiScore.className = "engine-score na";
        engTiEngines.textContent = "Rate-limited — analysis incomplete, excluded from score";
        engTiRow.className = "engine-row amber";
      } else if (ti.threat_intel_failed) {
        engTiScore.textContent = "N/A";
        engTiScore.className = "engine-score na";
        engTiEngines.textContent = "Analysis failed — threat intel lookup timed out";
        engTiRow.className = "engine-row failed";
      } else {
        const score = Math.round(ti.threat_score);
        engTiScore.textContent = `${score}/100`;
        engTiScore.className = "engine-score";
        engTiEngines.textContent = `${ti.total_engines_flagged} of ${ti.total_engines_checked} engines flagged`;
        engTiRow.className = `engine-row ${score === 0 ? "green" : score <= 30 ? "amber" : "red"}`;
      }
    }

    setView("results");
  }

  async function performScan() {
    setView("loading");
    startStepAnimation();

    const storage = await chrome.storage.sync.get({
      apiUrl: DEFAULT_API_URL,
      dashboardUrl: DEFAULT_DASHBOARD_URL
    });

    let apiBase = (storage.apiUrl || DEFAULT_API_URL).trim().replace(/\/+$/, "");
    if (apiBase === "https://phishlens-1-27oz.onrender.com") {
      apiBase = "https://phishlens-doyc.onrender.com";
    }
    if (searchParams.get("api")) {
      apiBase = searchParams.get("api");
    }

    try {
      const response = await fetch(`${apiBase}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url: targetScanUrl,
          source: targetSource || "email"
        })
      });

      stopStepAnimation();

      if (!response.ok) {
        let msg = "";
        if (response.status === 503) {
          msg = "Scanner busy, try again";
        } else {
          // Attempt to extract dynamic detail message from backend response (e.g. dynamic 429 limit message)
          try {
            const errText = await response.text();
            if (errText) {
              try {
                const body = JSON.parse(errText);
                if (body?.detail) {
                  msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
                }
              } catch {
                msg = errText.slice(0, 120);
              }
            }
          } catch {
            // ignore parse errors
          }
          if (!msg) {
            if (response.status === 429) {
              msg = "Rate limit exceeded. Please try again later.";
            } else {
              msg = `Request failed with status ${response.status}`;
            }
          }
        }
        throw new Error(msg);
      }

      const text = await response.text();
      if (!text || !text.trim()) {
        throw new Error(`Empty response received from backend (${apiBase}). Please make sure the PhishLens backend server is running.`);
      }

      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Invalid response received from backend (${apiBase}). Expected JSON scan verdict.`);
      }

      renderResults(data);
    } catch (err) {
      stopStepAnimation();
      const rawMsg = err instanceof Error ? err.message : "Unable to reach PhishLens backend server.";
      errorTitle.textContent = "⚠️ Scan Failed";
      if (rawMsg.includes("Failed to fetch") || rawMsg.includes("NetworkError")) {
        errorText.textContent = `Network error: Unable to connect to PhishLens backend at ${apiBase}. Please verify the backend is running or update Settings.`;
      } else {
        errorText.textContent = rawMsg;
      }
      setView("error");
    }
  }

  // Scans are initiated exclusively when the user clicks the scan button (never on open)
  scanBtn.addEventListener("click", performScan);
  errRetryBtn.addEventListener("click", performScan);
  errBackBtn.addEventListener("click", () => setView("initial"));
  resScanAnotherBtn.addEventListener("click", () => setView("initial"));

  resOpenDashboardBtn.addEventListener("click", async () => {
    const storage = await chrome.storage.sync.get({
      dashboardUrl: DEFAULT_DASHBOARD_URL
    });
    let dashboardBase = (storage.dashboardUrl || DEFAULT_DASHBOARD_URL).trim().replace(/\/+$/, "");
    if (dashboardBase === "https://phishlens-1-27oz.onrender.com") {
      dashboardBase = DEFAULT_DASHBOARD_URL;
    }
    const targetUrl = buildDashboardUrl(dashboardBase, targetScanUrl, targetSource);
    await chrome.tabs.create({ url: targetUrl });
  });
});
