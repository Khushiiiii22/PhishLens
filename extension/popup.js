import { isScannable, unwrapRedirect, sourceFor, buildDashboardUrl } from "./lib/urls.js";

const DEFAULT_API_URL = "http://127.0.0.1:8000";
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
  const errorText = document.getElementById("error-text");
  const errRetryBtn = document.getElementById("err-retry-btn");
  const errBackBtn = document.getElementById("err-back-btn");

  // Navigation
  const optionsBtn = document.getElementById("open-options-btn");
  const optionsLink = document.getElementById("options-link");

  let stepInterval = null;
  let currentResult = null;
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

  // Query Active Tab
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const rawUrl = activeTab?.url || "";

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
    currentResult = data;
    const finalScore = Math.max(0, Math.min(100, Math.round(data.final_risk_score ?? 0)));
    resScoreValue.textContent = String(finalScore);

    // Score Circle & Verdict
    resScoreCircle.className = "score-circle";
    resVerdictTitle.className = "verdict-title";

    if (finalScore <= 30) {
      resScoreCircle.classList.add("legit");
      resVerdictTitle.classList.add("legit");
      resVerdictTitle.textContent = "LEGITIMATE / SAFE";
    } else if (finalScore <= 60) {
      resScoreCircle.classList.add("suspicious");
      resVerdictTitle.classList.add("suspicious");
      resVerdictTitle.textContent = "SUSPICIOUS ACTIVITY";
    } else {
      resScoreCircle.classList.add("phish");
      resVerdictTitle.classList.add("phish");
      resVerdictTitle.textContent = "PHISHING DETECTED";
    }

    const enginesUsedCount = data.engines_used ? data.engines_used.length : 5;
    resVerdictMeta.textContent = `Score fused from ${enginesUsedCount} of 5 detection engines`;

    // 1. Lexical
    if (data.lexical_analysis) {
      const lex = data.lexical_analysis;
      const score = Math.round(lex.lexical_score);
      engLexicalScore.textContent = `${score}/100`;
      engLexicalLen.textContent = `Len: ${lex.url_length}`;
      engLexicalEntropy.textContent = `Entropy: ${lex.entropy_score.toFixed(2)}`;
      engLexicalKeywords.textContent = lex.has_suspicious_keywords ? "⚠️ Suspicious words" : "Clean keywords";
      engLexicalRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 2. Domain
    if (data.domain_analysis) {
      const dom = data.domain_analysis;
      const score = Math.round(dom.domain_score);
      engDomainScore.textContent = `${score}/100`;
      const ageDays = dom.domain_age_days;
      engDomainAge.textContent = ageDays !== null ? (ageDays >= 365 ? `${Math.floor(ageDays/365)} yrs` : `${ageDays} days`) : "Age: Unknown";
      engDomainSsl.textContent = dom.ssl_valid ? "SSL: Valid" : "SSL: Invalid";
      engDomainReg.textContent = dom.registrar ? dom.registrar.split(/[,.]/)[0] : "Registrar: Unknown";
      engDomainRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 3. Behavior
    if (data.behavior_analysis) {
      const beh = data.behavior_analysis;
      if (beh.behavior_analysis_failed) {
        engBehaviorScore.textContent = "N/A";
        engBehaviorLogin.textContent = "Analysis unavailable / domain unreachable";
        engBehaviorRedirect.textContent = "";
        engBehaviorRow.className = "engine-row failed";
      } else {
        const score = Math.round(beh.behavior_score);
        engBehaviorScore.textContent = `${score}/100`;
        engBehaviorLogin.textContent = beh.has_login_form ? "⚠️ Login form found" : "No login form";
        engBehaviorRedirect.textContent = beh.has_js_redirect ? "⚠️ Redirects" : "No redirect";
        engBehaviorRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
      }
    }

    // 4. ML Ensemble
    if (data.ml_analysis) {
      const ml = data.ml_analysis;
      const score = Math.round(ml.ml_score);
      engMlScore.textContent = `${score}/100`;
      engMlPred.textContent = ml.prediction === "phishing" ? "Predicted Phish" : "Predicted Legit";
      engMlAgree.textContent = ml.models_agreed ? "Models agree" : "Models disagree";
      engMlConf.textContent = `${((ml.confidence ?? 0.9) * 100).toFixed(0)}% conf`;
      engMlRow.className = `engine-row ${score <= 30 ? "green" : score <= 60 ? "amber" : "red"}`;
    }

    // 5. Threat Intel
    if (data.threat_intelligence_analysis) {
      const ti = data.threat_intelligence_analysis;
      if (ti.never_seen_before) {
        engTiScore.textContent = "—";
        engTiEngines.textContent = "No prior records (URL never seen by VirusTotal)";
        engTiRow.className = "engine-row failed";
      } else if (ti.rate_limited_incomplete) {
        engTiScore.textContent = "…";
        engTiEngines.textContent = "Rate-limited by threat intelligence provider";
        engTiRow.className = "engine-row failed";
      } else if (ti.threat_intel_failed) {
        engTiScore.textContent = "N/A";
        engTiEngines.textContent = "Lookup timed out";
        engTiRow.className = "engine-row failed";
      } else {
        const score = Math.round(ti.threat_score);
        engTiScore.textContent = `${score}/100`;
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

    const apiBase = storage.apiUrl || DEFAULT_API_URL;

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
        let msg = `Server error HTTP ${response.status}`;
        try {
          const body = await response.json();
          if (body && body.detail) {
            msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
          }
        } catch {
          // Keep generic
        }
        if (response.status === 503) {
          msg = "Scanner is currently busy analyzing another URL. Please try again in a moment.";
        } else if (response.status === 429) {
          msg = "Rate limit reached (10 scans per hour limit). Please try again later.";
        }
        throw new Error(msg);
      }

      const data = await response.json();
      renderResults(data);
    } catch (err) {
      stopStepAnimation();
      errorText.textContent = err instanceof Error ? err.message : "Unable to reach PhishLens backend server.";
      setView("error");
    }
  }

  scanBtn.addEventListener("click", performScan);
  errRetryBtn.addEventListener("click", performScan);
  errBackBtn.addEventListener("click", () => setView("initial"));
  resScanAnotherBtn.addEventListener("click", () => setView("initial"));

  resOpenDashboardBtn.addEventListener("click", async () => {
    const storage = await chrome.storage.sync.get({
      dashboardUrl: DEFAULT_DASHBOARD_URL
    });
    const dashboardBase = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;
    const targetUrl = buildDashboardUrl(dashboardBase, targetScanUrl, targetSource);
    await chrome.tabs.create({ url: targetUrl });
  });
});
