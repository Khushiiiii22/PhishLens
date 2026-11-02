import { isScannable, unwrapRedirect, sourceFor, buildDashboardUrl } from "./lib/urls.js";

const DEFAULT_DASHBOARD_URL = "https://phishlens-1-27oz.onrender.com";

const SOURCE_LABELS = {
  email: "Email",
  social_media: "Social Media",
  message: "Message"
};

document.addEventListener("DOMContentLoaded", async () => {
  const urlDisplay = document.getElementById("active-url");
  const sourceBadge = document.getElementById("source-badge");
  const unwrappedContainer = document.getElementById("unwrapped-container");
  const unwrappedUrlDisplay = document.getElementById("unwrapped-url");
  const warningBox = document.getElementById("warning-message");
  const scanBtn = document.getElementById("scan-btn");
  const optionsBtn = document.getElementById("open-options-btn");
  const optionsLink = document.getElementById("options-link");

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

  const detectedSource = sourceFor(rawUrl);
  if (detectedSource && SOURCE_LABELS[detectedSource]) {
    sourceBadge.textContent = SOURCE_LABELS[detectedSource];
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

  scanBtn.addEventListener("click", async () => {
    if (!scannable) return;

    scanBtn.disabled = true;
    scanBtn.textContent = "Opening Dashboard…";

    const storage = await chrome.storage.sync.get({ dashboardUrl: DEFAULT_DASHBOARD_URL });
    const dashboardBase = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;

    const finalTarget = buildDashboardUrl(dashboardBase, unwrappedUrl, detectedSource);
    await chrome.tabs.create({ url: finalTarget });
    window.close();
  });
});
