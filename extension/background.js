import { isScannable, unwrapRedirect, sourceFor, buildDashboardUrl } from "./lib/urls.js";

const DEFAULT_DASHBOARD_URL = "https://phishlens-1-27oz.onrender.com";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "check-phishlens",
    title: "Check with PhishLens",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "check-phishlens") return;

  const rawLink = info.linkUrl || "";
  const targetUrl = unwrapRedirect(rawLink);

  if (!isScannable(targetUrl)) {
    // Show badge text warning instead of opening anything
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
    chrome.action.setTitle({ title: "PhishLens: Link is not a scannable HTTP/HTTPS URL" });

    setTimeout(() => {
      chrome.action.setBadgeText({ text: "" });
      chrome.action.setTitle({ title: "PhishLens XAI" });
    }, 3500);
    return;
  }

  const pageUrl = info.pageUrl || (tab && tab.url) || "";
  const source = sourceFor(pageUrl);

  const storage = await chrome.storage.sync.get({ dashboardUrl: DEFAULT_DASHBOARD_URL });
  const dashboardUrl = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;

  const finalUrl = buildDashboardUrl(dashboardUrl, targetUrl, source);
  await chrome.tabs.create({ url: finalUrl });
});
