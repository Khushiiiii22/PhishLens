import { isScannable } from "./lib/urls.js";

const DEFAULT_DASHBOARD_URL = "https://phishlens-1-27oz.onrender.com";
const LOCALHOST_DASHBOARD_URL = "http://localhost:5173";

function showStatus(message, isError = false) {
  const statusEl = document.getElementById("status");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.className = `status-msg ${isError ? "error" : "success"}`;
  if (!isError) {
    setTimeout(() => {
      statusEl.textContent = "";
    }, 3000);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const inputEl = document.getElementById("dashboard-url");
  const useLocalhostBtn = document.getElementById("btn-use-localhost");
  const useDefaultBtn = document.getElementById("btn-use-default");
  const form = document.getElementById("options-form");

  // Load existing setting
  const storage = await chrome.storage.sync.get({ dashboardUrl: DEFAULT_DASHBOARD_URL });
  inputEl.value = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;

  useLocalhostBtn?.addEventListener("click", () => {
    inputEl.value = LOCALHOST_DASHBOARD_URL;
    showStatus("Set to localhost:5173. Click 'Save Settings' to apply.");
  });

  useDefaultBtn?.addEventListener("click", () => {
    inputEl.value = DEFAULT_DASHBOARD_URL;
    showStatus("Reset to default. Click 'Save Settings' to apply.");
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const value = inputEl.value.trim();
    if (!value) {
      showStatus("Please enter a Dashboard URL.", true);
      return;
    }

    // Validate that it is http/https
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        showStatus("Invalid URL: must start with http:// or https://", true);
        return;
      }
    } catch {
      showStatus("Invalid URL format. Please check the URL.", true);
      return;
    }

    // Clean trailing slashes
    const normalized = value.replace(/\/+$/, "");

    await chrome.storage.sync.set({ dashboardUrl: normalized });
    inputEl.value = normalized;
    showStatus("Settings saved successfully!", false);
  });
});
