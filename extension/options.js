const DEFAULT_RENDER_URL = "https://phishlens-doyc.onrender.com";
const LOCALHOST_API_URL = "http://localhost:8000";
const LOCALHOST_DASHBOARD_URL = "http://localhost:5173";

const DEFAULT_API_URL = DEFAULT_RENDER_URL;
const DEFAULT_DASHBOARD_URL = LOCALHOST_DASHBOARD_URL;

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

function isValidHttpUrl(str) {
  if (!str || typeof str !== "string") return false;
  try {
    const parsed = new URL(str.trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const apiInput = document.getElementById("api-url");
  const dashboardInput = document.getElementById("dashboard-url");
  const useLocalhostBtn = document.getElementById("btn-use-localhost");
  const useRenderBtn = document.getElementById("btn-use-render");
  const form = document.getElementById("options-form");

  // Load existing settings with localhost defaults
  const storage = await chrome.storage.sync.get({
    apiUrl: DEFAULT_API_URL,
    dashboardUrl: DEFAULT_DASHBOARD_URL,
  });

  let currentApi = storage.apiUrl || DEFAULT_API_URL;
  let currentDashboard = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;

  // Fallback away from Render static frontend URL
  if (currentApi === DEFAULT_RENDER_URL) {
    currentApi = DEFAULT_API_URL;
  }
  if (currentDashboard === DEFAULT_RENDER_URL) {
    currentDashboard = DEFAULT_DASHBOARD_URL;
  }

  apiInput.value = currentApi;
  dashboardInput.value = currentDashboard;

  useLocalhostBtn?.addEventListener("click", async () => {
    apiInput.value = LOCALHOST_API_URL;
    dashboardInput.value = LOCALHOST_DASHBOARD_URL;
    await chrome.storage.sync.set({
      apiUrl: LOCALHOST_API_URL,
      dashboardUrl: LOCALHOST_DASHBOARD_URL,
    });
    showStatus("Set to localhost (API: http://localhost:8000) and saved!");
  });

  useRenderBtn?.addEventListener("click", () => {
    apiInput.value = DEFAULT_RENDER_URL;
    dashboardInput.value = LOCALHOST_DASHBOARD_URL;
    showStatus("Set API to Render (phishlens-doyc.onrender.com). Click 'Save Settings' to apply.");
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawApi = apiInput.value.trim();
    const rawDashboard = dashboardInput.value.trim();

    if (!isValidHttpUrl(rawApi)) {
      showStatus("API Base URL must be a valid http:// or https:// address.", true);
      return;
    }

    if (!isValidHttpUrl(rawDashboard)) {
      showStatus("Dashboard URL must be a valid http:// or https:// address.", true);
      return;
    }

    const cleanApi = rawApi.replace(/\/+$/, "");
    const cleanDashboard = rawDashboard.replace(/\/+$/, "");

    await chrome.storage.sync.set({
      apiUrl: cleanApi,
      dashboardUrl: cleanDashboard,
    });

    apiInput.value = cleanApi;
    dashboardInput.value = cleanDashboard;
    showStatus("Settings saved successfully!", false);
  });
});
