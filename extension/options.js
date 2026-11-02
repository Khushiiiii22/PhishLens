const DEFAULT_API_URL = "http://127.0.0.1:8000";
const DEFAULT_DASHBOARD_URL = "http://localhost:5173";

const RENDER_CLOUD_URL = "https://phishlens-1-27oz.onrender.com";

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
  const useLocalBtn = document.getElementById("btn-use-local");
  const useRenderBtn = document.getElementById("btn-use-render");
  const form = document.getElementById("options-form");

  // Load existing settings
  const storage = await chrome.storage.sync.get({
    apiUrl: DEFAULT_API_URL,
    dashboardUrl: DEFAULT_DASHBOARD_URL,
  });

  apiInput.value = storage.apiUrl || DEFAULT_API_URL;
  dashboardInput.value = storage.dashboardUrl || DEFAULT_DASHBOARD_URL;

  useLocalBtn?.addEventListener("click", () => {
    apiInput.value = "http://127.0.0.1:8000";
    dashboardInput.value = "http://localhost:5173";
    showStatus("Set to local development URLs. Click 'Save Settings' to apply.");
  });

  useRenderBtn?.addEventListener("click", () => {
    apiInput.value = RENDER_CLOUD_URL;
    dashboardInput.value = RENDER_CLOUD_URL;
    showStatus("Set to Render cloud URLs. Click 'Save Settings' to apply.");
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawApi = apiInput.value.trim();
    const rawDashboard = dashboardInput.value.trim();

    if (!isValidHttpUrl(rawApi)) {
      showStatus("API URL must be a valid http:// or https:// address.", true);
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
