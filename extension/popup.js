const statusElement = document.getElementById("api-status");
const refreshButton = document.getElementById("refresh-status");
const settingsButton = document.getElementById("open-settings");
const policyVersionElement = document.getElementById("policy-version");
const apiUrlElement = document.getElementById("api-url");
const clientIdElement = document.getElementById("client-id");
const mappingCountElement = document.getElementById("mapping-count");
const regexCountElement = document.getElementById("regex-count");

function setStatus(label, className) {
  statusElement.textContent = label;
  statusElement.className = `status ${className}`;
}

function renderPolicy(policy) {
  policyVersionElement.textContent = policy.policyVersion || "-";
  clientIdElement.textContent = policy.clientId ? `${policy.clientId.slice(0, 8)}...` : "-";
  apiUrlElement.textContent = policy.apiUrl || "-";
  mappingCountElement.textContent = `${(policy.labelMappings || []).length} redaction mappings`;
  regexCountElement.textContent = `${(policy.regexRules || []).length} optional rules`;
}

async function sendMessage(message) {
  return chrome.runtime.sendMessage(message);
}

async function loadPolicy() {
  const response = await sendMessage({ type: "GET_POLICY" });
  if (!response?.ok) {
    throw new Error(response?.error || "Failed to load SAPEI policy.");
  }

  renderPolicy(response.policy);
}

async function checkHealth() {
  setStatus("Checking...", "status-checking");

  const response = await sendMessage({ type: "HEALTH_CHECK" });
  if (response?.ok) {
    const modelStatus = response.payload?.status || "ok";
    setStatus(modelStatus, "status-ok");
    return;
  }

  setStatus("Offline", "status-error");
}

refreshButton.addEventListener("click", () => {
  checkHealth().catch((error) => {
    console.error("[SAPEI] Health check failed.", error);
    setStatus("Offline", "status-error");
  });
});

settingsButton.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

loadPolicy().catch((error) => {
  console.error("[SAPEI] Policy load failed.", error);
});

checkHealth().catch((error) => {
  console.error("[SAPEI] Health check failed.", error);
  setStatus("Offline", "status-error");
});
