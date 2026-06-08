const policyVersionElement = document.getElementById("policy-version");
const clientIdElement = document.getElementById("client-id");
const policyStorageElement = document.getElementById("policy-storage");
const apiUrlElement = document.getElementById("api-url");
const timeoutElement = document.getElementById("timeout");
const settingsForm = document.getElementById("settings-form");
const apiBaseUrlInput = document.getElementById("api-base-url");
const labelMappingsElement = document.getElementById("label-mappings");
const regexRulesElement = document.getElementById("regex-rules");
const labelForm = document.getElementById("label-form");
const regexForm = document.getElementById("regex-form");

function formatSource(source) {
  return source === "user" ? "User custom" : "SAPEI default";
}

function createRuleRow({ title, subtitle, replacement, source, onDelete }) {
  const row = document.createElement("div");
  row.className = "rule";

  const text = document.createElement("div");
  const detected = document.createElement("div");
  detected.className = "detected";
  detected.textContent = title;
  const meta = document.createElement("div");
  meta.className = "muted";
  meta.textContent = `${formatSource(source)} - ${subtitle}`;
  text.append(detected, meta);

  const tag = document.createElement("div");
  tag.className = "replacement";
  tag.textContent = replacement;

  const removeButton = document.createElement("button");
  removeButton.className = "danger";
  removeButton.type = "button";
  removeButton.textContent = "Delete";
  removeButton.addEventListener("click", onDelete);

  row.append(text, tag, removeButton);
  return row;
}

function renderPolicy(policy) {
  policyVersionElement.textContent = policy.policyVersion || "-";
  clientIdElement.textContent = policy.clientId || "-";
  policyStorageElement.textContent = policy.serverPolicy?.storage || "-";
  apiUrlElement.textContent = policy.apiUrl || "-";
  timeoutElement.textContent = policy.requestTimeoutMs ? `${policy.requestTimeoutMs} ms` : "-";

  labelMappingsElement.replaceChildren();
  for (const mapping of policy.labelMappings || []) {
    labelMappingsElement.appendChild(createRuleRow({
      title: mapping.name,
      subtitle: (mapping.labels || []).join(", "),
      replacement: mapping.replacement,
      source: mapping.source,
      onDelete: () => deleteLabelMapping(mapping.id)
    }));
  }

  regexRulesElement.replaceChildren();
  for (const rule of policy.regexRules || []) {
    regexRulesElement.appendChild(createRuleRow({
      title: rule.name,
      subtitle: rule.pattern,
      replacement: rule.replacement,
      source: rule.source,
      onDelete: () => deleteRegexRule(rule.id)
    }));
  }
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

async function loadSettings() {
  const response = await sendMessage({ type: "GET_SETTINGS" });
  if (!response?.ok) {
    throw new Error(response?.error || "Failed to load SAPEI settings.");
  }

  apiBaseUrlInput.value = response.settings.apiBaseUrl;
}

async function deleteRegexRule(ruleId) {
  const response = await sendMessage({ type: "DELETE_REGEX_RULE", ruleId });
  if (!response?.ok) throw new Error(response?.error || "Failed to delete regex rule.");
  await loadPolicy();
}

async function deleteLabelMapping(mappingId) {
  const response = await sendMessage({ type: "DELETE_LABEL_MAPPING", mappingId });
  if (!response?.ok) throw new Error(response?.error || "Failed to delete label mapping.");
  await loadPolicy();
}

labelForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const mapping = {
    name: document.getElementById("label-name").value.trim(),
    labels: document.getElementById("label-aliases").value.split(",").map((item) => item.trim()).filter(Boolean),
    replacement: document.getElementById("label-replacement").value.trim(),
    enabled: true
  };

  const response = await sendMessage({ type: "CREATE_LABEL_MAPPING", mapping });
  if (!response?.ok) {
    window.alert(response?.error || "Failed to add label mapping.");
    return;
  }

  labelForm.reset();
  await loadPolicy();
});

regexForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const rule = {
    name: document.getElementById("regex-name").value.trim(),
    pattern: document.getElementById("regex-pattern").value.trim(),
    replacement: document.getElementById("regex-replacement").value.trim(),
    capture_group: 0,
    ignore_case: document.getElementById("regex-ignore-case").checked,
    enabled: true
  };

  const response = await sendMessage({ type: "CREATE_REGEX_RULE", rule });
  if (!response?.ok) {
    window.alert(response?.error || "Failed to add regex rule.");
    return;
  }

  regexForm.reset();
  await loadPolicy();
});

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const response = await sendMessage({
    type: "UPDATE_SETTINGS",
    settings: {
      apiBaseUrl: apiBaseUrlInput.value.trim()
    }
  });

  if (!response?.ok) {
    window.alert(response?.error || "Failed to save endpoint.");
    return;
  }

  await loadPolicy();
});

loadSettings().catch((error) => {
  console.error("[SAPEI] Settings load failed.", error);
});

loadPolicy().catch((error) => {
  console.error("[SAPEI] Policy load failed.", error);
});
