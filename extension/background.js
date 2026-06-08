const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const REQUEST_TIMEOUT_MS = 30000;
const IDENTITY_STORAGE_KEY = "sapei_identity";
const SETTINGS_STORAGE_KEY = "sapei_settings";
const POLICY = {
  name: "SAPEI",
  policyVersion: "sapei-local-pii-interceptor-v1",
  requestTimeoutMs: REQUEST_TIMEOUT_MS,
  transport: "chrome.runtime.sendMessage -> extension service worker -> local FastAPI",
  privacyNote: "Raw prompt text is sent to the local API but is not logged by the extension."
};

console.info("[SAPEI] Background policy loaded", POLICY);

function randomToken(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function getIdentity() {
  const stored = await chrome.storage.local.get(IDENTITY_STORAGE_KEY);
  if (stored[IDENTITY_STORAGE_KEY]?.clientId) {
    return stored[IDENTITY_STORAGE_KEY];
  }

  const identity = {
    clientId: crypto.randomUUID ? crypto.randomUUID() : `client_${randomToken(16)}`,
    createdAt: new Date().toISOString()
  };

  await chrome.storage.local.set({ [IDENTITY_STORAGE_KEY]: identity });
  return identity;
}

async function identityHeaders() {
  const identity = await getIdentity();
  return {
    "X-SAPEI-Client-Id": identity.clientId
  };
}

function normalizeApiBaseUrl(value) {
  const rawValue = String(value || DEFAULT_API_BASE_URL).trim().replace(/\/+$/, "");
  if (!/^https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?(?:\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]*)?$/.test(rawValue)) {
    throw new Error("Invalid API Base URL.");
  }
  return rawValue;
}

async function getSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_STORAGE_KEY);
  const settings = stored[SETTINGS_STORAGE_KEY] || {};
  return {
    apiBaseUrl: normalizeApiBaseUrl(settings.apiBaseUrl || DEFAULT_API_BASE_URL)
  };
}

async function updateSettings(nextSettings) {
  const settings = {
    apiBaseUrl: normalizeApiBaseUrl(nextSettings.apiBaseUrl)
  };
  await chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: settings });
  return settings;
}

async function endpoint(path) {
  const settings = await getSettings();
  return `${settings.apiBaseUrl}${path}`;
}

async function maskText(text) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(await endpoint("/mask-pii"), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(await identityHeaders()) },
      body: JSON.stringify({ text }),
      signal: controller.signal
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Local API returned ${response.status}: ${errorText}`);
    }

    const payload = await response.json();
    if (typeof payload.masked_text !== "string") {
      throw new Error("Local API response does not contain masked_text.");
    }

    return payload.masked_text;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(await identityHeaders()), ...(options.headers || {}) }
  });

  const payload = await response.json().catch(async () => ({ detail: await response.text() }));
  if (!response.ok) {
    throw new Error(payload.detail || `Local API returned ${response.status}`);
  }

  return payload;
}

async function getPolicy() {
  const identity = await getIdentity();
  const settings = await getSettings();
  const serverPolicy = await apiRequest(await endpoint("/policy"));
  return {
    ...POLICY,
    clientId: identity.clientId,
    apiBaseUrl: settings.apiBaseUrl,
    apiUrl: `${settings.apiBaseUrl}/mask-pii`,
    healthUrl: `${settings.apiBaseUrl}/health`,
    policyUrl: `${settings.apiBaseUrl}/policy`,
    serverPolicy,
    policyVersion: serverPolicy.policy_version || POLICY.policyVersion,
    labelMappings: serverPolicy.label_mappings || [],
    regexRules: serverPolicy.regex_rules || []
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "GET_POLICY") {
    getPolicy()
      .then((policy) => sendResponse({ ok: true, policy }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
    return true;
  }

  if (message?.type === "GET_SETTINGS") {
    getSettings()
      .then((settings) => sendResponse({ ok: true, settings }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
    return true;
  }

  if (message?.type === "UPDATE_SETTINGS") {
    updateSettings(message.settings || {})
      .then((settings) => sendResponse({ ok: true, settings }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
    return true;
  }

  if (message?.type === "HEALTH_CHECK") {
    identityHeaders()
      .then(async (headers) => fetch(await endpoint("/health"), { headers }))
      .then(async (response) => {
        const payload = await response.json();
        sendResponse({ ok: response.ok, status: response.status, payload });
      })
      .catch((error) => {
        sendResponse({ ok: false, error: error.message || String(error) });
      });

    return true;
  }

  if (message?.type === "CREATE_REGEX_RULE") {
    endpoint("/policy/regex-rules").then((url) => apiRequest(url, {
      method: "POST",
      body: JSON.stringify(message.rule)
    }))
      .then((rule) => sendResponse({ ok: true, rule }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

    return true;
  }

  if (message?.type === "DELETE_REGEX_RULE") {
    endpoint(`/policy/regex-rules/${encodeURIComponent(message.ruleId)}`).then((url) => apiRequest(url, {
      method: "DELETE"
    }))
      .then((payload) => sendResponse({ ok: true, payload }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

    return true;
  }

  if (message?.type === "CREATE_LABEL_MAPPING") {
    endpoint("/policy/label-mappings").then((url) => apiRequest(url, {
      method: "POST",
      body: JSON.stringify(message.mapping)
    }))
      .then((mapping) => sendResponse({ ok: true, mapping }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

    return true;
  }

  if (message?.type === "DELETE_LABEL_MAPPING") {
    endpoint(`/policy/label-mappings/${encodeURIComponent(message.mappingId)}`).then((url) => apiRequest(url, {
      method: "DELETE"
    }))
      .then((payload) => sendResponse({ ok: true, payload }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

    return true;
  }

  if (message?.type !== "MASK_PII") {
    return false;
  }

  maskText(message.text)
    .then((maskedText) => {
      sendResponse({ ok: true, maskedText });
    })
    .catch((error) => {
      console.error("[SAPEI] Background masking failed.", error);
      sendResponse({ ok: false, error: error.message || String(error) });
    });

  return true;
});
