(() => {
  "use strict";

  const CONFIG = {
    policyVersion: "local-pii-interceptor-v1",
    triggers: ["send-button-click", "enter-key", "form-submit"],
    maskingRules: [
      { detectedLabel: "PERSON | NAME | PER", replacement: "[PRIVATE_PERSON]" },
      { detectedLabel: "EMAIL", replacement: "[PRIVATE_EMAIL]" },
      { detectedLabel: "PHONE | MOBILE | TEL | HP | MSISDN", replacement: "[PRIVATE_PHONE]" },
      { detectedLabel: "SECRET | PASSWORD | PASS | TOKEN | API-KEY | KEY", replacement: "[SECRET]" },
      { detectedLabel: "NIK | KTP 16 DIGITS", replacement: "[PRIVATE_NIK]" },
      { detectedLabel: "OTHER PII LABELS", replacement: "[PRIVATE_<LABEL>]" }
    ],
    inputSelectors: [
      "#prompt-textarea",
      "textarea[data-id='root']",
      "textarea",
      "[contenteditable='true'][id='prompt-textarea']",
      "[contenteditable='true'].ProseMirror",
      "[contenteditable='true']"
    ],
    sendButtonSelectors: [
      "button[data-testid='send-button']",
      "button[data-testid='composer-submit-button']",
      "button[aria-label='Send prompt']",
      "button[aria-label='Send message']",
      "button[aria-label='Kirim pesan']",
      "button[type='submit']"
    ]
  };

  let isProcessing = false;
  let bypassUntil = 0;

  function log(message, data) {
    if (data === undefined) {
      console.info(`[SAPEI] ${message}`);
      return;
    }
    console.info(`[SAPEI] ${message}`, data);
  }

  function showActiveBadge() {
    if (document.getElementById("privacy-filter-active-badge")) return;

    const badge = document.createElement("div");
    badge.id = "privacy-filter-active-badge";
    badge.textContent = "SAPEI Active";
    badge.style.cssText = [
      "position:fixed",
      "right:16px",
      "bottom:16px",
      "z-index:2147483647",
      "padding:8px 10px",
      "border-radius:6px",
      "background:#111827",
      "color:#ffffff",
      "font:12px/1.2 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      "box-shadow:0 8px 24px rgba(0,0,0,.22)",
      "opacity:.88",
      "pointer-events:none"
    ].join(";");

    document.documentElement.appendChild(badge);
    window.setTimeout(() => badge.remove(), 3500);
  }

  function logPolicy() {
    log("Policy loaded", {
      policyVersion: CONFIG.policyVersion,
      triggers: CONFIG.triggers,
      inputSelectors: CONFIG.inputSelectors,
      sendButtonSelectors: CONFIG.sendButtonSelectors,
      maskingRules: CONFIG.maskingRules,
      privacyNote: "Raw prompt text is not logged."
    });
    console.table(CONFIG.maskingRules);
  }

  function findComposerInput() {
    const activeElement = document.activeElement;
    if (isSupportedInput(activeElement)) return activeElement;

    for (const selector of CONFIG.inputSelectors) {
      const candidates = [...document.querySelectorAll(selector)];
      const visible = candidates.find(isVisible);
      if (visible) return visible;
    }

    return null;
  }

  function findSendButton() {
    for (const selector of CONFIG.sendButtonSelectors) {
      const candidates = [...document.querySelectorAll(selector)];
      const visible = candidates.find((button) => isVisible(button) && !button.disabled);
      if (visible) return visible;
    }

    return null;
  }

  function isSupportedInput(element) {
    if (!element) return false;
    const tagName = element.tagName?.toLowerCase();
    return tagName === "textarea" || element.isContentEditable;
  }

  function isVisible(element) {
    if (!element) return false;
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  }

  function getInputText(input) {
    if (!input) return "";
    if ("value" in input) return input.value;
    return input.innerText || input.textContent || "";
  }

  function setInputText(input, text) {
    input.focus();

    if ("value" in input) {
      const nativeSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
      if (nativeSetter) {
        nativeSetter.call(input, text);
      } else {
        input.value = text;
      }
    } else {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(input);
      selection.removeAllRanges();
      selection.addRange(range);

      if (!document.execCommand("insertText", false, text)) {
        input.textContent = text;
      }
      placeCaretAtEnd(input);
    }

    input.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      cancelable: true,
      inputType: "insertText",
      data: text
    }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function placeCaretAtEnd(element) {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(false);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  async function maskText(text) {
    const response = await chrome.runtime.sendMessage({
      type: "MASK_PII",
      text
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Background worker failed to mask text.");
    }

    return response.maskedText;
  }

  function shouldHandleEnter(event) {
    if (event.key !== "Enter") return false;
    if (event.shiftKey || event.ctrlKey || event.metaKey || event.altKey) return false;
    return isSupportedInput(event.target) || Boolean(event.target?.closest?.(CONFIG.inputSelectors.join(",")));
  }

  function shouldHandleClick(event) {
    return Boolean(event.target?.closest?.(CONFIG.sendButtonSelectors.join(",")));
  }

  function interceptEvent(event) {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
  }

  async function processAndSend(event) {
    if (Date.now() < bypassUntil) {
      return;
    }

    if (isProcessing) {
      interceptEvent(event);
      return;
    }

    const input = findComposerInput();
    const sendButton = findSendButton();
    const originalText = getInputText(input).trim();

    if (!input || !sendButton || !originalText) {
      return;
    }

    interceptEvent(event);
    isProcessing = true;
    sendButton.disabled = true;

    try {
      log("Masking prompt before send.");
      const maskedText = await maskText(originalText);
      setInputText(input, maskedText);

      window.setTimeout(() => {
        bypassUntil = Date.now() + 1200;
        sendButton.disabled = false;
        sendButton.click();
      }, 80);
    } catch (error) {
      sendButton.disabled = false;
      console.error("[SAPEI] Failed to mask prompt. Original prompt was not sent.", error);
      window.alert("Privacy Filter gagal memproses teks. Prompt asli tidak dikirim.");
    } finally {
      isProcessing = false;
    }
  }

  document.addEventListener("keydown", (event) => {
    if (shouldHandleEnter(event)) {
      processAndSend(event);
    }
  }, true);

  document.addEventListener("click", (event) => {
    if (shouldHandleClick(event)) {
      processAndSend(event);
    }
  }, true);

  document.addEventListener("submit", (event) => {
    processAndSend(event);
  }, true);

  showActiveBadge();
  log("SAPEI is Active");
  logPolicy();
})();
