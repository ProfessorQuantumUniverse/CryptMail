/**
 * CryptMail – Gmail Content Script
 *
 * Observes the Gmail DOM via MutationObserver for:
 *   1. Compose windows  → adds "Encrypt" button, subject encryption, file attach.
 *   2. Message bodies    → shows a "Decrypt" button for CryptMail envelopes.
 *   3. First-run welcome screen for new users.
 *   4. Status indicator in the Gmail header.
 *
 * All key management is done via message-passing to the background service worker.
 * Crypto operations (symmetric) run in the content script with progress feedback.
 * ECDH operations are delegated to the background worker.
 */

(() => {
  "use strict";

  /* ---- Constants ---- */
  const DECRYPT_ATTR = "data-cryptmail-decrypted";
  const DECRYPT_BTN_ATTR = "data-cryptmail-btn";
  const BUTTON_CLASS = "cryptmail-send-btn";
  const SUBJECT_INDICATOR = "\u{1F512}"; // 🔒
  const SCAN_DEBOUNCE_MS = 500;

  /* ---- Settings ---- */
  let _settingsCache = null;
  let _settingsTimer = null;

  async function getSettings() {
    if (!_settingsCache) {
      try {
        _settingsCache = await KeyStore.getSettings();
      } catch {
        _settingsCache = {
          stealthMode: false,
          stealthSubjects: ["Hi", "Re: Follow-up", "Quick update"],
          autoDecrypt: false,
          showStatusIndicator: true,
          encryptSubjectByDefault: false,
          autoKeyExchange: true,
        };
      }
    }
    return _settingsCache;
  }

  // Refresh settings every 30 s
  _settingsTimer = setInterval(async () => {
    try {
      _settingsCache = await KeyStore.getSettings();
    } catch {
      /* ignore */
    }
  }, 30000);

  /* ---- Key Fingerprint Helper ---- */

  function generateFingerprint(publicKeyB64) {
    try {
      const raw = atob(publicKeyB64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      const hex = Array.from(bytes.slice(0, 16))
        .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
        .join("");
      return hex.match(/.{4}/g).join(" : ");
    } catch {
      return publicKeyB64.substring(0, 32) + "…";
    }
  }

  /* ---- Smart Recipient Indicators ---- */

  /**
   * Scan compose windows for recipient email addresses and show
   * lock indicators: 🟢 secured, 🟡 unverified key, ⚪ no key.
   */
  async function scanRecipientIndicators() {
    const composeWindows = document.querySelectorAll(
      '.M9, .dw .nH, .inboxsdk__compose, [role="dialog"], .AD'
    );

    for (const composeEl of composeWindows) {
      // Find all recipient chips
      const chips = composeEl.querySelectorAll('[email]');
      for (const chip of chips) {
        if (chip.getAttribute('data-cm-indicator')) continue;
        chip.setAttribute('data-cm-indicator', 'true');

        const email = chip.getAttribute('email');
        if (!email || !email.includes('@')) continue;

        const indicator = document.createElement('span');
        indicator.className = 'cryptmail-recipient-indicator';

        try {
          const unlocked = await KeyStore.isUnlocked();
          if (!unlocked) {
            indicator.textContent = '⚪';
            indicator.title = 'CryptMail: Locked — unlock to see status';
            indicator.className += ' cm-status-none';
          } else {
            const status = await KeyStore.getContactStatus(email);
            if (status.level === 'verified') {
              indicator.textContent = '🟢';
              indicator.title = 'CryptMail: Secured & verified ✓';
              indicator.className += ' cm-status-verified';
            } else if (status.level === 'secure') {
              indicator.textContent = '🟢';
              indicator.title = 'CryptMail: Secured (passphrase)';
              indicator.className += ' cm-status-secure';
            } else if (status.level === 'unverified') {
              indicator.textContent = '🟡';
              indicator.title = 'CryptMail: Key available, not verified';
              indicator.className += ' cm-status-unverified';
            } else {
              indicator.textContent = '⚪';
              indicator.title = 'CryptMail: No encryption key';
              indicator.className += ' cm-status-none';
            }
          }
        } catch {
          indicator.textContent = '⚪';
          indicator.title = 'CryptMail';
          indicator.className += ' cm-status-none';
        }

        chip.style.position = 'relative';
        chip.appendChild(indicator);
      }
    }
  }

  /* ---- Shadow DOM Host for modals ---- */

  let _shadowHost = null;
  let _shadowRoot = null;

  function getShadowRoot() {
    if (_shadowRoot) return _shadowRoot;
    _shadowHost = document.createElement("div");
    _shadowHost.id = "cryptmail-shadow-host";
    _shadowHost.style.cssText =
      "position:fixed;top:0;left:0;width:0;height:0;z-index:0;pointer-events:none;";
    document.body.appendChild(_shadowHost);
    _shadowRoot = _shadowHost.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = getModalStyles();
    _shadowRoot.appendChild(style);

    return _shadowRoot;
  }

  function getModalStyles() {
    return `
      * { box-sizing: border-box; margin: 0; padding: 0; }
      .cm-overlay {
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(0,0,0,0.5); display: flex; align-items: center;
        justify-content: center; z-index: 9999999; pointer-events: auto;
        font-family: 'Segoe UI', Roboto, Arial, sans-serif;
      }
      .cm-card {
        background: #fff; border-radius: 12px; padding: 28px 32px;
        max-width: 480px; width: 90%; box-shadow: 0 8px 32px rgba(0,0,0,0.25);
      }
      .cm-header {
        font-size: 20px; font-weight: 600; color: #202124;
        margin-bottom: 16px; text-align: center;
      }
      .cm-body { font-size: 14px; color: #3c4043; line-height: 1.6; }
      .cm-body p { margin-bottom: 10px; }
      .cm-input {
        width: 100%; padding: 10px 12px; border: 1px solid #dadce0;
        border-radius: 6px; font-size: 14px; margin-top: 8px;
        outline: none; transition: border-color 0.2s;
      }
      .cm-input:focus { border-color: #1a73e8; }
      .cm-error {
        color: #d93025; font-size: 12px; margin-top: 6px; min-height: 16px;
      }
      .cm-btn-row {
        display: flex; gap: 8px; margin-top: 16px;
      }
      .cm-btn {
        flex: 1; padding: 10px; border-radius: 6px; font-size: 14px;
        cursor: pointer; font-weight: 500; border: none;
        transition: background 0.15s;
      }
      .cm-btn-secondary {
        background: #fff; border: 1px solid #dadce0; color: #3c4043;
      }
      .cm-btn-secondary:hover { background: #f1f3f4; }
      .cm-btn-primary {
        background: #1a73e8; color: #fff;
      }
      .cm-btn-primary:hover { background: #1765cc; }
      .cm-steps { margin: 16px 0; }
      .cm-step {
        display: flex; align-items: flex-start; gap: 10px; margin-bottom: 12px;
      }
      .cm-step-num {
        background: #1a73e8; color: #fff; width: 24px; height: 24px;
        border-radius: 50%; display: flex; align-items: center;
        justify-content: center; font-size: 13px; font-weight: 600;
        flex-shrink: 0;
      }
      .cm-note {
        background: #fef7e0; padding: 10px 12px; border-radius: 6px;
        font-size: 13px; color: #5f6368; margin-top: 8px;
      }
    `;
  }

  /* ---- Modal helpers ---- */

  function createOverlay(html) {
    const root = getShadowRoot();
    const overlay = document.createElement("div");
    overlay.className = "cm-overlay";
    overlay.innerHTML = `<div class="cm-card">${html}</div>`;
    root.appendChild(overlay);
    return overlay;
  }

  function removeOverlay(overlay) {
    if (overlay && overlay.parentNode) overlay.remove();
  }

  /* ---- Welcome Screen ---- */

  function showWelcomeScreen() {
    if (_shadowRoot && _shadowRoot.querySelector("#cm-welcome")) return;

    const overlay = createOverlay(`
      <div class="cm-header">🔒 Welcome to CryptMail v3.0!</div>
      <div class="cm-body">
        <p><strong>CryptMail</strong> adds AES-256 end-to-end encryption to Gmail with automatic key exchange.</p>
        <div class="cm-steps">
          <div class="cm-step">
            <span class="cm-step-num">1</span>
            <span>Click the <strong>CryptMail icon</strong> in your toolbar to set up your identity.</span>
          </div>
          <div class="cm-step">
            <span class="cm-step-num">2</span>
            <span>Watch for <strong>🟢 🟡 ⚪</strong> indicators next to recipients — they show encryption status.</span>
          </div>
          <div class="cm-step">
            <span class="cm-step-num">3</span>
            <span>Click <strong>"🔒 Encrypt"</strong> to send a secure message. Keys are exchanged automatically!</span>
          </div>
        </div>
        <div class="cm-note">
          💡 <strong>New in v3.0:</strong> Biometric unlock, automatic key exchange,
          and smart encryption indicators. No more sharing passwords manually!
        </div>
      </div>
      <div class="cm-btn-row">
        <button class="cm-btn cm-btn-primary" id="cm-welcome-close">Got it — Let's go!</button>
      </div>
    `);
    overlay.id = "cm-welcome";

    const closeBtn = overlay.querySelector("#cm-welcome-close");
    closeBtn.addEventListener("click", () => {
      removeOverlay(overlay);
      try {
        chrome.storage.local.set({ cryptmail_welcomed: true });
      } catch {
        /* ignore */
      }
    });
  }

  function checkFirstRun() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get("cryptmail_welcomed", (result) => {
        if (!result.cryptmail_welcomed) showWelcomeScreen();
      });
    }
  }

  /* ---- Progress bar ---- */

  function createProgressBar(label) {
    let container = document.getElementById("cryptmail-progress");
    if (!container) {
      container = document.createElement("div");
      container.id = "cryptmail-progress";
      container.className = "cryptmail-progress-container";
      document.body.appendChild(container);
    }
    container.innerHTML = `
      <div class="cryptmail-progress-label">${label}</div>
      <div class="cryptmail-progress-track">
        <div class="cryptmail-progress-bar" id="cryptmail-progress-bar"></div>
      </div>
      <div class="cryptmail-progress-percent" id="cryptmail-progress-percent">0%</div>
    `;
    container.style.display = "flex";
    return (percent) => {
      const bar = document.getElementById("cryptmail-progress-bar");
      const pct = document.getElementById("cryptmail-progress-percent");
      if (bar) bar.style.width = percent + "%";
      if (pct) pct.textContent = percent + "%";
    };
  }

  function hideProgressBar() {
    const container = document.getElementById("cryptmail-progress");
    if (container) container.style.display = "none";
  }

  /* ---- Passphrase prompt (Shadow DOM) ---- */

  function showPassphrasePrompt(email) {
    return new Promise((resolve) => {
      const safeEmail = email
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");

      const overlay = createOverlay(`
        <div class="cm-header">\u{1F511} Passphrase Required</div>
        <div class="cm-body">
          <p>No shared passphrase found for <strong>${safeEmail}</strong>.</p>
          <p>Enter the passphrase you agreed on with this contact.</p>
          <input type="password" class="cm-input" id="cm-prompt-pw"
            placeholder="Shared passphrase" autocomplete="off">
        </div>
        <div class="cm-btn-row">
          <button class="cm-btn cm-btn-secondary" id="cm-prompt-cancel">Cancel</button>
          <button class="cm-btn cm-btn-primary" id="cm-prompt-ok">Save &amp; Encrypt</button>
        </div>
      `);

      const pwInput = overlay.querySelector("#cm-prompt-pw");
      pwInput.focus();

      overlay.querySelector("#cm-prompt-ok").addEventListener("click", () => {
        const val = pwInput.value;
        removeOverlay(overlay);
        resolve(val || null);
      });

      overlay.querySelector("#cm-prompt-cancel").addEventListener("click", () => {
        removeOverlay(overlay);
        resolve(null);
      });

      pwInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          const val = pwInput.value;
          removeOverlay(overlay);
          resolve(val || null);
        }
      });
    });
  }

  /* ---- Master password prompt (Shadow DOM) ---- */

  async function ensureUnlocked() {
    try {
      const unlocked = await KeyStore.isUnlocked();
      if (unlocked) return true;
    } catch {
      /* assume locked */
    }

    return new Promise((resolve) => {
      const overlay = createOverlay(`
        <div class="cm-header">\u{1F511} CryptMail Locked</div>
        <div class="cm-body">
          <p>Enter your <strong>master password</strong> to unlock your stored keys.</p>
          <input type="password" class="cm-input" id="cm-master-pw"
            placeholder="Master password" autocomplete="off">
          <div class="cm-error" id="cm-master-err"></div>
        </div>
        <div class="cm-btn-row">
          <button class="cm-btn cm-btn-secondary" id="cm-master-cancel">Cancel</button>
          <button class="cm-btn cm-btn-primary" id="cm-master-ok">Unlock</button>
        </div>
      `);

      const pwInput = overlay.querySelector("#cm-master-pw");
      const errEl = overlay.querySelector("#cm-master-err");
      pwInput.focus();

      async function tryUnlock() {
        const pw = pwInput.value;
        if (!pw) {
          errEl.textContent = "Please enter a password.";
          return;
        }
        try {
          const ok = await KeyStore.unlock(pw);
          if (ok) {
            removeOverlay(overlay);
            updateStatusIndicator();
            resolve(true);
          } else {
            errEl.textContent = "Wrong master password.";
          }
        } catch (err) {
          errEl.textContent = "Error: " + err.message;
        }
      }

      overlay.querySelector("#cm-master-ok").addEventListener("click", tryUnlock);
      pwInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") tryUnlock();
      });
      overlay.querySelector("#cm-master-cancel").addEventListener("click", () => {
        removeOverlay(overlay);
        resolve(false);
      });
    });
  }

  /* ---- Notifications ---- */

  function showNotification(msg, isError) {
    let container = document.getElementById("cryptmail-notification");
    if (!container) {
      container = document.createElement("div");
      container.id = "cryptmail-notification";
      document.body.appendChild(container);
    }
    container.textContent = msg;
    container.className = isError ? "cryptmail-notify error" : "cryptmail-notify";
    container.style.display = "block";
    setTimeout(() => {
      container.style.display = "none";
    }, 5000);
  }

  /* ---- Status Indicator ---- */

  let _statusIndicator = null;

  async function initStatusIndicator() {
    try {
      const settings = await getSettings();
      if (!settings.showStatusIndicator) return;
    } catch {
      /* show by default */
    }

    if (_statusIndicator) return;
    _statusIndicator = document.createElement("div");
    _statusIndicator.id = "cryptmail-status";
    _statusIndicator.className = "cryptmail-status-indicator";
    _statusIndicator.title = "CryptMail";
    document.body.appendChild(_statusIndicator);
    updateStatusIndicator();
  }

  async function updateStatusIndicator() {
    if (!_statusIndicator) return;
    try {
      const unlocked = await KeyStore.isUnlocked();
      _statusIndicator.textContent = unlocked ? "\u{1F513}" : "\u{1F512}";
      _statusIndicator.className =
        "cryptmail-status-indicator " + (unlocked ? "unlocked" : "locked");
      _statusIndicator.title = unlocked ? "CryptMail: Unlocked" : "CryptMail: Locked";
    } catch {
      _statusIndicator.textContent = "\u{1F512}";
      _statusIndicator.className = "cryptmail-status-indicator locked";
    }
  }

  /* ---- Compose helpers ---- */

  /**
   * Robust recipient extraction with multiple fallback strategies.
   */
  function getRecipient(composeEl) {
    const strategies = [
      () => composeEl.querySelector("[email]")?.getAttribute("email"),
      () => composeEl.querySelector('input[name="to"]')?.value?.trim(),
      () =>
        composeEl
          .querySelector("[data-hovercard-id]")
          ?.getAttribute("data-hovercard-id"),
      () => {
        // aria-label based search (works for multiple Gmail locales)
        const toField =
          composeEl.querySelector('[aria-label*="To"]') ||
          composeEl.querySelector('[aria-label*="An"]') ||
          composeEl.querySelector('[aria-label*="À"]');
        if (toField) {
          const chip = toField.querySelector("[email]");
          if (chip) return chip.getAttribute("email");
          const input = toField.querySelector("input");
          if (input && input.value) return input.value.trim();
        }
        return null;
      },
      () => {
        // Fallback: look for any span/div with an email-like text
        const spans = composeEl.querySelectorAll("span[email], div[email]");
        for (const s of spans) {
          const e = s.getAttribute("email");
          if (e && e.includes("@")) return e;
        }
        return null;
      },
    ];

    for (const strategy of strategies) {
      try {
        const result = strategy();
        if (result && result.includes("@")) return result;
      } catch {
        /* try next */
      }
    }
    return null;
  }

  /**
   * Robust compose body finder with multiple selectors.
   */
  function getComposeBody(composeEl) {
    const selectors = [
      '[role="textbox"][aria-label*="Message"]',
      '[role="textbox"][aria-label*="Nachricht"]',
      '[role="textbox"][aria-label*="Corps"]',
      '[role="textbox"][aria-label]',
      '[g_editable="true"]',
      'div[contenteditable="true"]',
    ];
    for (const sel of selectors) {
      const el = composeEl.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  /**
   * Robust subject input finder.
   */
  function getSubjectInput(composeEl) {
    return (
      composeEl.querySelector('input[name="subjectbox"]') ||
      composeEl.querySelector('input[aria-label="Subject"]') ||
      composeEl.querySelector('input[aria-label="Betreff"]') ||
      composeEl.querySelector('input[aria-label="Objet"]')
    );
  }

  /* ---- Button injection ---- */

  function injectButton(composeEl) {
    if (composeEl.querySelector("." + BUTTON_CLASS)) return;

    const toolbar =
      composeEl.querySelector('[role="toolbar"]') ||
      composeEl.querySelector(".btC") ||
      composeEl.querySelector(".J-J5-Ji") ||
      composeEl.querySelector("td.gU") ||
      composeEl.querySelector("tr.btC td");

    if (!toolbar) {
      // Don't crash – just skip this compose window
      return;
    }

    try {
      // Subject encryption checkbox
      const checkboxWrap = document.createElement("label");
      checkboxWrap.className = "cryptmail-subject-label";
      checkboxWrap.title = "Also encrypt the email subject line";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "cryptmail-subject-checkbox";

      getSettings()
        .then((s) => {
          checkbox.checked = s.encryptSubjectByDefault;
        })
        .catch(() => {});

      checkboxWrap.appendChild(checkbox);
      checkboxWrap.appendChild(document.createTextNode(" Encrypt subject"));
      toolbar.appendChild(checkboxWrap);

      // Encrypt button
      const btn = document.createElement("button");
      btn.className = BUTTON_CLASS;
      btn.textContent = "\u{1F512} Encrypt";
      btn.title = "Encrypt the message with CryptMail";
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleEncrypt(composeEl, checkbox.checked);
      });
      toolbar.appendChild(btn);

      // Attach encrypted file button
      const attachBtn = document.createElement("button");
      attachBtn.className = "cryptmail-attach-btn";
      attachBtn.textContent = "\u{1F4CE}\u{1F512}";
      attachBtn.title = "Encrypt & download file (attach manually)";
      attachBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleAttachEncrypted(composeEl);
      });
      toolbar.appendChild(attachBtn);
    } catch (err) {
      console.error("CryptMail: Failed to inject buttons:", err);
    }
  }

  /* ---- Encrypt handler ---- */

  async function handleEncrypt(composeEl, encryptSubject) {
    try {
      const body = getComposeBody(composeEl);
      if (!body) {
        showNotification("Could not find compose body.", true);
        return;
      }

      const plaintext = body.innerText.trim();
      if (!plaintext) {
        showNotification("Message body is empty.", true);
        return;
      }

      const recipient = getRecipient(composeEl);
      if (!recipient) {
        showNotification("Could not determine recipient email. Please add a recipient.", true);
        return;
      }

      if (!(await ensureUnlocked())) return;

      let passphrase = await KeyStore.getKey(recipient);
      if (!passphrase) {
        passphrase = await showPassphrasePrompt(recipient);
        if (!passphrase) return;
        await KeyStore.setKey(recipient, passphrase);
      }

      const settings = await getSettings();
      const updateProgress = createProgressBar("\u{1F512} Encrypting message\u2026");

      // Build encryption options
      const encryptOptions = { onProgress: updateProgress };

      // Include our public key for automatic key exchange
      if (settings.autoKeyExchange !== false) {
        try {
          const keyPair = await KeyStore.getKeyPair();
          if (keyPair && keyPair.publicKey) {
            encryptOptions.senderPublicKey = keyPair.publicKey;
          }
        } catch {
          /* skip public key inclusion */
        }
      }

      // Stealth mode: embed subject in envelope body
      if (encryptSubject && settings.stealthMode) {
        const subjectInput = getSubjectInput(composeEl);
        if (subjectInput && subjectInput.value.trim()) {
          const encSubj = await CryptMail.encryptSubject(
            subjectInput.value.trim(),
            passphrase
          );
          encryptOptions.encryptedSubject = encSubj;
        }
      }

      const encrypted = await CryptMail.encrypt(
        plaintext,
        passphrase,
        encryptOptions
      );

      // Set compose body
      if (settings.stealthMode) {
        body.innerText = encrypted;
      } else {
        body.innerText =
          "This message is secured with CryptMail (end-to-end encrypted).\n" +
          "To read it, please install the CryptMail extension.\n\n" +
          encrypted +
          "\n\nThis is an automated encryption envelope. " +
          "If you cannot decrypt it, ask the sender for the CryptMail extension.";
      }

      // Handle subject encryption
      if (encryptSubject) {
        const subjectInput = getSubjectInput(composeEl);
        if (subjectInput && subjectInput.value.trim()) {
          if (settings.stealthMode) {
            // Random generic subject
            const subjects = settings.stealthSubjects || ["Private Message"];
            subjectInput.value =
              subjects[Math.floor(Math.random() * subjects.length)];
          } else {
            const subjectPlain = subjectInput.value.trim();
            const encryptedSubject = await CryptMail.encryptSubject(
              subjectPlain,
              passphrase
            );
            subjectInput.value = SUBJECT_INDICATOR + " " + encryptedSubject;
          }
          subjectInput.dispatchEvent(new Event("input", { bubbles: true }));
        }
      }

      hideProgressBar();
      showNotification(
        "\u2705 Encrypted! Click Gmail's Send button to deliver."
      );

      // Update recipient indicators after encryption
      setTimeout(scanRecipientIndicators, 500);
    } catch (err) {
      hideProgressBar();
      console.error("CryptMail encryption error:", err);
      showNotification("Encryption failed: " + err.message, true);
    }
  }

  /* ---- Attach encrypted file ---- */

  async function handleAttachEncrypted(composeEl) {
    try {
      const recipient = getRecipient(composeEl);
      if (!recipient) {
        showNotification(
          "Could not determine recipient. Add a recipient first.",
          true
        );
        return;
      }

      if (!(await ensureUnlocked())) return;

      let passphrase = await KeyStore.getKey(recipient);
      if (!passphrase) {
        passphrase = await showPassphrasePrompt(recipient);
        if (!passphrase) return;
        await KeyStore.setKey(recipient, passphrase);
      }

      const input = document.createElement("input");
      input.type = "file";
      input.accept = "*/*";
      input.style.display = "none";
      document.body.appendChild(input);

      input.addEventListener("change", async () => {
        const file = input.files[0];
        input.remove();
        if (!file) return;

        try {
          const updateProgress = createProgressBar(
            "\u{1F512} Encrypting file\u2026"
          );
          const buffer = await file.arrayBuffer();
          const encrypted = await CryptMail.encryptFile(
            buffer,
            file.name,
            file.type,
            passphrase,
            updateProgress
          );

          // Trigger download of .cmail file
          const blob = new Blob([encrypted], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = file.name + ".cmail";
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);

          hideProgressBar();
          showNotification(
            "\u{1F4CE} Encrypted file downloaded. Attach it to your email manually."
          );
        } catch (err) {
          hideProgressBar();
          showNotification("File encryption failed: " + err.message, true);
        }
      });

      input.click();
    } catch (err) {
      showNotification("Error: " + err.message, true);
    }
  }

  /* ---- Decrypt buttons for received messages ---- */

  async function scanAndShowDecryptButton() {
    const messageBodies = document.querySelectorAll(
      ".a3s.aiL, .a3s.aXjCH, div[data-message-id] .a3s, .a3s"
    );

    for (const el of messageBodies) {
      if (el.getAttribute(DECRYPT_ATTR)) continue;
      if (el.getAttribute(DECRYPT_BTN_ATTR)) continue;

      const text = el.innerText;
      if (!CryptMail.isEncrypted(text)) continue;

      // Find sender email
      const senderEl =
        el.closest("[data-message-id]")?.querySelector("[email]") ||
        el.closest(".gs")?.querySelector("[email]") ||
        el.closest(".kv")?.querySelector("[email]") ||
        el.closest(".h7")?.querySelector("[email]");
      const senderEmail = senderEl ? senderEl.getAttribute("email") : null;
      if (!senderEmail) continue;

      el.setAttribute(DECRYPT_BTN_ATTR, "true");

      // Extract the armored block
      const start = text.indexOf(CryptMail.ENVELOPE_PREFIX);
      const suffixIdx = text.indexOf(CryptMail.ENVELOPE_SUFFIX);
      if (start === -1 || suffixIdx === -1) continue;
      const end = suffixIdx + CryptMail.ENVELOPE_SUFFIX.length;
      const armored = text.substring(start, end);

      // Auto-store sender's public key if present (auto key exchange)
      try {
        const info = CryptMail.getEnvelopeInfo(armored);
        if (info && info.senderPublicKey) {
          // Check if this is a new or changed key before storing
          const existingKey = await KeyStore.getContactPublicKey(senderEmail);
          const isNewKey = !existingKey || existingKey !== info.senderPublicKey;
          await KeyStore.storeContactPublicKey(senderEmail, info.senderPublicKey);
          if (isNewKey) {
            showNotification(
              "\u{1F511} Auto-discovered encryption key for " + senderEmail
            );
          }
        }
      } catch {
        /* ignore */
      }

      // Detect ECDH mode
      const envelopeInfo = CryptMail.getEnvelopeInfo(armored);
      const isECDH = envelopeInfo && envelopeInfo.mode === "ecdh";

      // Insert decrypt button
      const decryptBtn = document.createElement("button");
      decryptBtn.className = "cryptmail-decrypt-btn";
      decryptBtn.textContent = isECDH
        ? "\u{1F513} Decrypt (ECDH)"
        : "\u{1F513} Decrypt Message";

      decryptBtn.addEventListener("click", async () => {
        if (!(await ensureUnlocked())) return;

        decryptBtn.disabled = true;
        decryptBtn.textContent = "Decrypting\u2026";

        try {
          let decrypted;

          if (isECDH) {
            // Delegate to background
            decrypted = await KeyStore.hybridDecrypt(armored);
          } else {
            // Symmetric decryption
            let passphrase = await KeyStore.getKey(senderEmail);
            if (!passphrase) {
              passphrase = await showPassphrasePrompt(senderEmail);
              if (!passphrase) {
                decryptBtn.disabled = false;
                decryptBtn.textContent = "\u{1F513} Decrypt Message";
                return;
              }
              await KeyStore.setKey(senderEmail, passphrase);
            }

            const updateProgress = createProgressBar(
              "\u{1F513} Decrypting message\u2026"
            );
            decrypted = await CryptMail.decrypt(
              armored,
              passphrase,
              updateProgress
            );
            hideProgressBar();

            // Try subject decryption
            await decryptSubjectInView(el, armored, passphrase);
          }

          el.setAttribute(DECRYPT_ATTR, "true");
          el.innerHTML = "";

          const secureBanner = document.createElement("div");
          secureBanner.className = "cryptmail-secure-banner";
          secureBanner.innerHTML =
            '<span class="cryptmail-secure-icon">🔒</span>' +
            '<span>End-to-end encrypted' +
            (isECDH ? ' (Public Key)' : ' (Passphrase)') + '</span>';

          const clearDiv = document.createElement("div");
          clearDiv.className = "cryptmail-decrypted";
          clearDiv.textContent = decrypted;

          const toggleBtn = document.createElement("button");
          toggleBtn.className = "cryptmail-toggle-btn";
          toggleBtn.textContent = "Show encrypted";
          let showingRaw = false;
          toggleBtn.addEventListener("click", () => {
            showingRaw = !showingRaw;
            clearDiv.textContent = showingRaw ? armored : decrypted;
            toggleBtn.textContent = showingRaw
              ? "Show decrypted"
              : "Show encrypted";
          });

          el.appendChild(secureBanner);
          el.appendChild(toggleBtn);
          el.appendChild(clearDiv);
        } catch (err) {
          hideProgressBar();
          decryptBtn.disabled = false;
          decryptBtn.textContent = isECDH
            ? "\u{1F513} Decrypt (ECDH)"
            : "\u{1F513} Decrypt Message";
          console.warn("CryptMail decryption failed:", err);
          showNotification("Decryption failed: " + err.message, true);
        }
      });

      el.insertBefore(decryptBtn, el.firstChild);

      // Auto-decrypt if enabled
      try {
        const settings = await getSettings();
        if (settings.autoDecrypt) {
          decryptBtn.click();
        }
      } catch {
        /* ignore */
      }
    }
  }

  /* ---- Subject decryption ---- */

  async function decryptSubjectInView(messageEl, armored, passphrase) {
    try {
      // 1. Check for embedded subject in the envelope (stealth mode)
      const info = CryptMail.getEnvelopeInfo(armored);
      if (info && info.encryptedSubject) {
        const plainSubject = await CryptMail.decryptSubject(
          info.encryptedSubject,
          passphrase
        );
        setDecryptedSubject(messageEl, plainSubject);
        return;
      }

      // 2. Look for [CM] token in subject elements
      const subjectSelectors = [
        "h2.hP",
        ".ha h2",
        'h2[data-thread-perm-id]',
        ".nH h2",
      ];

      const container =
        messageEl.closest(".gs") ||
        messageEl.closest(".kv") ||
        messageEl.closest("[data-message-id]") ||
        document;

      for (const sel of subjectSelectors) {
        const subjectEl =
          container.querySelector(sel) || document.querySelector(sel);
        if (!subjectEl) continue;

        const subjectText = subjectEl.textContent.trim();
        const cmIdx = subjectText.indexOf(CryptMail.SUBJECT_PREFIX);
        if (cmIdx === -1) continue;

        const token = subjectText.substring(cmIdx);
        try {
          const plainSubject = await CryptMail.decryptSubject(
            token,
            passphrase
          );
          subjectEl.textContent = "\u{1F513} " + plainSubject;
          return;
        } catch {
          /* try next */
        }
      }

      // 3. Fallback: scan all h2 for 🔒 prefix with [CM] token
      const allH2 = document.querySelectorAll("h2");
      for (const h2 of allH2) {
        const text = h2.textContent.trim();
        if (
          text.includes(SUBJECT_INDICATOR) &&
          text.includes(CryptMail.SUBJECT_PREFIX)
        ) {
          const cmIdx = text.indexOf(CryptMail.SUBJECT_PREFIX);
          const token = text.substring(cmIdx);
          try {
            const plainSubject = await CryptMail.decryptSubject(
              token,
              passphrase
            );
            h2.textContent = "\u{1F513} " + plainSubject;
            return;
          } catch {
            /* continue */
          }
        }
      }

      // 4. Also try the document title (Gmail sets it to the subject)
      if (document.title.includes(CryptMail.SUBJECT_PREFIX)) {
        const cmIdx = document.title.indexOf(CryptMail.SUBJECT_PREFIX);
        const token = document.title.substring(cmIdx);
        try {
          const plainSubject = await CryptMail.decryptSubject(
            token,
            passphrase
          );
          document.title = "\u{1F513} " + plainSubject;
        } catch {
          /* ignore */
        }
      }
    } catch {
      // Subject decryption is always best-effort
    }
  }

  function setDecryptedSubject(messageEl, plainSubject) {
    const selectors = ["h2.hP", ".ha h2", 'h2[data-thread-perm-id]', ".nH h2"];
    const container =
      messageEl.closest(".gs") ||
      messageEl.closest("[data-message-id]") ||
      document;

    for (const sel of selectors) {
      const el =
        container.querySelector(sel) || document.querySelector(sel);
      if (el) {
        el.textContent = "\u{1F513} " + plainSubject;
        return;
      }
    }
  }

  /* ---- Compose scanning ---- */

  function scanCompose() {
    try {
      const composeWindows = document.querySelectorAll(
        '.M9, .dw .nH, .inboxsdk__compose, [role="dialog"], .AD'
      );
      composeWindows.forEach((c) => {
        try {
          injectButton(c);
        } catch (e) {
          console.debug("CryptMail: Button injection skipped:", e.message);
        }
      });

      // Also look for editable areas that might be compose windows
      const editables = document.querySelectorAll(
        'div[contenteditable="true"][aria-label]'
      );
      editables.forEach((el) => {
        const compose =
          el.closest(".M9") ||
          el.closest(".dw") ||
          el.closest('[role="dialog"]') ||
          el.closest("form") ||
          el.closest(".AD");
        if (compose) {
          try {
            injectButton(compose);
          } catch (e) {
            console.debug("CryptMail:", e.message);
          }
        }
      });
    } catch (err) {
      console.error("CryptMail scanCompose error:", err);
    }
  }

  /* ---- MutationObserver (replaces setInterval) ---- */

  let _scanTimeout = null;

  const observer = new MutationObserver(() => {
    if (_scanTimeout) clearTimeout(_scanTimeout);
    _scanTimeout = setTimeout(() => {
      _scanTimeout = null;
      scanCompose();
      scanAndShowDecryptButton();
      scanRecipientIndicators();
    }, SCAN_DEBOUNCE_MS);
  });

  // Start observing
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  // Initial scan
  scanCompose();
  scanAndShowDecryptButton();
  scanRecipientIndicators();

  // First-run & status
  checkFirstRun();
  initStatusIndicator();

  // Periodically update status indicator
  setInterval(updateStatusIndicator, 10000);
})();
