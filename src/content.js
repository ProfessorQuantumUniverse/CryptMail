/**
 * CryptMail – Gmail Content Script
 *
 * Observes the Gmail DOM for:
 *   1. Compose windows  → adds "Encrypt" button + optional subject encryption.
 *   2. Message bodies    → shows a "Decrypt" button for CryptMail envelopes.
 *   3. First-run welcome screen for new users.
 */

(() => {
  "use strict";

  /* ---- Constants ---- */
  const DECRYPT_ATTR = "data-cryptmail-decrypted";
  const DECRYPT_BTN_ATTR = "data-cryptmail-btn";
  const BUTTON_CLASS = "cryptmail-send-btn";
  const SCAN_INTERVAL_MS = 2000;
  const SUBJECT_PREFIX = "🔒 [CryptMail]";

  /* ---- Welcome screen (first-run) ---- */

  function showWelcomeScreen() {
    if (document.getElementById("cryptmail-welcome")) return;

    const overlay = document.createElement("div");
    overlay.id = "cryptmail-welcome";
    overlay.className = "cryptmail-welcome-overlay";

    overlay.innerHTML = `
      <div class="cryptmail-welcome-card">
        <div class="cryptmail-welcome-header">🔒 Welcome to CryptMail!</div>
        <div class="cryptmail-welcome-body">
          <p><strong>CryptMail</strong> adds multi-layer AES-256 encryption to your Gmail messages.</p>
          <div class="cryptmail-welcome-steps">
            <div class="cryptmail-welcome-step">
              <span class="cryptmail-step-num">1</span>
              <span>Click the <strong>CryptMail icon</strong> in your toolbar to add a shared passphrase for a contact.</span>
            </div>
            <div class="cryptmail-welcome-step">
              <span class="cryptmail-step-num">2</span>
              <span>Compose an email and click <strong>"🔒 Encrypt"</strong> to encrypt before sending.</span>
            </div>
            <div class="cryptmail-welcome-step">
              <span class="cryptmail-step-num">3</span>
              <span>When you receive an encrypted message, click <strong>"🔓 Decrypt"</strong> to read it.</span>
            </div>
          </div>
          <p class="cryptmail-welcome-note">💡 <strong>Tip:</strong> You can also encrypt the subject line with the checkbox in the compose window. Share the passphrase with your contact securely (in person, via Signal, etc.).</p>
        </div>
        <button class="cryptmail-welcome-close" id="cryptmail-welcome-close">Got it – Let's go!</button>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("cryptmail-welcome-close").addEventListener("click", () => {
      overlay.remove();
      chrome.storage.local.set({ cryptmail_welcomed: true });
    });
  }

  function checkFirstRun() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get("cryptmail_welcomed", (result) => {
        if (!result.cryptmail_welcomed) {
          showWelcomeScreen();
        }
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

  /* ---- Compose integration ---- */

  /**
   * Extract the recipient email from Gmail's compose "To" field.
   * Gmail uses <span email="..."> or <input name="to"> depending on state.
   */
  function getRecipient(composeEl) {
    const chip = composeEl.querySelector('[email]');
    if (chip) return chip.getAttribute("email");

    const input = composeEl.querySelector('input[name="to"]');
    if (input && input.value) return input.value.trim();

    const toSpan = composeEl.querySelector('[data-hovercard-id]');
    if (toSpan) return toSpan.getAttribute("data-hovercard-id");

    return null;
  }

  /**
   * Get the editable body element inside a Gmail compose window.
   */
  function getComposeBody(composeEl) {
    return composeEl.querySelector('[role="textbox"][aria-label]') ||
           composeEl.querySelector('[g_editable="true"]') ||
           composeEl.querySelector('div[contenteditable="true"]');
  }

  /**
   * Get the subject input element inside a Gmail compose window.
   */
  function getSubjectInput(composeEl) {
    return composeEl.querySelector('input[name="subjectbox"]') ||
           composeEl.querySelector('input[aria-label="Subject"]');
  }

  /**
   * Inject the "Encrypt" button, subject-encrypt checkbox, into a compose toolbar.
   */
  function injectButton(composeEl) {
    if (composeEl.querySelector("." + BUTTON_CLASS)) return;

    const toolbar = composeEl.querySelector('[role="toolbar"]') ||
                    composeEl.querySelector(".btC");
    if (!toolbar) return;

    // Subject encryption checkbox
    const checkboxWrap = document.createElement("label");
    checkboxWrap.className = "cryptmail-subject-label";
    checkboxWrap.title = "Also encrypt the email subject line";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "cryptmail-subject-checkbox";
    checkboxWrap.appendChild(checkbox);
    checkboxWrap.appendChild(document.createTextNode(" Encrypt subject"));
    toolbar.appendChild(checkboxWrap);

    const btn = document.createElement("button");
    btn.className = BUTTON_CLASS;
    btn.textContent = "🔒 Encrypt";
    btn.title = "Encrypt the message with CryptMail";
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleEncrypt(composeEl, checkbox.checked);
    });
    toolbar.appendChild(btn);
  }

  /**
   * Handler for the "Encrypt" button.
   * Encrypts the body (and optionally subject), then prompts user to send manually.
   */
  async function handleEncrypt(composeEl, encryptSubject) {
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
      showNotification("Could not determine recipient email.", true);
      return;
    }

    const passphrase = await KeyStore.getKey(recipient);
    if (!passphrase) {
      showNotification(
        `No key found for ${recipient}. Add one in the CryptMail popup.`,
        true
      );
      return;
    }

    try {
      const updateProgress = createProgressBar("🔒 Encrypting message…");
      const encrypted = await CryptMail.encrypt(plaintext, passphrase, undefined, updateProgress);
      body.innerText = encrypted;

      // Optionally encrypt the subject
      if (encryptSubject) {
        const subjectInput = getSubjectInput(composeEl);
        if (subjectInput && subjectInput.value.trim()) {
          const subjectPlain = subjectInput.value.trim();
          const encryptedSubject = await CryptMail.encrypt(subjectPlain, passphrase);
          subjectInput.value = SUBJECT_PREFIX + " " + encryptedSubject;
          // Dispatch input event so Gmail picks up the change
          subjectInput.dispatchEvent(new Event("input", { bubbles: true }));
        }
      }

      hideProgressBar();
      showNotification("✅ Encrypted! Please click Gmail's Send button to send the message.");
    } catch (err) {
      hideProgressBar();
      console.error("CryptMail encryption error:", err);
      showNotification("Encryption failed: " + err.message, true);
    }
  }

  /* ---- Decryption of received messages ---- */

  /**
   * Scan visible message bodies and add a "Decrypt" button for CryptMail envelopes.
   * Decryption only happens when the user clicks the button.
   */
  async function scanAndShowDecryptButton() {
    const messageBodies = document.querySelectorAll(
      '.a3s.aiL, .a3s.aXjCH, div[data-message-id] .a3s'
    );

    for (const el of messageBodies) {
      if (el.getAttribute(DECRYPT_ATTR)) continue;
      if (el.getAttribute(DECRYPT_BTN_ATTR)) continue;

      const text = el.innerText;
      if (!CryptMail.isEncrypted(text)) continue;

      // Try to find the sender's email
      const senderEl =
        el.closest('[data-message-id]')?.querySelector('[email]') ||
        el.closest('.gs')?.querySelector('[email]');
      const senderEmail = senderEl ? senderEl.getAttribute("email") : null;

      if (!senderEmail) continue;

      const passphrase = await KeyStore.getKey(senderEmail);
      if (!passphrase) continue;

      el.setAttribute(DECRYPT_BTN_ATTR, "true");

      // Extract the armored block for later use
      const start = text.indexOf(CryptMail.ENVELOPE_PREFIX);
      const suffixIdx = text.indexOf(CryptMail.ENVELOPE_SUFFIX);
      if (start === -1 || suffixIdx === -1) continue;
      const end = suffixIdx + CryptMail.ENVELOPE_SUFFIX.length;
      const armored = text.substring(start, end);

      // Insert a decrypt button at the top
      const decryptBtn = document.createElement("button");
      decryptBtn.className = "cryptmail-decrypt-btn";
      decryptBtn.textContent = "🔓 Decrypt Message";
      decryptBtn.addEventListener("click", async () => {
        decryptBtn.disabled = true;
        decryptBtn.textContent = "Decrypting…";

        try {
          const updateProgress = createProgressBar("🔓 Decrypting message…");
          const decrypted = await CryptMail.decrypt(armored, passphrase, updateProgress);
          hideProgressBar();

          el.setAttribute(DECRYPT_ATTR, "true");

          // Replace content, preserving a toggle to view raw
          el.innerHTML = "";

          const clearDiv = document.createElement("div");
          clearDiv.className = "cryptmail-decrypted";
          clearDiv.textContent = decrypted;

          const toggleBtn = document.createElement("button");
          toggleBtn.className = "cryptmail-toggle-btn";
          toggleBtn.textContent = "Show encrypted";
          let showingRaw = false;
          toggleBtn.addEventListener("click", () => {
            showingRaw = !showingRaw;
            if (showingRaw) {
              clearDiv.textContent = armored;
              toggleBtn.textContent = "Show decrypted";
            } else {
              clearDiv.textContent = decrypted;
              toggleBtn.textContent = "Show encrypted";
            }
          });

          el.appendChild(toggleBtn);
          el.appendChild(clearDiv);
        } catch (err) {
          hideProgressBar();
          decryptBtn.disabled = false;
          decryptBtn.textContent = "🔓 Decrypt Message";
          console.warn("CryptMail decryption failed for message from", senderEmail, err);
          showNotification("Decryption failed: " + err.message, true);
        }
      });

      el.insertBefore(decryptBtn, el.firstChild);
    }
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

  /* ---- Observer ---- */

  function scanCompose() {
    const composeWindows = document.querySelectorAll(
      '.M9, .dw .nH, .inboxsdk__compose'
    );
    composeWindows.forEach(injectButton);

    // Also try the generic compose containers
    const editables = document.querySelectorAll(
      'div[contenteditable="true"][aria-label]'
    );
    editables.forEach((el) => {
      const compose = el.closest('.M9') || el.closest('.dw') || el.closest('form');
      if (compose) injectButton(compose);
    });
  }

  // Periodic scan for new compose windows and encrypted messages
  setInterval(() => {
    scanCompose();
    scanAndShowDecryptButton();
  }, SCAN_INTERVAL_MS);

  // Initial scan
  scanCompose();
  scanAndShowDecryptButton();

  // Check for first-run welcome screen
  checkFirstRun();
})();
