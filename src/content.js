/**
 * CryptMail – Gmail Content Script
 *
 * Observes the Gmail DOM for:
 *   1. Compose windows  → adds an "Encrypt & Send" button.
 *   2. Message bodies    → auto-decrypts CryptMail envelopes inline.
 */

(() => {
  "use strict";

  /* ---- Constants ---- */
  const DECRYPT_ATTR = "data-cryptmail-decrypted";
  const BUTTON_CLASS = "cryptmail-send-btn";
  const SCAN_INTERVAL_MS = 2000;

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
   * Inject the "Encrypt & Send" button into a compose toolbar.
   */
  function injectButton(composeEl) {
    if (composeEl.querySelector("." + BUTTON_CLASS)) return;

    const toolbar = composeEl.querySelector('[role="toolbar"]') ||
                    composeEl.querySelector(".btC");
    if (!toolbar) return;

    const btn = document.createElement("button");
    btn.className = BUTTON_CLASS;
    btn.textContent = "🔒 Encrypt & Send";
    btn.title = "Encrypt the message with CryptMail, then send";
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleEncryptAndSend(composeEl);
    });
    toolbar.appendChild(btn);
  }

  /**
   * Handler for the "Encrypt & Send" button.
   */
  async function handleEncryptAndSend(composeEl) {
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
      showNotification("Encrypting…");
      const encrypted = await CryptMail.encrypt(plaintext, passphrase);
      body.innerText = encrypted;
      showNotification("Encrypted! Click Gmail's Send button to send.");

      // Simulate clicking Gmail's native send button
      const sendBtn =
        composeEl.querySelector('[role="button"][data-tooltip*="Send"]') ||
        composeEl.querySelector('[aria-label*="Send"]');
      if (sendBtn) {
        sendBtn.click();
      }
    } catch (err) {
      console.error("CryptMail encryption error:", err);
      showNotification("Encryption failed: " + err.message, true);
    }
  }

  /* ---- Decryption of received messages ---- */

  /**
   * Scan visible message bodies and decrypt any CryptMail envelopes found.
   */
  async function scanAndDecrypt() {
    const messageBodies = document.querySelectorAll(
      '.a3s.aiL, .a3s.aXjCH, div[data-message-id] .a3s'
    );

    for (const el of messageBodies) {
      if (el.getAttribute(DECRYPT_ATTR)) continue;

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

      try {
        // Extract just the armored block
        const start = text.indexOf(CryptMail.ENVELOPE_PREFIX);
        const end = text.indexOf(CryptMail.ENVELOPE_SUFFIX) +
                    CryptMail.ENVELOPE_SUFFIX.length;
        const armored = text.substring(start, end);

        const decrypted = await CryptMail.decrypt(armored, passphrase);

        el.setAttribute(DECRYPT_ATTR, "true");

        // Replace content, preserving a toggle to view raw
        const original = el.innerHTML;
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
        console.warn("CryptMail decryption failed for message from", senderEmail, err);
      }
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
    }, 4000);
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
    scanAndDecrypt();
  }, SCAN_INTERVAL_MS);

  // Initial scan
  scanCompose();
  scanAndDecrypt();
})();
