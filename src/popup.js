/**
 * CryptMail – Popup UI Logic
 *
 * Manages:
 *  - Master password unlock flow
 *  - Keys tab: add/search/edit/remove contact passphrases
 *  - Settings tab: toggle preferences
 *  - Security tab: ECDH key pair, public keys, file encrypt/decrypt
 *
 * All state management is routed to the background service worker via KeyStore proxy.
 */

(() => {
  "use strict";

  /* ---- DOM references ---- */
  const $ = (id) => document.getElementById(id);

  const masterLock = $("master-lock");
  const mainContent = $("main-content");
  const masterPasswordInput = $("masterPassword");
  const unlockBtn = $("unlockBtn");
  const masterStatus = $("masterStatus");
  const lockBadge = $("lockBadge");

  const welcomeBanner = $("welcome-banner");
  const dismissWelcome = $("dismissWelcome");

  // Keys tab
  const emailInput = $("email");
  const passphraseInput = $("passphrase");
  const saveBtn = $("saveBtn");
  const statusEl = $("status");
  const keyListEl = $("keyList");
  const keySearchInput = $("keySearch");

  // Settings tab
  const optStealth = $("opt-stealth");
  const optAutoDecrypt = $("opt-autoDecrypt");
  const optEncryptSubject = $("opt-encryptSubject");
  const optStatusIndicator = $("opt-statusIndicator");
  const stealthSubjectsEl = $("stealthSubjects");
  const saveSettingsBtn = $("saveSettingsBtn");
  const settingsStatusEl = $("settingsStatus");

  // Security tab
  const keypairInfoEl = $("keypairInfo");
  const generateKeyPairBtn = $("generateKeyPairBtn");
  const copyPubKeyBtn = $("copyPubKeyBtn");
  const pubkeyListEl = $("pubkeyList");
  const addPubKeyEmail = $("addPubKeyEmail");
  const addPubKeyValue = $("addPubKeyValue");
  const addPubKeyBtn = $("addPubKeyBtn");
  const fileContact = $("fileContact");
  const encryptFileBtn = $("encryptFileBtn");
  const decryptFileBtn = $("decryptFileBtn");
  const securityStatusEl = $("securityStatus");

  let _currentPublicKey = null;

  /* ---- Welcome banner ---- */

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get("cryptmail_popup_welcomed", (result) => {
      if (!result.cryptmail_popup_welcomed) {
        welcomeBanner.style.display = "block";
      }
    });
  }

  if (dismissWelcome) {
    dismissWelcome.addEventListener("click", () => {
      welcomeBanner.style.display = "none";
      if (typeof chrome !== "undefined" && chrome.storage) {
        chrome.storage.local.set({ cryptmail_popup_welcomed: true });
      }
    });
  }

  /* ---- Tabs ---- */

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      tab.classList.add("active");
      const target = tab.getAttribute("data-tab");
      const content = $("tab-" + target);
      if (content) content.classList.add("active");

      // Refresh data when switching to a tab
      if (target === "settings") loadSettings();
      if (target === "security") {
        loadKeyPairInfo();
        loadPublicKeys();
      }
    });
  });

  /* ---- Helpers ---- */

  function showStatus(el, msg, isError) {
    el.textContent = msg;
    el.className = isError ? "error" : "";
    setTimeout(() => {
      el.textContent = "";
      el.className = "";
    }, 3000);
  }

  /* ---- Key Management ---- */

  let _allKeys = {};

  async function renderKeys(filter) {
    try {
      _allKeys = await KeyStore.listKeys();
    } catch (err) {
      showStatus(statusEl, "Failed to load keys: " + err.message, true);
      return;
    }

    let emails = Object.keys(_allKeys);
    if (filter) {
      const lf = filter.toLowerCase();
      emails = emails.filter((e) => e.includes(lf));
    }

    if (emails.length === 0) {
      keyListEl.innerHTML = '<div class="empty-state">' +
        (filter ? "No matching contacts." : "No keys stored yet.") +
        "</div>";
      return;
    }

    keyListEl.innerHTML = "";
    emails.sort().forEach((email) => {
      const item = document.createElement("div");
      item.className = "key-item";

      const span = document.createElement("span");
      span.className = "email";
      span.textContent = email;
      span.title = email;

      const badge = document.createElement("span");
      badge.className = "key-type";
      badge.textContent = "PSK";

      const actions = document.createElement("div");
      actions.className = "key-actions";

      // Edit button
      const editBtn = document.createElement("button");
      editBtn.className = "edit-btn";
      editBtn.textContent = "✏️";
      editBtn.title = "Edit passphrase";
      editBtn.addEventListener("click", () => {
        startEdit(item, email);
      });

      // Remove button
      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = "Remove key";
      removeBtn.addEventListener("click", async () => {
        await KeyStore.removeKey(email);
        showStatus(statusEl, `Key for ${email} removed.`);
        renderKeys(keySearchInput.value);
      });

      actions.appendChild(editBtn);
      actions.appendChild(removeBtn);

      item.appendChild(span);
      item.appendChild(badge);
      item.appendChild(actions);
      keyListEl.appendChild(item);
    });
  }

  function startEdit(itemEl, email) {
    // Replace the item content with an inline edit form
    const currentValue = _allKeys[email] || "";
    itemEl.innerHTML = "";
    itemEl.className = "key-item";

    const label = document.createElement("span");
    label.className = "email";
    label.textContent = email;
    label.style.fontSize = "11px";

    const editRow = document.createElement("div");
    editRow.className = "edit-row";
    editRow.style.flex = "1";
    editRow.style.marginLeft = "8px";

    const input = document.createElement("input");
    input.type = "password";
    input.value = currentValue;
    input.placeholder = "New passphrase";
    input.style.flex = "1";

    const saveEditBtn = document.createElement("button");
    saveEditBtn.className = "btn btn-small";
    saveEditBtn.textContent = "Save";
    saveEditBtn.addEventListener("click", async () => {
      if (input.value) {
        await KeyStore.setKey(email, input.value);
        showStatus(statusEl, `Updated key for ${email}.`);
      }
      renderKeys(keySearchInput.value);
    });

    const cancelBtn = document.createElement("button");
    cancelBtn.className = "btn btn-small btn-secondary";
    cancelBtn.textContent = "×";
    cancelBtn.addEventListener("click", () => {
      renderKeys(keySearchInput.value);
    });

    editRow.appendChild(input);
    editRow.appendChild(saveEditBtn);
    editRow.appendChild(cancelBtn);

    itemEl.appendChild(label);
    itemEl.appendChild(editRow);
    input.focus();
  }

  saveBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const passphrase = passphraseInput.value;

    if (!email) {
      showStatus(statusEl, "Please enter an email address.", true);
      return;
    }
    if (!passphrase) {
      showStatus(statusEl, "Please enter a passphrase.", true);
      return;
    }

    try {
      await KeyStore.setKey(email, passphrase);
      showStatus(statusEl, `Key saved for ${email}.`);
      emailInput.value = "";
      passphraseInput.value = "";
      renderKeys(keySearchInput.value);
    } catch (err) {
      showStatus(statusEl, "Error: " + err.message, true);
    }
  });

  // Key search
  keySearchInput.addEventListener("input", () => {
    renderKeys(keySearchInput.value);
  });

  /* ---- Settings ---- */

  async function loadSettings() {
    try {
      const settings = await KeyStore.getSettings();
      optStealth.checked = !!settings.stealthMode;
      optAutoDecrypt.checked = !!settings.autoDecrypt;
      optEncryptSubject.checked = !!settings.encryptSubjectByDefault;
      optStatusIndicator.checked = settings.showStatusIndicator !== false;
      stealthSubjectsEl.value = (settings.stealthSubjects || []).join("\n");
    } catch (err) {
      showStatus(settingsStatusEl, "Failed to load settings: " + err.message, true);
    }
  }

  saveSettingsBtn.addEventListener("click", async () => {
    try {
      const subjects = stealthSubjectsEl.value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      await KeyStore.saveSettings({
        stealthMode: optStealth.checked,
        autoDecrypt: optAutoDecrypt.checked,
        encryptSubjectByDefault: optEncryptSubject.checked,
        showStatusIndicator: optStatusIndicator.checked,
        stealthSubjects: subjects,
      });
      showStatus(settingsStatusEl, "Settings saved.");
    } catch (err) {
      showStatus(settingsStatusEl, "Error: " + err.message, true);
    }
  });

  /* ---- Security: ECDH Key Pair ---- */

  async function loadKeyPairInfo() {
    try {
      const keyPair = await KeyStore.getKeyPair();
      if (keyPair && keyPair.publicKey) {
        _currentPublicKey = keyPair.publicKey;
        keypairInfoEl.innerHTML =
          '<div class="pubkey-display">' + escapeHtml(keyPair.publicKey) + "</div>";
        copyPubKeyBtn.disabled = false;
        generateKeyPairBtn.textContent = "Regenerate Key Pair";
      } else {
        keypairInfoEl.innerHTML =
          '<div class="empty-state">No key pair generated yet.</div>';
        copyPubKeyBtn.disabled = true;
        _currentPublicKey = null;
      }
    } catch (err) {
      keypairInfoEl.innerHTML =
        '<div class="empty-state">Could not load key pair.</div>';
    }
  }

  generateKeyPairBtn.addEventListener("click", async () => {
    try {
      generateKeyPairBtn.disabled = true;
      generateKeyPairBtn.textContent = "Generating…";
      const publicKey = await KeyStore.generateKeyPair();
      _currentPublicKey = publicKey;
      showStatus(securityStatusEl, "Key pair generated.");
      loadKeyPairInfo();
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    } finally {
      generateKeyPairBtn.disabled = false;
    }
  });

  copyPubKeyBtn.addEventListener("click", () => {
    if (_currentPublicKey) {
      navigator.clipboard.writeText(_currentPublicKey).then(
        () => showStatus(securityStatusEl, "Public key copied to clipboard."),
        () => showStatus(securityStatusEl, "Failed to copy.", true)
      );
    }
  });

  /* ---- Security: Contact Public Keys ---- */

  async function loadPublicKeys() {
    try {
      const keys = await KeyStore.listContactPublicKeys();
      const emails = Object.keys(keys);

      if (emails.length === 0) {
        pubkeyListEl.innerHTML =
          '<div class="empty-state">No contact public keys stored.</div>';
        return;
      }

      pubkeyListEl.innerHTML = "";
      emails.sort().forEach((email) => {
        const item = document.createElement("div");
        item.className = "pubkey-item";

        const emailSpan = document.createElement("span");
        emailSpan.className = "pk-email";
        emailSpan.textContent = email;
        emailSpan.title = keys[email];

        const removeBtn = document.createElement("button");
        removeBtn.className = "btn btn-small btn-secondary";
        removeBtn.textContent = "✕";
        removeBtn.style.marginLeft = "4px";
        removeBtn.addEventListener("click", async () => {
          // Remove by setting to null/empty – or we need a dedicated remove
          // For now, just reload (the store doesn't have a remove pubkey, so we'll skip)
          showStatus(securityStatusEl, "Contact public key management coming soon.");
        });

        item.appendChild(emailSpan);
        item.appendChild(removeBtn);
        pubkeyListEl.appendChild(item);
      });
    } catch (err) {
      pubkeyListEl.innerHTML =
        '<div class="empty-state">Could not load public keys.</div>';
    }
  }

  addPubKeyBtn.addEventListener("click", async () => {
    const email = addPubKeyEmail.value.trim();
    const pubKey = addPubKeyValue.value.trim();
    if (!email || !pubKey) {
      showStatus(securityStatusEl, "Please enter both email and public key.", true);
      return;
    }
    try {
      await KeyStore.storeContactPublicKey(email, pubKey);
      showStatus(securityStatusEl, `Public key stored for ${email}.`);
      addPubKeyEmail.value = "";
      addPubKeyValue.value = "";
      loadPublicKeys();
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    }
  });

  /* ---- Security: File Encrypt / Decrypt ---- */

  encryptFileBtn.addEventListener("click", async () => {
    const contact = fileContact.value.trim();
    if (!contact) {
      showStatus(securityStatusEl, "Enter a contact email for the passphrase.", true);
      return;
    }

    try {
      const passphrase = await KeyStore.getKey(contact);
      if (!passphrase) {
        showStatus(
          securityStatusEl,
          "No passphrase stored for " + contact + ". Add one in the Keys tab.",
          true
        );
        return;
      }

      const input = document.createElement("input");
      input.type = "file";
      input.accept = "*/*";
      input.addEventListener("change", async () => {
        const file = input.files[0];
        if (!file) return;

        try {
          encryptFileBtn.disabled = true;
          encryptFileBtn.textContent = "Encrypting…";
          const buffer = await file.arrayBuffer();
          const encrypted = await CryptMail.encryptFile(
            buffer,
            file.name,
            file.type,
            passphrase
          );

          const blob = new Blob([encrypted], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = file.name + ".cmail";
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);

          showStatus(securityStatusEl, "File encrypted and downloaded.");
        } catch (err) {
          showStatus(securityStatusEl, "Encryption failed: " + err.message, true);
        } finally {
          encryptFileBtn.disabled = false;
          encryptFileBtn.textContent = "🔒 Encrypt File";
        }
      });
      input.click();
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    }
  });

  decryptFileBtn.addEventListener("click", async () => {
    const contact = fileContact.value.trim();
    if (!contact) {
      showStatus(securityStatusEl, "Enter the sender's email for the passphrase.", true);
      return;
    }

    try {
      const passphrase = await KeyStore.getKey(contact);
      if (!passphrase) {
        showStatus(
          securityStatusEl,
          "No passphrase stored for " + contact + ".",
          true
        );
        return;
      }

      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".cmail,.enc,.json";
      input.addEventListener("change", async () => {
        const file = input.files[0];
        if (!file) return;

        try {
          decryptFileBtn.disabled = true;
          decryptFileBtn.textContent = "Decrypting…";
          const text = await file.text();
          const result = await CryptMail.decryptFile(text, passphrase);

          const blob = new Blob([result.data], { type: result.mimeType });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = result.filename;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);

          showStatus(
            securityStatusEl,
            "File decrypted: " + result.filename
          );
        } catch (err) {
          showStatus(securityStatusEl, "Decryption failed: " + err.message, true);
        } finally {
          decryptFileBtn.disabled = false;
          decryptFileBtn.textContent = "🔓 Decrypt .cmail";
        }
      });
      input.click();
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    }
  });

  /* ---- Master password unlock flow ---- */

  async function showMasterLock() {
    try {
      const hasMP = await KeyStore.hasMasterPassword();
      masterStatus.textContent = hasMP
        ? ""
        : "First time? Choose a master password to protect your keys.";
      masterStatus.className = "";
    } catch {
      masterStatus.textContent = "";
    }
    masterLock.style.display = "block";
    mainContent.style.display = "none";
    lockBadge.textContent = "🔒";
  }

  async function handleUnlock() {
    const pw = masterPasswordInput.value;
    if (!pw) {
      masterStatus.textContent = "Please enter a master password.";
      masterStatus.className = "error";
      return;
    }
    try {
      unlockBtn.disabled = true;
      unlockBtn.textContent = "Unlocking…";
      const ok = await KeyStore.unlock(pw);
      if (ok) {
        masterLock.style.display = "none";
        mainContent.style.display = "block";
        lockBadge.textContent = "🔓";
        renderKeys();
        loadSettings();
      } else {
        masterStatus.textContent = "Wrong master password.";
        masterStatus.className = "error";
      }
    } catch (err) {
      masterStatus.textContent = "Error: " + err.message;
      masterStatus.className = "error";
    } finally {
      unlockBtn.disabled = false;
      unlockBtn.textContent = "Unlock";
    }
  }

  unlockBtn.addEventListener("click", handleUnlock);
  masterPasswordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleUnlock();
  });

  // Lock badge click – toggle lock state
  lockBadge.addEventListener("click", async () => {
    try {
      const unlocked = await KeyStore.isUnlocked();
      if (unlocked) {
        await KeyStore.lock();
        showMasterLock();
      } else {
        // Already showing lock screen
      }
    } catch {
      showMasterLock();
    }
  });

  /* ---- Startup ---- */

  async function init() {
    try {
      const unlocked = await KeyStore.isUnlocked();
      if (unlocked) {
        masterLock.style.display = "none";
        mainContent.style.display = "block";
        lockBadge.textContent = "🔓";
        renderKeys();
        loadSettings();
      } else {
        showMasterLock();
      }
    } catch {
      showMasterLock();
    }
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  init();
})();
