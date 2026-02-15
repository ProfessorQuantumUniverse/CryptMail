/**
 * CryptMail – Popup UI logic
 */

(() => {
  "use strict";

  const emailInput = document.getElementById("email");
  const passphraseInput = document.getElementById("passphrase");
  const saveBtn = document.getElementById("saveBtn");
  const statusEl = document.getElementById("status");
  const keyListEl = document.getElementById("keyList");
  const welcomeBanner = document.getElementById("welcome-banner");
  const dismissWelcome = document.getElementById("dismissWelcome");

  const masterLock = document.getElementById("master-lock");
  const mainContent = document.getElementById("main-content");
  const masterPasswordInput = document.getElementById("masterPassword");
  const unlockBtn = document.getElementById("unlockBtn");
  const masterStatus = document.getElementById("masterStatus");

  // Show welcome banner on first open
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
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ cryptmail_popup_welcomed: true });
      }
    });
  }

  function showStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.className = isError ? "error" : "";
    setTimeout(() => {
      statusEl.textContent = "";
      statusEl.className = "";
    }, 3000);
  }

  async function renderKeys() {
    let keys;
    try {
      keys = await KeyStore.listKeys();
    } catch (err) {
      showStatus("Failed to load keys: " + err.message, true);
      return;
    }
    const emails = Object.keys(keys);

    if (emails.length === 0) {
      keyListEl.innerHTML = '<div class="empty-state">No keys stored yet.</div>';
      return;
    }

    keyListEl.innerHTML = "";
    emails.forEach((email) => {
      const item = document.createElement("div");
      item.className = "key-item";

      const span = document.createElement("span");
      span.className = "email";
      span.textContent = email;

      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = "Remove key";
      removeBtn.addEventListener("click", async () => {
        await KeyStore.removeKey(email);
        showStatus(`Key for ${email} removed.`);
        renderKeys();
      });

      item.appendChild(span);
      item.appendChild(removeBtn);
      keyListEl.appendChild(item);
    });
  }

  saveBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const passphrase = passphraseInput.value;

    if (!email) {
      showStatus("Please enter an email address.", true);
      return;
    }
    if (!passphrase) {
      showStatus("Please enter a passphrase.", true);
      return;
    }

    await KeyStore.setKey(email, passphrase);
    showStatus(`Key saved for ${email}.`);
    emailInput.value = "";
    passphraseInput.value = "";
    renderKeys();
  });

  /* ---- Master password unlock flow ---- */

  async function showMasterLock() {
    const hasMP = await KeyStore.hasMasterPassword();
    masterStatus.textContent = hasMP
      ? ""
      : "First time? Choose a master password to protect your keys.";
    masterStatus.className = "";
    masterLock.style.display = "block";
    mainContent.style.display = "none";
  }

  async function handleUnlock() {
    const pw = masterPasswordInput.value;
    if (!pw) {
      masterStatus.textContent = "Please enter a master password.";
      masterStatus.className = "error";
      return;
    }
    const ok = await KeyStore.unlock(pw);
    if (ok) {
      masterLock.style.display = "none";
      mainContent.style.display = "block";
      renderKeys();
    } else {
      masterStatus.textContent = "Wrong master password.";
      masterStatus.className = "error";
    }
  }

  unlockBtn.addEventListener("click", handleUnlock);
  masterPasswordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleUnlock();
  });

  // On load: if the store is already unlocked (same page session), skip the lock screen
  if (KeyStore.isUnlocked()) {
    masterLock.style.display = "none";
    mainContent.style.display = "block";
    renderKeys();
  } else {
    showMasterLock();
  }
})();
