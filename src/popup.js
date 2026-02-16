/**
 * CryptMail v3.0 – Popup UI Logic
 *
 * Manages:
 *  - Onboarding wizard (first-run setup with 4 steps)
 *  - WebAuthn biometric unlock (Windows Hello / Touch ID)
 *  - Master password unlock flow
 *  - Keys tab: contact management with trust indicators
 *  - Settings tab: biometric, auto key exchange, preferences
 *  - Security tab: ECDH identity, public keys, file encrypt/decrypt
 */

(() => {
  "use strict";

  /* ---- DOM references ---- */
  const $ = (id) => document.getElementById(id);

  /* -- App containers -- */
  const onboardingEl = $("onboarding");
  const appEl = $("app");
  const masterLock = $("master-lock");
  const mainContent = $("main-content");
  const masterPasswordInput = $("masterPassword");
  const unlockBtn = $("unlockBtn");
  const masterStatus = $("masterStatus");
  const lockBadge = $("lockBadge");
  const biometricBadge = $("biometricBadge");

  const welcomeBanner = $("welcome-banner");
  const dismissWelcome = $("dismissWelcome");

  /* -- Biometric unlock on lock screen -- */
  const biometricUnlockSection = $("biometric-unlock");
  const biometricUnlockBtn = $("biometricUnlockBtn");

  /* -- Keys tab -- */
  const emailInput = $("email");
  const passphraseInput = $("passphrase");
  const saveBtn = $("saveBtn");
  const statusEl = $("status");
  const keyListEl = $("keyList");
  const keySearchInput = $("keySearch");

  /* -- Settings tab -- */
  const optBiometric = $("opt-biometric");
  const optAutoKeyExchange = $("opt-autoKeyExchange");
  const optStealth = $("opt-stealth");
  const optAutoDecrypt = $("opt-autoDecrypt");
  const optEncryptSubject = $("opt-encryptSubject");
  const optStatusIndicator = $("opt-statusIndicator");
  const stealthSubjectsEl = $("stealthSubjects");
  const saveSettingsBtn = $("saveSettingsBtn");
  const settingsStatusEl = $("settingsStatus");

  /* -- Security tab -- */
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
  let _selectedMode = "psk";

  /* ======================================================
   *  ONBOARDING WIZARD
   * ====================================================== */

  let _wizardStep = 1;
  let _wizardPassword = null;

  function showOnboarding() {
    onboardingEl.style.display = "flex";
    appEl.style.display = "none";
    goToWizardStep(1);
  }

  function hideOnboarding() {
    onboardingEl.style.display = "none";
    appEl.style.display = "block";
  }

  function goToWizardStep(step) {
    _wizardStep = step;

    // Update dots
    document.querySelectorAll(".wizard-dot").forEach((dot) => {
      const s = parseInt(dot.getAttribute("data-step"));
      dot.classList.remove("active", "done");
      if (s < step) dot.classList.add("done");
      if (s === step) dot.classList.add("active");
    });

    // Update lines
    for (let i = 1; i <= 3; i++) {
      const line = $("wiz-line-" + i);
      if (line) {
        line.classList.toggle("done", i < step);
      }
    }

    // Show the right page
    document.querySelectorAll(".wizard-page").forEach((p) => {
      p.classList.remove("active");
    });
    const page = $("wizard-step-" + step);
    if (page) page.classList.add("active");
  }

  /* -- Step 1: Master Password with strength meter -- */

  const wizardPw = $("wizard-pw");
  const wizardPwConfirm = $("wizard-pw-confirm");
  const strengthBar = $("strength-bar");
  const strengthLabel = $("strength-label");
  const wizardPwError = $("wizard-pw-error");

  function calculateStrength(pw) {
    if (!pw) return { score: 0, label: "", cls: "" };
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length >= 16) score++;

    if (score <= 1) return { score, label: "Weak — add more characters", cls: "weak" };
    if (score <= 2) return { score, label: "Fair — try uppercase & numbers", cls: "fair" };
    if (score <= 3) return { score, label: "Good — almost there!", cls: "good" };
    return { score, label: "Strong — excellent!", cls: "strong" };
  }

  if (wizardPw) {
    wizardPw.addEventListener("input", () => {
      const s = calculateStrength(wizardPw.value);
      strengthBar.className = "strength-bar " + s.cls;
      strengthLabel.textContent = s.label;
    });
  }

  if ($("wizard-next-1")) {
    $("wizard-next-1").addEventListener("click", async () => {
      const pw = wizardPw.value;
      const confirm = wizardPwConfirm.value;
      wizardPwError.textContent = "";

      if (!pw || pw.length < 6) {
        wizardPwError.textContent = "Password must be at least 6 characters.";
        return;
      }
      if (pw !== confirm) {
        wizardPwError.textContent = "Passwords don't match.";
        return;
      }

      try {
        $("wizard-next-1").disabled = true;
        $("wizard-next-1").textContent = "Setting up…";
        const ok = await KeyStore.unlock(pw);
        if (ok) {
          _wizardPassword = pw;
          goToWizardStep(2);
        } else {
          wizardPwError.textContent = "Failed to set master password.";
        }
      } catch (err) {
        wizardPwError.textContent = "Error: " + err.message;
      } finally {
        $("wizard-next-1").disabled = false;
        $("wizard-next-1").textContent = "Continue →";
      }
    });
  }

  /* -- Step 2: Biometric Setup -- */

  if ($("wizard-biometric")) {
    $("wizard-biometric").addEventListener("click", async () => {
      await registerBiometric(_wizardPassword, $("wizard-biometric-status"), () => {
        $("wizard-biometric").classList.add("success");
        $("wizard-biometric").innerHTML =
          '<span class="biometric-icon">✅</span><span>Biometric Enabled!</span>';
        $("wizard-skip-2").style.display = "none";
        $("wizard-next-2").style.display = "block";
      });
    });
  }

  if ($("wizard-skip-2")) {
    $("wizard-skip-2").addEventListener("click", () => goToWizardStep(3));
  }
  if ($("wizard-next-2")) {
    $("wizard-next-2").addEventListener("click", () => goToWizardStep(3));
  }

  /* -- Step 3: Generate Identity -- */

  if ($("wizard-generate")) {
    $("wizard-generate").addEventListener("click", async () => {
      try {
        $("wizard-generate").disabled = true;
        $("wizard-generate").innerHTML = '<span class="spinner"></span> Generating…';
        const publicKey = await KeyStore.generateKeyPair();
        _currentPublicKey = publicKey;

        const fp = generateFingerprint(publicKey);
        $("wizard-fingerprint").textContent = fp;
        $("identity-card").style.display = "block";
        $("wizard-generate").style.display = "none";
        $("wizard-next-3").style.display = "block";
      } catch (err) {
        $("wizard-generate").textContent = "Retry";
        $("wizard-generate").disabled = false;
      }
    });
  }

  if ($("wizard-next-3")) {
    $("wizard-next-3").addEventListener("click", () => goToWizardStep(4));
  }

  /* -- Step 4: Done -- */

  if ($("wizard-finish")) {
    $("wizard-finish").addEventListener("click", async () => {
      try {
        await KeyStore.setOnboardingDone();
      } catch { /* ignore */ }
      hideOnboarding();
      masterLock.style.display = "none";
      mainContent.style.display = "block";
      lockBadge.textContent = "🔓";
      renderKeys();
      loadSettings();
      checkBiometricBadge();
    });
  }

  /* ======================================================
   *  WEBAUTHN BIOMETRIC
   * ====================================================== */

  /**
   * Register a WebAuthn credential and store the encrypted master password.
   * The biometric (Windows Hello / Touch ID) acts as a gate:
   * only a successful assertion allows decryption.
   */
  async function registerBiometric(masterPassword, statusEl, onSuccess) {
    if (!window.PublicKeyCredential) {
      if (statusEl) statusEl.textContent = "Biometrics not supported in this browser.";
      return;
    }

    try {
      if (statusEl) statusEl.textContent = "Waiting for biometric…";

      const userId = crypto.getRandomValues(new Uint8Array(16));
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const credential = await navigator.credentials.create({
        publicKey: {
          rp: { name: "CryptMail", id: location.hostname || "cryptmail.extension" },
          user: {
            id: userId,
            name: "cryptmail-user",
            displayName: "CryptMail User",
          },
          challenge,
          pubKeyCredParams: [
            { alg: -7, type: "public-key" },   // ES256
            { alg: -257, type: "public-key" },  // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required",
            residentKey: "discouraged",
          },
          timeout: 60000,
        },
      });

      if (!credential) {
        if (statusEl) statusEl.textContent = "Biometric registration cancelled.";
        return;
      }

      // Generate a wrapping key and encrypt the master password
      const wrappingKey = crypto.getRandomValues(new Uint8Array(32));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await crypto.subtle.importKey(
        "raw", wrappingKey, { name: "AES-GCM" }, false, ["encrypt"]
      );
      const enc = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          new TextEncoder().encode(masterPassword)
        )
      );

      // Store credential data
      const credentialId = Array.from(new Uint8Array(credential.rawId));
      await KeyStore.storeWebAuthnData({
        credentialId,
        wrappingKey: Array.from(wrappingKey),
        iv: Array.from(iv),
        encryptedPassword: Array.from(enc),
      });

      if (statusEl) statusEl.textContent = "Biometric unlock enabled!";
      if (onSuccess) onSuccess();
    } catch (err) {
      const msg = err.name === "NotAllowedError"
        ? "Biometric registration cancelled."
        : "Biometric setup failed: " + err.message;
      if (statusEl) statusEl.textContent = msg;
    }
  }

  /**
   * Authenticate with biometrics and unlock the store.
   */
  async function authenticateBiometric() {
    const data = await KeyStore.getWebAuthnData();
    if (!data) return false;

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const credentialId = new Uint8Array(data.credentialId);

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          allowCredentials: [{
            id: credentialId,
            type: "public-key",
            transports: ["internal"],
          }],
          userVerification: "required",
          timeout: 60000,
        },
      });

      if (!assertion) return false;

      // Decrypt the stored master password
      const wrappingKey = new Uint8Array(data.wrappingKey);
      const iv = new Uint8Array(data.iv);
      const encryptedPassword = new Uint8Array(data.encryptedPassword);

      const key = await crypto.subtle.importKey(
        "raw", wrappingKey, { name: "AES-GCM" }, false, ["decrypt"]
      );
      const decBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv }, key, encryptedPassword
      );
      const masterPassword = new TextDecoder().decode(decBuf);

      // Unlock the store
      const ok = await KeyStore.unlock(masterPassword);
      return ok;
    } catch (err) {
      if (err.name === "NotAllowedError") return false;
      console.warn("CryptMail biometric auth error:", err);
      return false;
    }
  }

  async function checkBiometricBadge() {
    try {
      const data = await KeyStore.getWebAuthnData();
      if (data) {
        biometricBadge.style.display = "inline-block";
        biometricUnlockSection.style.display = "block";
      } else {
        biometricBadge.style.display = "none";
        biometricUnlockSection.style.display = "none";
      }
    } catch {
      biometricBadge.style.display = "none";
    }
  }

  /* -- Biometric unlock on lock screen -- */

  if (biometricUnlockBtn) {
    biometricUnlockBtn.addEventListener("click", async () => {
      biometricUnlockBtn.disabled = true;
      const origHTML = biometricUnlockBtn.innerHTML;
      biometricUnlockBtn.innerHTML =
        '<span class="spinner"></span><span>Verifying…</span>';

      const ok = await authenticateBiometric();
      if (ok) {
        masterLock.style.display = "none";
        mainContent.style.display = "block";
        lockBadge.textContent = "🔓";
        renderKeys();
        loadSettings();
      } else {
        masterStatus.textContent = "Biometric verification failed. Use password.";
        masterStatus.className = "error";
      }

      biometricUnlockBtn.disabled = false;
      biometricUnlockBtn.innerHTML = origHTML;
    });
  }

  /* ======================================================
   *  WELCOME BANNER
   * ====================================================== */

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get("cryptmail_popup_welcomed_v3", (result) => {
      if (!result.cryptmail_popup_welcomed_v3) {
        welcomeBanner.style.display = "block";
      }
    });
  }

  if (dismissWelcome) {
    dismissWelcome.addEventListener("click", () => {
      welcomeBanner.style.display = "none";
      if (typeof chrome !== "undefined" && chrome.storage) {
        chrome.storage.local.set({ cryptmail_popup_welcomed_v3: true });
      }
    });
  }

  /* ======================================================
   *  TABS
   * ====================================================== */

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      tab.classList.add("active");
      const target = tab.getAttribute("data-tab");
      const content = $("tab-" + target);
      if (content) content.classList.add("active");

      if (target === "settings") loadSettings();
      if (target === "security") {
        loadKeyPairInfo();
        loadPublicKeys();
      }
    });
  });

  /* ======================================================
   *  HELPERS
   * ====================================================== */

  function showStatus(el, msg, isError) {
    el.textContent = msg;
    el.className = isError ? "error" : "";
    setTimeout(() => {
      el.textContent = "";
      el.className = "";
    }, 3000);
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  /**
   * Generate a human-readable fingerprint from a public key (base64).
   * Groups of 4 hex chars separated by colons.
   */
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

  /* ======================================================
   *  KEY MANAGEMENT WITH TRUST INDICATORS
   * ====================================================== */

  let _allKeys = {};

  async function renderKeys(filter) {
    try {
      _allKeys = await KeyStore.listKeys();
    } catch (err) {
      showStatus(statusEl, "Failed to load keys: " + err.message, true);
      return;
    }

    // Also load public keys and merge
    let publicKeys = {};
    try {
      publicKeys = await KeyStore.listContactPublicKeys();
    } catch { /* ignore */ }

    const allEmails = new Set([
      ...Object.keys(_allKeys),
      ...Object.keys(publicKeys),
    ]);

    let emails = Array.from(allEmails);
    if (filter) {
      const lf = filter.toLowerCase();
      emails = emails.filter((e) => e.includes(lf));
    }

    if (emails.length === 0) {
      keyListEl.innerHTML = '<div class="empty-state">' +
        (filter ? "No matching contacts." : "No keys stored yet. Add one above!") +
        "</div>";
      return;
    }

    keyListEl.innerHTML = "";
    emails.sort().forEach((email) => {
      const hasPsk = !!_allKeys[email];
      const hasPk = !!publicKeys[email];
      const item = document.createElement("div");
      item.className = "key-item";

      // Trust indicator
      const indicator = document.createElement("span");
      indicator.className = "trust-indicator";
      if (hasPsk && hasPk) {
        indicator.textContent = "🟢";
        indicator.title = "Fully secured: passphrase + public key";
      } else if (hasPsk) {
        indicator.textContent = "🟢";
        indicator.title = "Secured with shared passphrase";
      } else if (hasPk) {
        indicator.textContent = "🟡";
        indicator.title = "Public key available (unverified)";
      } else {
        indicator.textContent = "⚪";
        indicator.title = "No encryption key";
      }

      const span = document.createElement("span");
      span.className = "email";
      span.textContent = email;
      span.title = email;

      // Badge
      const badge = document.createElement("span");
      badge.className = "trust-badge";
      if (hasPk && hasPsk) {
        badge.classList.add("verified");
        badge.textContent = "PKI+PSK";
      } else if (hasPk) {
        badge.classList.add("unverified");
        badge.textContent = "PKI";
      } else if (hasPsk) {
        badge.classList.add("psk");
        badge.textContent = "PSK";
      }

      const actions = document.createElement("div");
      actions.className = "key-actions";

      // Edit
      if (hasPsk) {
        const editBtn = document.createElement("button");
        editBtn.className = "edit-btn";
        editBtn.textContent = "✏️";
        editBtn.title = "Edit passphrase";
        editBtn.addEventListener("click", () => startEdit(item, email));
        actions.appendChild(editBtn);
      }

      // Remove
      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = "Remove key";
      removeBtn.addEventListener("click", async () => {
        if (hasPsk) await KeyStore.removeKey(email);
        if (hasPk) {
          try { await KeyStore.removeContactPublicKey(email); } catch { /* ignore */ }
        }
        showStatus(statusEl, `Key for ${email} removed.`);
        renderKeys(keySearchInput.value);
      });
      actions.appendChild(removeBtn);

      item.appendChild(indicator);
      item.appendChild(span);
      item.appendChild(badge);
      item.appendChild(actions);
      keyListEl.appendChild(item);
    });
  }

  function startEdit(itemEl, email) {
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
    cancelBtn.addEventListener("click", () => renderKeys(keySearchInput.value));

    editRow.appendChild(input);
    editRow.appendChild(saveEditBtn);
    editRow.appendChild(cancelBtn);

    itemEl.appendChild(label);
    itemEl.appendChild(editRow);
    input.focus();
  }

  /* -- Mode selector for new contacts -- */

  document.querySelectorAll("#newContactMode .mode-option").forEach((opt) => {
    opt.addEventListener("click", () => {
      document.querySelectorAll("#newContactMode .mode-option").forEach((o) =>
        o.classList.remove("active")
      );
      opt.classList.add("active");
      _selectedMode = opt.getAttribute("data-mode");

      // Show/hide passphrase field based on mode
      const pwGroup = passphraseInput.closest(".form-group");
      if (_selectedMode === "auto") {
        pwGroup.style.opacity = "0.4";
        passphraseInput.placeholder = "Optional (auto key exchange)";
      } else {
        pwGroup.style.opacity = "1";
        passphraseInput.placeholder = "Agreed secret key";
      }
    });
  });

  saveBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const passphrase = passphraseInput.value;

    if (!email) {
      showStatus(statusEl, "Please enter an email address.", true);
      return;
    }

    if (_selectedMode === "psk" && !passphrase) {
      showStatus(statusEl, "Please enter a passphrase for classic mode.", true);
      return;
    }

    try {
      if (passphrase) {
        await KeyStore.setKey(email, passphrase);
      }
      await KeyStore.setContactMode(email, _selectedMode);
      showStatus(
        statusEl,
        _selectedMode === "auto"
          ? `Auto key exchange set for ${email}.`
          : `Key saved for ${email}.`
      );
      emailInput.value = "";
      passphraseInput.value = "";
      renderKeys(keySearchInput.value);
    } catch (err) {
      showStatus(statusEl, "Error: " + err.message, true);
    }
  });

  keySearchInput.addEventListener("input", () => {
    renderKeys(keySearchInput.value);
  });

  /* ======================================================
   *  SETTINGS
   * ====================================================== */

  async function loadSettings() {
    try {
      const settings = await KeyStore.getSettings();
      optStealth.checked = !!settings.stealthMode;
      optAutoDecrypt.checked = !!settings.autoDecrypt;
      optEncryptSubject.checked = !!settings.encryptSubjectByDefault;
      optStatusIndicator.checked = settings.showStatusIndicator !== false;
      optAutoKeyExchange.checked = settings.autoKeyExchange !== false;
      stealthSubjectsEl.value = (settings.stealthSubjects || []).join("\n");

      // Biometric toggle state
      const webauthnData = await KeyStore.getWebAuthnData();
      optBiometric.checked = !!webauthnData;
    } catch (err) {
      showStatus(settingsStatusEl, "Failed to load settings: " + err.message, true);
    }
  }

  /* -- Biometric toggle in settings -- */
  if (optBiometric) {
    optBiometric.addEventListener("change", async () => {
      if (optBiometric.checked) {
        // Get the current master password to encrypt
        // We need the user to enter it if not available
        const unlocked = await KeyStore.isUnlocked();
        if (!unlocked) {
          optBiometric.checked = false;
          showStatus(settingsStatusEl, "Unlock the store first to enable biometrics.", true);
          return;
        }
        // Prompt for password to store
        const pw = prompt("Enter your master password to enable biometric unlock:");
        if (!pw) {
          optBiometric.checked = false;
          return;
        }
        // Verify password
        const ok = await KeyStore.unlock(pw);
        if (!ok) {
          optBiometric.checked = false;
          showStatus(settingsStatusEl, "Wrong password.", true);
          return;
        }
        await registerBiometric(pw, settingsStatusEl, () => {
          showStatus(settingsStatusEl, "Biometric unlock enabled!");
          checkBiometricBadge();
        });
      } else {
        await KeyStore.removeWebAuthnData();
        showStatus(settingsStatusEl, "Biometric unlock disabled.");
        checkBiometricBadge();
      }
    });
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
        autoKeyExchange: optAutoKeyExchange.checked,
        stealthSubjects: subjects,
      });
      showStatus(settingsStatusEl, "Settings saved.");
    } catch (err) {
      showStatus(settingsStatusEl, "Error: " + err.message, true);
    }
  });

  /* ======================================================
   *  SECURITY: ECDH KEY PAIR
   * ====================================================== */

  async function loadKeyPairInfo() {
    try {
      const keyPair = await KeyStore.getKeyPair();
      if (keyPair && keyPair.publicKey) {
        _currentPublicKey = keyPair.publicKey;
        const fp = generateFingerprint(keyPair.publicKey);
        keypairInfoEl.innerHTML =
          '<div class="identity-card">' +
          '<div class="fingerprint">' + escapeHtml(fp) + "</div>" +
          '<div class="identity-label">Your Key Fingerprint</div>' +
          '<div class="pubkey-display" style="margin-top:8px;font-size:10px;">' +
          escapeHtml(keyPair.publicKey) + "</div>" +
          "</div>";
        copyPubKeyBtn.disabled = false;
        generateKeyPairBtn.textContent = "Regenerate Key Pair";
      } else {
        keypairInfoEl.innerHTML =
          '<div class="empty-state">No key pair generated yet. Generate one to enable automatic encryption.</div>';
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
      generateKeyPairBtn.innerHTML = '<span class="spinner"></span> Generating…';
      const publicKey = await KeyStore.generateKeyPair();
      _currentPublicKey = publicKey;
      showStatus(securityStatusEl, "Key pair generated.");
      loadKeyPairInfo();
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    } finally {
      generateKeyPairBtn.disabled = false;
      generateKeyPairBtn.textContent = "Generate Key Pair";
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

  /* ======================================================
   *  SECURITY: CONTACT PUBLIC KEYS (with verification)
   * ====================================================== */

  async function loadPublicKeys() {
    try {
      const keys = await KeyStore.listContactPublicKeys();
      const emails = Object.keys(keys);

      if (emails.length === 0) {
        pubkeyListEl.innerHTML =
          '<div class="empty-state">No contact public keys stored. Keys are auto-discovered from incoming emails.</div>';
        return;
      }

      pubkeyListEl.innerHTML = "";
      for (const email of emails.sort()) {
        const item = document.createElement("div");
        item.className = "pubkey-item";

        const emailSpan = document.createElement("span");
        emailSpan.className = "pk-email";
        emailSpan.textContent = email;

        const fp = generateFingerprint(keys[email]);
        emailSpan.title = "Fingerprint: " + fp;

        // Check verification status
        let verification = null;
        try {
          verification = await KeyStore.getContactVerification(email);
        } catch { /* ignore */ }

        const statusBadge = document.createElement("span");
        statusBadge.className = "pk-status";
        if (verification && verification.verified) {
          statusBadge.textContent = "✅ Verified";
          statusBadge.style.background = "#e8f5e9";
          statusBadge.style.color = "#1b5e20";
        } else {
          statusBadge.textContent = "⚠️ Unverified";
          statusBadge.style.background = "#fef7e0";
          statusBadge.style.color = "#e37400";
          statusBadge.style.cursor = "pointer";
          statusBadge.title = "Click to verify this key";
          statusBadge.addEventListener("click", () => {
            verifyContactKey(email, keys[email]);
          });
        }

        const removeBtn = document.createElement("button");
        removeBtn.className = "btn btn-small btn-secondary";
        removeBtn.textContent = "✕";
        removeBtn.style.marginLeft = "4px";
        removeBtn.addEventListener("click", async () => {
          try {
            await KeyStore.removeContactPublicKey(email);
            showStatus(securityStatusEl, `Removed public key for ${email}.`);
            loadPublicKeys();
          } catch (err) {
            showStatus(securityStatusEl, "Error: " + err.message, true);
          }
        });

        item.appendChild(emailSpan);
        item.appendChild(statusBadge);
        item.appendChild(removeBtn);
        pubkeyListEl.appendChild(item);
      }
    } catch (err) {
      pubkeyListEl.innerHTML =
        '<div class="empty-state">Could not load public keys.</div>';
    }
  }

  /**
   * Show inline verification flow for a contact's public key.
   * Users compare fingerprints out-of-band (Signal, phone, etc.).
   */
  function verifyContactKey(email, publicKey) {
    const fp = generateFingerprint(publicKey);

    // Remove existing verify section if any
    const existing = pubkeyListEl.querySelector(".verify-section");
    if (existing) existing.remove();

    const section = document.createElement("div");
    section.className = "verify-section";
    section.innerHTML =
      '<strong>Verify ' + escapeHtml(email) + '</strong>' +
      '<p style="margin:4px 0;font-size:11px;color:#5f6368;">' +
      'Compare this fingerprint with your contact (via Signal, phone, etc.):</p>' +
      '<div class="fingerprint">' + escapeHtml(fp) + '</div>' +
      '<div style="display:flex;gap:4px;margin-top:8px;">' +
      '<button class="btn btn-small" id="verifyConfirmBtn">✅ Fingerprints Match</button>' +
      '<button class="btn btn-small btn-secondary" id="verifyCancelBtn">Cancel</button>' +
      '</div>';

    pubkeyListEl.appendChild(section);

    section.querySelector("#verifyConfirmBtn").addEventListener("click", async () => {
      await KeyStore.setContactVerified(email, fp);
      showStatus(securityStatusEl, `${email} verified!`);
      section.remove();
      loadPublicKeys();
      renderKeys(keySearchInput.value);
    });

    section.querySelector("#verifyCancelBtn").addEventListener("click", () => {
      section.remove();
    });
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
      renderKeys(keySearchInput.value);
    } catch (err) {
      showStatus(securityStatusEl, "Error: " + err.message, true);
    }
  });

  /* ======================================================
   *  SECURITY: FILE ENCRYPT / DECRYPT
   * ====================================================== */

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
            buffer, file.name, file.type, passphrase
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
        showStatus(securityStatusEl, "No passphrase stored for " + contact + ".", true);
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

          showStatus(securityStatusEl, "File decrypted: " + result.filename);
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

  /* ======================================================
   *  MASTER PASSWORD UNLOCK FLOW
   * ====================================================== */

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
    await checkBiometricBadge();
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

  lockBadge.addEventListener("click", async () => {
    try {
      const unlocked = await KeyStore.isUnlocked();
      if (unlocked) {
        await KeyStore.lock();
        showMasterLock();
      }
    } catch {
      showMasterLock();
    }
  });

  /* ======================================================
   *  STARTUP
   * ====================================================== */

  async function init() {
    try {
      // Check if onboarding is needed
      const onboardingDone = await KeyStore.isOnboardingDone();
      const hasMaster = await KeyStore.hasMasterPassword();

      if (!onboardingDone && !hasMaster) {
        // First-time user → show onboarding wizard
        showOnboarding();
        return;
      }

      // Existing user → show app
      hideOnboarding();
      await checkBiometricBadge();

      const unlocked = await KeyStore.isUnlocked();
      if (unlocked) {
        masterLock.style.display = "none";
        mainContent.style.display = "block";
        lockBadge.textContent = "🔓";
        renderKeys();
        loadSettings();
      } else {
        showMasterLock();

        // Auto-trigger biometric if available
        const webauthnData = await KeyStore.getWebAuthnData();
        if (webauthnData && window.PublicKeyCredential) {
          // Small delay so the popup renders first
          setTimeout(async () => {
            const ok = await authenticateBiometric();
            if (ok) {
              masterLock.style.display = "none";
              mainContent.style.display = "block";
              lockBadge.textContent = "🔓";
              renderKeys();
              loadSettings();
            }
          }, 300);
        }
      }
    } catch {
      hideOnboarding();
      showMasterLock();
    }
  }

  init();
})();
