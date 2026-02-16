/**
 * CryptMail – Background Service Worker (MV3)
 *
 * Central hub for:
 * - Master password management (persisted via chrome.storage.session)
 * - KeyStore operations (per-contact passphrases encrypted at rest)
 * - Settings management
 * - ECDH key pair management
 */

(() => {
  "use strict";

  /* ---- Constants ---- */
  const STORAGE_KEY = "cryptmail_keys";
  const MASTER_CHECK_KEY = "cryptmail_master_check";
  const MASTER_CHECK_TOKEN = "CRYPTMAIL_OK";
  const SETTINGS_KEY = "cryptmail_settings";
  const KEYPAIR_KEY = "cryptmail_keypair";
  const PUBLIC_KEYS_KEY = "cryptmail_public_keys";
  const PBKDF2_ITERATIONS = 800000;
  const STORAGE_SALT_BYTES = 16;
  const SESSION_PW_KEY = "cryptmail_master_pw";

  let _masterPassword = null;

  const DEFAULT_SETTINGS = {
    stealthMode: false,
    stealthSubjects: [
      "Hi",
      "Re: Follow-up",
      "Regarding our conversation",
      "Quick update",
      "FYI",
      "Reminder",
    ],
    autoDecrypt: false,
    showStatusIndicator: true,
    encryptSubjectByDefault: false,
  };

  /* ---- Crypto Helpers ---- */

  function textToBytes(text) {
    return new TextEncoder().encode(text);
  }

  function bytesToText(buf) {
    return new TextDecoder().decode(buf);
  }

  function uint8ToBase64(uint8) {
    let binary = "";
    for (let i = 0; i < uint8.length; i++) {
      binary += String.fromCharCode(uint8[i]);
    }
    return btoa(binary);
  }

  function base64ToUint8(b64) {
    const binary = atob(b64);
    const uint8 = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      uint8[i] = binary.charCodeAt(i);
    }
    return uint8;
  }

  async function deriveStorageKey(password, salt) {
    const raw = await crypto.subtle.importKey(
      "raw",
      textToBytes(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** Encrypt plaintext → base64(salt‖iv‖ciphertext) using UTF-8 safe encoding. */
  async function encryptValue(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(STORAGE_SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveStorageKey(password, salt);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        textToBytes(plaintext)
      )
    );
    const packed = new Uint8Array(salt.length + iv.length + ct.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(ct, salt.length + iv.length);
    return uint8ToBase64(packed);
  }

  /** Decrypt base64 token → plaintext using UTF-8 safe decoding. */
  async function decryptValue(token, password) {
    const packed = base64ToUint8(token);
    const salt = packed.slice(0, STORAGE_SALT_BYTES);
    const iv = packed.slice(STORAGE_SALT_BYTES, STORAGE_SALT_BYTES + 12);
    const ct = packed.slice(STORAGE_SALT_BYTES + 12);
    const key = await deriveStorageKey(password, salt);
    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
    );
    return bytesToText(plain);
  }

  /* ---- ECDH Key Pair Management ---- */

  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
    const publicKeyRaw = await crypto.subtle.exportKey(
      "raw",
      keyPair.publicKey
    );
    const privateKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey
    );
    return {
      publicKey: uint8ToBase64(new Uint8Array(publicKeyRaw)),
      privateKey: JSON.stringify(privateKeyJwk),
    };
  }

  async function storeKeyPair(keyPair) {
    if (!_masterPassword) throw new Error("Store is locked");
    const encPrivate = await encryptValue(keyPair.privateKey, _masterPassword);
    await chrome.storage.local.set({
      [KEYPAIR_KEY]: { publicKey: keyPair.publicKey, privateKey: encPrivate },
    });
  }

  async function loadKeyPair() {
    const result = await chrome.storage.local.get(KEYPAIR_KEY);
    const stored = result[KEYPAIR_KEY];
    if (!stored) return null;
    if (!_masterPassword)
      return { publicKey: stored.publicKey, privateKey: null };
    try {
      const privateKey = await decryptValue(stored.privateKey, _masterPassword);
      return { publicKey: stored.publicKey, privateKey };
    } catch {
      return { publicKey: stored.publicKey, privateKey: null };
    }
  }

  async function storeContactPublicKey(email, publicKey) {
    const result = await chrome.storage.local.get(PUBLIC_KEYS_KEY);
    const keys = result[PUBLIC_KEYS_KEY] || {};
    keys[email.toLowerCase()] = publicKey;
    await chrome.storage.local.set({ [PUBLIC_KEYS_KEY]: keys });
  }

  async function getContactPublicKey(email) {
    const result = await chrome.storage.local.get(PUBLIC_KEYS_KEY);
    const keys = result[PUBLIC_KEYS_KEY] || {};
    return keys[email.toLowerCase()] || null;
  }

  async function listContactPublicKeys() {
    const result = await chrome.storage.local.get(PUBLIC_KEYS_KEY);
    return result[PUBLIC_KEYS_KEY] || {};
  }

  /* ---- Storage I/O ---- */

  async function loadAllKeys() {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    return result[STORAGE_KEY] || {};
  }

  async function saveAllKeys(keys) {
    await chrome.storage.local.set({ [STORAGE_KEY]: keys });
  }

  /* ---- Master Password ---- */

  async function hasMasterPassword() {
    const result = await chrome.storage.local.get(MASTER_CHECK_KEY);
    return !!result[MASTER_CHECK_KEY];
  }

  async function initMasterPassword(password) {
    const token = await encryptValue(MASTER_CHECK_TOKEN, password);
    await chrome.storage.local.set({ [MASTER_CHECK_KEY]: token });
    _masterPassword = password;
    try {
      await chrome.storage.session.set({ [SESSION_PW_KEY]: password });
    } catch {
      /* session storage may not be available */
    }
  }

  async function unlock(password) {
    const result = await chrome.storage.local.get(MASTER_CHECK_KEY);
    const stored = result[MASTER_CHECK_KEY];
    if (!stored) {
      await initMasterPassword(password);
      return true;
    }
    try {
      const plain = await decryptValue(stored, password);
      if (plain === MASTER_CHECK_TOKEN) {
        _masterPassword = password;
        try {
          await chrome.storage.session.set({ [SESSION_PW_KEY]: password });
        } catch {
          /* ignore */
        }
        updateBadge();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  function isUnlocked() {
    return _masterPassword !== null;
  }

  function lock() {
    _masterPassword = null;
    try {
      chrome.storage.session.remove(SESSION_PW_KEY);
    } catch {
      /* ignore */
    }
    updateBadge();
  }

  /* ---- Restore master password from session on SW restart ---- */

  async function restoreFromSession() {
    try {
      const result = await chrome.storage.session.get(SESSION_PW_KEY);
      if (result[SESSION_PW_KEY]) {
        _masterPassword = result[SESSION_PW_KEY];
        return true;
      }
    } catch {
      /* session storage not available */
    }
    return false;
  }

  /* ---- Key Operations ---- */

  async function getKey(email) {
    const keys = await loadAllKeys();
    const encrypted = keys[email.toLowerCase()];
    if (!encrypted || !_masterPassword) return null;
    try {
      return await decryptValue(encrypted, _masterPassword);
    } catch {
      return null;
    }
  }

  async function setKey(email, passphrase) {
    if (!_masterPassword) throw new Error("Store is locked");
    const keys = await loadAllKeys();
    keys[email.toLowerCase()] = await encryptValue(
      passphrase,
      _masterPassword
    );
    await saveAllKeys(keys);
  }

  async function removeKey(email) {
    const keys = await loadAllKeys();
    delete keys[email.toLowerCase()];
    await saveAllKeys(keys);
  }

  async function listKeys() {
    const keys = await loadAllKeys();
    if (!_masterPassword) return {};
    const decrypted = {};
    for (const [email, enc] of Object.entries(keys)) {
      try {
        decrypted[email] = await decryptValue(enc, _masterPassword);
      } catch {
        /* Skip entries that fail */
      }
    }
    return decrypted;
  }

  /* ---- Settings ---- */

  async function getSettings() {
    const result = await chrome.storage.local.get(SETTINGS_KEY);
    return { ...DEFAULT_SETTINGS, ...(result[SETTINGS_KEY] || {}) };
  }

  async function saveSettings(settings) {
    const current = await getSettings();
    const merged = { ...current, ...settings };
    await chrome.storage.local.set({ [SETTINGS_KEY]: merged });
    return merged;
  }

  /* ---- ECDH Hybrid Encryption (run in service worker) ---- */

  async function hybridEncryptInBackground(plaintext, recipientEmail) {
    const keyPair = await loadKeyPair();
    if (!keyPair || !keyPair.privateKey) {
      throw new Error("No ECDH key pair available. Generate one first.");
    }
    const recipientPubKey = await getContactPublicKey(recipientEmail);
    if (!recipientPubKey) {
      throw new Error(
        "No public key for " + recipientEmail + ". Use passphrase encryption."
      );
    }

    // Import keys and derive shared secret
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(keyPair.privateKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );
    const publicKey = await crypto.subtle.importKey(
      "raw",
      base64ToUint8(recipientPubKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const sharedKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        sharedKey,
        textToBytes(plaintext)
      )
    );

    const hexEncode = (buf) =>
      Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const envelope = {
      v: 2,
      mode: "ecdh",
      senderPublicKey: keyPair.publicKey,
      iv: hexEncode(iv),
      data: hexEncode(ciphertext),
    };

    const json = JSON.stringify(envelope);
    const b64Envelope = uint8ToBase64(textToBytes(json));
    return (
      "-----BEGIN CRYPTMAIL-----\n" +
      b64Envelope +
      "\n-----END CRYPTMAIL-----"
    );
  }

  async function hybridDecryptInBackground(armored) {
    const keyPair = await loadKeyPair();
    if (!keyPair || !keyPair.privateKey) {
      throw new Error("No ECDH key pair available.");
    }

    const prefix = "-----BEGIN CRYPTMAIL-----";
    const suffix = "-----END CRYPTMAIL-----";
    const b64 = armored.replace(prefix, "").replace(suffix, "").trim();
    const json = bytesToText(base64ToUint8(b64));
    const envelope = JSON.parse(json);

    if (envelope.v !== 2 || envelope.mode !== "ecdh") {
      throw new Error("Not an ECDH envelope");
    }

    const hexDecode = (hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
      }
      return bytes;
    };

    const privateKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(keyPair.privateKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );
    const senderPublicKey = await crypto.subtle.importKey(
      "raw",
      base64ToUint8(envelope.senderPublicKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const sharedKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: senderPublicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const iv = hexDecode(envelope.iv);
    const ciphertext = hexDecode(envelope.data);
    const plainBuf = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, sharedKey, ciphertext)
    );
    return bytesToText(plainBuf);
  }

  /* ---- Badge / Status Indicator ---- */

  function updateBadge() {
    try {
      const color = isUnlocked() ? "#4caf50" : "#9e9e9e";
      chrome.action.setBadgeBackgroundColor({ color });
      chrome.action.setBadgeText({ text: isUnlocked() ? "✓" : "" });
    } catch {
      /* badge API might not be available */
    }
  }

  /* ---- Message Handler ---- */

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    handleMessage(msg)
      .then(sendResponse)
      .catch((err) => {
        sendResponse({ error: err.message });
      });
    return true; // will respond asynchronously
  });

  async function handleMessage(msg) {
    switch (msg.type) {
      case "IS_UNLOCKED":
        return { unlocked: isUnlocked() };

      case "HAS_MASTER_PASSWORD":
        return { exists: await hasMasterPassword() };

      case "UNLOCK":
        return { success: await unlock(msg.password) };

      case "LOCK":
        lock();
        return { success: true };

      case "GET_KEY":
        return { passphrase: await getKey(msg.email) };

      case "SET_KEY":
        await setKey(msg.email, msg.passphrase);
        return { success: true };

      case "REMOVE_KEY":
        await removeKey(msg.email);
        return { success: true };

      case "LIST_KEYS":
        return { keys: await listKeys() };

      case "GET_SETTINGS":
        return { settings: await getSettings() };

      case "SAVE_SETTINGS":
        return { settings: await saveSettings(msg.settings) };

      case "GENERATE_KEYPAIR": {
        const kp = await generateKeyPair();
        await storeKeyPair(kp);
        return { publicKey: kp.publicKey };
      }

      case "GET_KEYPAIR":
        return { keyPair: await loadKeyPair() };

      case "STORE_CONTACT_PUBLIC_KEY":
        await storeContactPublicKey(msg.email, msg.publicKey);
        return { success: true };

      case "GET_CONTACT_PUBLIC_KEY":
        return { publicKey: await getContactPublicKey(msg.email) };

      case "LIST_CONTACT_PUBLIC_KEYS":
        return { keys: await listContactPublicKeys() };

      case "HYBRID_ENCRYPT":
        return {
          armored: await hybridEncryptInBackground(
            msg.plaintext,
            msg.recipientEmail
          ),
        };

      case "HYBRID_DECRYPT":
        return {
          plaintext: await hybridDecryptInBackground(msg.armored),
        };

      default:
        return { error: "Unknown message type: " + msg.type };
    }
  }

  /* ---- Startup ---- */

  restoreFromSession().then(() => {
    updateBadge();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[SESSION_PW_KEY]) {
      updateBadge();
    }
  });
})();
