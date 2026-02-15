/**
 * CryptMail – Key Store
 *
 * Persists per-contact passphrases in chrome.storage.local.
 * All passphrases are encrypted at rest using AES-256-GCM with a key derived
 * from the user's master password via PBKDF2.
 *
 * Storage schema:
 *   {
 *     "cryptmail_keys": { "alice@example.com": "<base64(salt‖iv‖ciphertext)>", … },
 *     "cryptmail_master_check": "<base64(salt‖iv‖ciphertext)>"   // encrypted known token
 *   }
 *
 * The master password is kept only in memory for the lifetime of the page.
 */

/* exported KeyStore */
const KeyStore = (() => {
  "use strict";

  const STORAGE_KEY = "cryptmail_keys";
  const MASTER_CHECK_KEY = "cryptmail_master_check";
  const MASTER_CHECK_TOKEN = "CRYPTMAIL_OK";
  const PBKDF2_ITERATIONS = 600000;

  /** The master password lives only in memory. */
  let _masterPassword = null;

  function getStorage() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      return chrome.storage.local;
    }
    return null;
  }

  /* ---- crypto helpers (AES-GCM for at-rest encryption) ---- */

  function textToBytes(text) {
    return new TextEncoder().encode(text);
  }

  function bytesToText(buf) {
    return new TextDecoder().decode(buf);
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

  /** Encrypt `plaintext` with `password`. Returns base64 string of salt‖iv‖ciphertext. */
  async function encryptValue(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveStorageKey(password, salt);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textToBytes(plaintext))
    );
    const packed = new Uint8Array(salt.length + iv.length + ct.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(ct, salt.length + iv.length);
    return btoa(String.fromCharCode(...packed));
  }

  /** Decrypt a base64 `token` with `password`. Returns plaintext string. */
  async function decryptValue(token, password) {
    const raw = atob(token);
    const packed = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) packed[i] = raw.charCodeAt(i);
    const salt = packed.slice(0, 16);
    const iv = packed.slice(16, 28);
    const ct = packed.slice(28);
    const key = await deriveStorageKey(password, salt);
    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
    );
    return bytesToText(plain);
  }

  /* ---- storage I/O ---- */

  async function loadAll() {
    const storage = getStorage();
    if (!storage) return {};
    return new Promise((resolve) => {
      storage.get(STORAGE_KEY, (result) => {
        resolve(result[STORAGE_KEY] || {});
      });
    });
  }

  async function saveAll(keys) {
    const storage = getStorage();
    if (!storage) return;
    return new Promise((resolve) => {
      storage.set({ [STORAGE_KEY]: keys }, resolve);
    });
  }

  /* ---- master password management ---- */

  /**
   * Check whether a master password has been set (i.e. the check token exists).
   */
  async function hasMasterPassword() {
    const storage = getStorage();
    if (!storage) return false;
    return new Promise((resolve) => {
      storage.get(MASTER_CHECK_KEY, (result) => {
        resolve(!!result[MASTER_CHECK_KEY]);
      });
    });
  }

  /**
   * Initialise a new master password. Stores an encrypted check token.
   * Must be called once before any keys are saved.
   */
  async function initMasterPassword(password) {
    const token = await encryptValue(MASTER_CHECK_TOKEN, password);
    const storage = getStorage();
    if (storage) {
      await new Promise((resolve) => {
        storage.set({ [MASTER_CHECK_KEY]: token }, resolve);
      });
    }
    _masterPassword = password;
  }

  /**
   * Unlock the store by verifying the master password against the check token.
   * Returns true on success, false on wrong password.
   */
  async function unlock(password) {
    const storage = getStorage();
    if (!storage) { _masterPassword = password; return true; }
    const stored = await new Promise((resolve) => {
      storage.get(MASTER_CHECK_KEY, (result) => {
        resolve(result[MASTER_CHECK_KEY] || null);
      });
    });
    if (!stored) {
      // First time – initialise
      await initMasterPassword(password);
      return true;
    }
    try {
      const plain = await decryptValue(stored, password);
      if (plain === MASTER_CHECK_TOKEN) {
        _masterPassword = password;
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /** Returns true if the master password is currently in memory. */
  function isUnlocked() {
    return _masterPassword !== null;
  }

  /* ---- public key operations ---- */

  /** Get the passphrase stored for `email`. Returns null if none. */
  async function getKey(email) {
    const keys = await loadAll();
    const encrypted = keys[email.toLowerCase()];
    if (!encrypted) return null;
    if (!_masterPassword) return null;
    try {
      return await decryptValue(encrypted, _masterPassword);
    } catch {
      return null;
    }
  }

  /** Store a passphrase for `email`. */
  async function setKey(email, passphrase) {
    if (!_masterPassword) throw new Error("KeyStore is locked");
    const keys = await loadAll();
    keys[email.toLowerCase()] = await encryptValue(passphrase, _masterPassword);
    await saveAll(keys);
  }

  /** Remove the passphrase for `email`. */
  async function removeKey(email) {
    const keys = await loadAll();
    delete keys[email.toLowerCase()];
    await saveAll(keys);
  }

  /** Return all stored email→passphrase pairs (decrypted). */
  async function listKeys() {
    const keys = await loadAll();
    if (!_masterPassword) return {};
    const decrypted = {};
    for (const [email, enc] of Object.entries(keys)) {
      try {
        decrypted[email] = await decryptValue(enc, _masterPassword);
      } catch {
        // Skip entries that fail to decrypt
      }
    }
    return decrypted;
  }

  return {
    getKey,
    setKey,
    removeKey,
    listKeys,
    hasMasterPassword,
    initMasterPassword,
    unlock,
    isUnlocked,
    STORAGE_KEY,
    MASTER_CHECK_KEY,
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = KeyStore;
}
