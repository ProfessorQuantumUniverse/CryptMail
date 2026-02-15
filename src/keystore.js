/**
 * CryptMail – Key Store
 *
 * Persists per-contact passphrases in chrome.storage.local.
 * Storage schema:  { "cryptmail_keys": { "alice@example.com": "shared-secret", … } }
 */

/* exported KeyStore */
const KeyStore = (() => {
  "use strict";

  const STORAGE_KEY = "cryptmail_keys";

  function getStorage() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      return chrome.storage.local;
    }
    // Fallback for environments without chrome.storage (e.g. tests)
    return null;
  }

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

  /** Get the passphrase stored for `email`. Returns null if none. */
  async function getKey(email) {
    const keys = await loadAll();
    return keys[email.toLowerCase()] || null;
  }

  /** Store a passphrase for `email`. */
  async function setKey(email, passphrase) {
    const keys = await loadAll();
    keys[email.toLowerCase()] = passphrase;
    await saveAll(keys);
  }

  /** Remove the passphrase for `email`. */
  async function removeKey(email) {
    const keys = await loadAll();
    delete keys[email.toLowerCase()];
    await saveAll(keys);
  }

  /** Return all stored email→passphrase pairs. */
  async function listKeys() {
    return loadAll();
  }

  return { getKey, setKey, removeKey, listKeys, STORAGE_KEY };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = KeyStore;
}
