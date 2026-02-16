/**
 * CryptMail – KeyStore (Message-Passing Proxy)
 *
 * Thin async wrapper that routes all key/settings operations
 * to the background service worker via chrome.runtime.sendMessage.
 *
 * API is fully async – all methods return Promises.
 */

/* exported KeyStore */
const KeyStore = (() => {
  "use strict";

  async function sendMessage(msg) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(msg, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (response && response.error) {
            reject(new Error(response.error));
            return;
          }
          resolve(response);
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  /** Check if the KeyStore is currently unlocked. Returns Promise<boolean>. */
  async function isUnlocked() {
    const res = await sendMessage({ type: "IS_UNLOCKED" });
    return res.unlocked;
  }

  /** Check if a master password has been set. Returns Promise<boolean>. */
  async function hasMasterPassword() {
    const res = await sendMessage({ type: "HAS_MASTER_PASSWORD" });
    return res.exists;
  }

  /** Unlock the store with the given password. Returns Promise<boolean>. */
  async function unlock(password) {
    const res = await sendMessage({ type: "UNLOCK", password });
    return res.success;
  }

  /** Lock the store (clears master password from memory). */
  async function lock() {
    await sendMessage({ type: "LOCK" });
  }

  /** Get the passphrase stored for an email. Returns Promise<string|null>. */
  async function getKey(email) {
    const res = await sendMessage({ type: "GET_KEY", email });
    return res.passphrase;
  }

  /** Store a passphrase for an email. */
  async function setKey(email, passphrase) {
    await sendMessage({ type: "SET_KEY", email, passphrase });
  }

  /** Remove the passphrase for an email. */
  async function removeKey(email) {
    await sendMessage({ type: "REMOVE_KEY", email });
  }

  /** Return all stored email→passphrase pairs (decrypted). */
  async function listKeys() {
    const res = await sendMessage({ type: "LIST_KEYS" });
    return res.keys;
  }

  /** Get current settings. */
  async function getSettings() {
    const res = await sendMessage({ type: "GET_SETTINGS" });
    return res.settings;
  }

  /** Save settings (partial update, merged with existing). */
  async function saveSettings(settings) {
    const res = await sendMessage({ type: "SAVE_SETTINGS", settings });
    return res.settings;
  }

  /** Generate a new ECDH key pair. Returns the public key (base64). */
  async function generateKeyPair() {
    const res = await sendMessage({ type: "GENERATE_KEYPAIR" });
    return res.publicKey;
  }

  /** Get the stored ECDH key pair. */
  async function getKeyPair() {
    const res = await sendMessage({ type: "GET_KEYPAIR" });
    return res.keyPair;
  }

  /** Store a contact's public key. */
  async function storeContactPublicKey(email, publicKey) {
    await sendMessage({ type: "STORE_CONTACT_PUBLIC_KEY", email, publicKey });
  }

  /** Get a contact's public key. */
  async function getContactPublicKey(email) {
    const res = await sendMessage({ type: "GET_CONTACT_PUBLIC_KEY", email });
    return res.publicKey;
  }

  /** List all stored contact public keys. */
  async function listContactPublicKeys() {
    const res = await sendMessage({ type: "LIST_CONTACT_PUBLIC_KEYS" });
    return res.keys;
  }

  /** Request ECDH hybrid encryption from background. */
  async function hybridEncrypt(plaintext, recipientEmail) {
    const res = await sendMessage({
      type: "HYBRID_ENCRYPT",
      plaintext,
      recipientEmail,
    });
    return res.armored;
  }

  /** Request ECDH hybrid decryption from background. */
  async function hybridDecrypt(armored) {
    const res = await sendMessage({ type: "HYBRID_DECRYPT", armored });
    return res.plaintext;
  }

  return {
    isUnlocked,
    hasMasterPassword,
    unlock,
    lock,
    getKey,
    setKey,
    removeKey,
    listKeys,
    getSettings,
    saveSettings,
    generateKeyPair,
    getKeyPair,
    storeContactPublicKey,
    getContactPublicKey,
    listContactPublicKeys,
    hybridEncrypt,
    hybridDecrypt,
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = KeyStore;
}
