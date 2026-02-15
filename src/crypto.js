/**
 * CryptMail - Multi-layer AES-GCM encryption module.
 *
 * Encrypts plaintext multiple rounds using AES-256-GCM with a key derived
 * from a shared passphrase via PBKDF2.  Each round uses a fresh random IV
 * and salt so that identical plaintexts produce different ciphertexts.
 *
 * Wire format (base64-encoded JSON):
 *   { "v":1, "rounds":<n>, "params":[ { "salt":<hex>, "iv":<hex> }, … ], "data":<hex> }
 *
 * params[0] belongs to the innermost round, params[rounds-1] to the outermost.
 * "data" is the final ciphertext after all rounds.
 */

/* exported CryptMail */
const CryptMail = (() => {
  "use strict";

  const ALGO = "AES-GCM";
  const KEY_LENGTH = 256;
  const PBKDF2_ITERATIONS = 600000;
  const DEFAULT_ROUNDS = 100;
  const ENVELOPE_PREFIX = "-----BEGIN CRYPTMAIL-----";
  const ENVELOPE_SUFFIX = "-----END CRYPTMAIL-----";

  /* ---- helpers ---- */

  function randomBytes(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  }

  function hexEncode(buf) {
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexDecode(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  function textToBytes(text) {
    return new TextEncoder().encode(text);
  }

  function bytesToText(buf) {
    return new TextDecoder().decode(buf);
  }

  /* ---- key derivation ---- */

  async function deriveKey(passphrase, salt) {
    const raw = await crypto.subtle.importKey(
      "raw",
      textToBytes(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      raw,
      { name: ALGO, length: KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /* ---- public API ---- */

  /**
   * Encrypt `plaintext` with `passphrase` for `rounds` layers.
   * Returns the armored envelope string.
   */
  async function encrypt(plaintext, passphrase, rounds) {
    if (!plaintext || !passphrase) {
      throw new Error("plaintext and passphrase are required");
    }
    rounds = rounds || DEFAULT_ROUNDS;

    let current = textToBytes(plaintext);
    const params = [];

    for (let i = 0; i < rounds; i++) {
      const salt = randomBytes(16);
      const iv = randomBytes(12);
      const key = await deriveKey(passphrase, salt);
      current = new Uint8Array(
        await crypto.subtle.encrypt({ name: ALGO, iv }, key, current)
      );
      params.push({ salt: hexEncode(salt), iv: hexEncode(iv) });
    }

    const envelope = {
      v: 1,
      rounds,
      params,
      data: hexEncode(current),
    };

    const json = JSON.stringify(envelope);
    const b64 = btoa(unescape(encodeURIComponent(json)));
    return `${ENVELOPE_PREFIX}\n${b64}\n${ENVELOPE_SUFFIX}`;
  }

  /**
   * Decrypt an armored envelope string with `passphrase`.
   * Returns the original plaintext.
   */
  async function decrypt(armored, passphrase) {
    if (!armored || !passphrase) {
      throw new Error("armored text and passphrase are required");
    }

    const b64 = armored
      .replace(ENVELOPE_PREFIX, "")
      .replace(ENVELOPE_SUFFIX, "")
      .trim();
    const json = decodeURIComponent(escape(atob(b64)));
    const envelope = JSON.parse(json);

    if (envelope.v !== 1) {
      throw new Error("Unsupported envelope version: " + envelope.v);
    }

    let current = hexDecode(envelope.data);

    // Peel layers from outermost (last param) to innermost (first param)
    for (let i = envelope.params.length - 1; i >= 0; i--) {
      const p = envelope.params[i];
      const salt = hexDecode(p.salt);
      const iv = hexDecode(p.iv);
      const key = await deriveKey(passphrase, salt);
      current = new Uint8Array(
        await crypto.subtle.decrypt({ name: ALGO, iv }, key, current)
      );
    }

    return bytesToText(current);
  }

  /**
   * Check whether a string looks like a CryptMail envelope.
   */
  function isEncrypted(text) {
    return (
      typeof text === "string" &&
      text.includes(ENVELOPE_PREFIX) &&
      text.includes(ENVELOPE_SUFFIX)
    );
  }

  return {
    encrypt,
    decrypt,
    isEncrypted,
    ENVELOPE_PREFIX,
    ENVELOPE_SUFFIX,
    DEFAULT_ROUNDS,
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = CryptMail;
}
