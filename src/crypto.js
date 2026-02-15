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
  const PBKDF2_ITERATIONS = 1000000;
  const DEFAULT_ROUNDS = 1;
  const SALT_BYTES = 32;
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
   * @param {function} [onProgress] – optional callback(percent) called after each round.
   */
  async function encrypt(plaintext, passphrase, rounds, onProgress) {
    if (!plaintext || !passphrase) {
      throw new Error("plaintext and passphrase are required");
    }
    rounds = rounds || DEFAULT_ROUNDS;

    let current = textToBytes(plaintext);
    const params = [];

    for (let i = 0; i < rounds; i++) {
      const salt = randomBytes(SALT_BYTES);
      const iv = randomBytes(12);
      const key = await deriveKey(passphrase, salt);
      current = new Uint8Array(
        await crypto.subtle.encrypt({ name: ALGO, iv }, key, current)
      );
      params.push({ salt: hexEncode(salt), iv: hexEncode(iv) });
      if (onProgress) onProgress(Math.round(((i + 1) / rounds) * 100));
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
   * @param {function} [onProgress] – optional callback(percent) called after each round.
   */
  async function decrypt(armored, passphrase, onProgress) {
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
    const total = envelope.params.length;

    // Peel layers from outermost (last param) to innermost (first param)
    for (let i = envelope.params.length - 1; i >= 0; i--) {
      const p = envelope.params[i];
      const salt = hexDecode(p.salt);
      const iv = hexDecode(p.iv);
      const key = await deriveKey(passphrase, salt);
      current = new Uint8Array(
        await crypto.subtle.decrypt({ name: ALGO, iv }, key, current)
      );
      if (onProgress) onProgress(Math.round(((total - i) / total) * 100));
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

  /* ---- Compact subject encryption ---- */

  const SUBJECT_PREFIX = "[CM]";

  /**
   * Encrypt a short subject line into a compact token.
   * Format: [CM]<base64(salt‖iv‖ciphertext)>
   * Uses a single round with the same AES-256-GCM + PBKDF2 key derivation.
   */
  async function encryptSubject(plaintext, passphrase) {
    if (!plaintext || !passphrase) {
      throw new Error("plaintext and passphrase are required");
    }
    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(12);
    const key = await deriveKey(passphrase, salt);
    const cipherBuf = new Uint8Array(
      await crypto.subtle.encrypt({ name: ALGO, iv }, key, textToBytes(plaintext))
    );
    // Pack salt(32) + iv(12) + ciphertext into one buffer
    const packed = new Uint8Array(salt.length + iv.length + cipherBuf.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(cipherBuf, salt.length + iv.length);
    const b64 = btoa(String.fromCharCode(...packed));
    return SUBJECT_PREFIX + b64;
  }

  /**
   * Decrypt a compact subject token back to the original subject.
   */
  async function decryptSubject(token, passphrase) {
    if (!token || !passphrase) {
      throw new Error("token and passphrase are required");
    }
    const b64 = token.startsWith(SUBJECT_PREFIX)
      ? token.slice(SUBJECT_PREFIX.length)
      : token;
    const raw = atob(b64);
    const packed = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) packed[i] = raw.charCodeAt(i);

    const salt = packed.slice(0, SALT_BYTES);
    const iv = packed.slice(SALT_BYTES, SALT_BYTES + 12);
    const ciphertext = packed.slice(SALT_BYTES + 12);

    const key = await deriveKey(passphrase, salt);
    const plainBuf = new Uint8Array(
      await crypto.subtle.decrypt({ name: ALGO, iv }, key, ciphertext)
    );
    return bytesToText(plainBuf);
  }

  /**
   * Check whether a string looks like a CryptMail encrypted subject.
   */
  function isSubjectEncrypted(text) {
    return typeof text === "string" && text.startsWith(SUBJECT_PREFIX);
  }

  return {
    encrypt,
    decrypt,
    isEncrypted,
    encryptSubject,
    decryptSubject,
    isSubjectEncrypted,
    ENVELOPE_PREFIX,
    ENVELOPE_SUFFIX,
    SUBJECT_PREFIX,
    DEFAULT_ROUNDS,
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = CryptMail;
}
