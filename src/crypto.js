/**
 * CryptMail – AES-256-GCM Encryption Module
 *
 * Single-round AES-256-GCM encryption with PBKDF2 key derivation.
 * Also supports ECDH hybrid encryption and file encryption.
 *
 * Envelope wire format (base64-encoded JSON):
 *   v1 (symmetric): { "v":1, "rounds":1, "params":[{"salt":"<hex>","iv":"<hex>"}], "data":"<hex>" }
 *   v2 (ECDH):      { "v":2, "mode":"ecdh", "senderPublicKey":"<b64>", "iv":"<hex>", "data":"<hex>" }
 */

/* exported CryptMail */
const CryptMail = (() => {
  "use strict";

  const ALGO = "AES-GCM";
  const KEY_LENGTH = 256;
  const PBKDF2_ITERATIONS = 1000000;
  const SALT_BYTES = 32;
  const ENVELOPE_PREFIX = "-----BEGIN CRYPTMAIL-----";
  const ENVELOPE_SUFFIX = "-----END CRYPTMAIL-----";
  const SUBJECT_PREFIX = "[CM]";

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

  /** UTF-8 safe string → base64 (replaces deprecated unescape/escape) */
  function utf8ToBase64(str) {
    const bytes = textToBytes(str);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /** Base64 → UTF-8 string */
  function base64ToUtf8(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytesToText(bytes);
  }

  /** Binary Uint8Array → base64 */
  function uint8ToBase64(uint8) {
    let binary = "";
    for (let i = 0; i < uint8.length; i++) {
      binary += String.fromCharCode(uint8[i]);
    }
    return btoa(binary);
  }

  /** Base64 → Uint8Array */
  function base64ToUint8(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
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
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      raw,
      { name: ALGO, length: KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /* ---- Symmetric AES-256-GCM encryption (single round) ---- */

  /**
   * Encrypt plaintext with passphrase.
   *
   * Supports multiple call signatures for backward compatibility:
   *   encrypt(plaintext, passphrase)
   *   encrypt(plaintext, passphrase, onProgress)
   *   encrypt(plaintext, passphrase, rounds, onProgress)  ← rounds ignored
   *   encrypt(plaintext, passphrase, { onProgress, senderPublicKey, encryptedSubject })
   */
  async function encrypt(plaintext, passphrase, thirdArg, fourthArg) {
    if (!plaintext || !passphrase) {
      throw new Error("plaintext and passphrase are required");
    }

    let onProgress = null;
    let options = {};

    if (typeof thirdArg === "number") {
      // Legacy: encrypt(text, pass, rounds, onProgress) – rounds ignored
      onProgress = typeof fourthArg === "function" ? fourthArg : null;
    } else if (typeof thirdArg === "function") {
      // Legacy: encrypt(text, pass, onProgress)
      onProgress = thirdArg;
    } else if (thirdArg && typeof thirdArg === "object") {
      options = thirdArg;
      onProgress = options.onProgress || null;
    }

    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(12);
    const key = await deriveKey(passphrase, salt);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: ALGO, iv }, key, textToBytes(plaintext))
    );

    if (onProgress) onProgress(100);

    const envelope = {
      v: 1,
      rounds: 1,
      params: [{ salt: hexEncode(salt), iv: hexEncode(iv) }],
      data: hexEncode(ciphertext),
    };

    // Optional metadata
    if (options.senderPublicKey) envelope.senderPublicKey = options.senderPublicKey;
    if (options.encryptedSubject) envelope.encryptedSubject = options.encryptedSubject;

    return `${ENVELOPE_PREFIX}\n${utf8ToBase64(JSON.stringify(envelope))}\n${ENVELOPE_SUFFIX}`;
  }

  /**
   * Decrypt an armored envelope. Backward-compatible with multi-round envelopes.
   */
  async function decrypt(armored, passphrase, onProgress) {
    if (!armored || !passphrase) {
      throw new Error("armored text and passphrase are required");
    }

    const b64 = armored
      .replace(ENVELOPE_PREFIX, "")
      .replace(ENVELOPE_SUFFIX, "")
      .trim();
    const envelope = JSON.parse(base64ToUtf8(b64));

    if (envelope.v === 2 && envelope.mode === "ecdh") {
      throw new Error("ECDH envelope requires hybrid decryption via background service.");
    }
    if (envelope.v !== 1) {
      throw new Error("Unsupported envelope version: " + envelope.v);
    }

    let current = hexDecode(envelope.data);
    const total = envelope.params.length;

    // Backward-compatible: peel layers outermost → innermost
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

  /**
   * Extract metadata from an armored envelope without decrypting.
   */
  function getEnvelopeInfo(armored) {
    try {
      const b64 = armored
        .replace(ENVELOPE_PREFIX, "")
        .replace(ENVELOPE_SUFFIX, "")
        .trim();
      const envelope = JSON.parse(base64ToUtf8(b64));
      return {
        version: envelope.v,
        rounds: envelope.rounds || 1,
        mode: envelope.mode || "passphrase",
        senderPublicKey: envelope.senderPublicKey || null,
        hasEncryptedSubject: !!envelope.encryptedSubject,
        encryptedSubject: envelope.encryptedSubject || null,
      };
    } catch {
      return null;
    }
  }

  /* ---- Compact subject encryption ---- */

  /**
   * Encrypt a short subject line.
   * Format: [CM]<base64(salt‖iv‖ciphertext)>
   */
  async function encryptSubject(plaintext, passphrase) {
    if (!plaintext || !passphrase) {
      throw new Error("plaintext and passphrase are required");
    }
    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(12);
    const key = await deriveKey(passphrase, salt);
    const cipherBuf = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: ALGO, iv },
        key,
        textToBytes(plaintext)
      )
    );
    const packed = new Uint8Array(salt.length + iv.length + cipherBuf.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(cipherBuf, salt.length + iv.length);
    return SUBJECT_PREFIX + uint8ToBase64(packed);
  }

  /**
   * Decrypt a compact subject token.
   */
  async function decryptSubject(token, passphrase) {
    if (!token || !passphrase) {
      throw new Error("token and passphrase are required");
    }
    let b64 = token;
    if (b64.startsWith(SUBJECT_PREFIX)) b64 = b64.slice(SUBJECT_PREFIX.length);
    // Strip any whitespace or leading emoji that might be prepended
    b64 = b64.trim();

    const packed = base64ToUint8(b64);
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
    return typeof text === "string" && text.includes(SUBJECT_PREFIX);
  }

  /* ---- ECDH Key Pair Generation ---- */

  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
    const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return {
      publicKey: uint8ToBase64(new Uint8Array(publicKeyRaw)),
      privateKey: JSON.stringify(privateKeyJwk),
    };
  }

  /* ---- File Encryption ---- */

  /**
   * Encrypt a file (ArrayBuffer) with a passphrase.
   * Returns a JSON string containing the encrypted file envelope.
   */
  async function encryptFile(arrayBuffer, filename, mimeType, passphrase, onProgress) {
    if (!arrayBuffer || !passphrase) {
      throw new Error("file data and passphrase are required");
    }
    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(12);
    const key = await deriveKey(passphrase, salt);
    const data = new Uint8Array(arrayBuffer);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: ALGO, iv }, key, data)
    );

    if (onProgress) onProgress(100);

    return JSON.stringify({
      v: 1,
      type: "file",
      filename: filename || "unknown",
      mimeType: mimeType || "application/octet-stream",
      salt: hexEncode(salt),
      iv: hexEncode(iv),
      data: uint8ToBase64(ciphertext),
    });
  }

  /**
   * Decrypt a CryptMail file envelope.
   * Returns { data: ArrayBuffer, filename: string, mimeType: string }.
   */
  async function decryptFile(jsonString, passphrase, onProgress) {
    if (!jsonString || !passphrase) {
      throw new Error("encrypted file data and passphrase are required");
    }
    const envelope = JSON.parse(jsonString);
    if (envelope.type !== "file") {
      throw new Error("Not a CryptMail file envelope");
    }
    const salt = hexDecode(envelope.salt);
    const iv = hexDecode(envelope.iv);
    const ciphertext = base64ToUint8(envelope.data);
    const key = await deriveKey(passphrase, salt);
    const plainBuf = await crypto.subtle.decrypt(
      { name: ALGO, iv },
      key,
      ciphertext
    );

    if (onProgress) onProgress(100);

    return {
      data: plainBuf,
      filename: envelope.filename,
      mimeType: envelope.mimeType,
    };
  }

  /* ---- Public API ---- */

  return {
    encrypt,
    decrypt,
    isEncrypted,
    getEnvelopeInfo,
    encryptSubject,
    decryptSubject,
    isSubjectEncrypted,
    generateKeyPair,
    encryptFile,
    decryptFile,
    uint8ToBase64,
    base64ToUint8,
    ENVELOPE_PREFIX,
    ENVELOPE_SUFFIX,
    SUBJECT_PREFIX,
  };
})();

// Node.js / test compatibility
if (typeof module !== "undefined" && module.exports) {
  module.exports = CryptMail;
}

// Service worker compatibility
if (typeof self !== "undefined") {
  try {
    self.CryptMail = CryptMail;
  } catch {
    /* ignore in strict contexts */
  }
}
