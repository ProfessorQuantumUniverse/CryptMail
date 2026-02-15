/**
 * CryptMail – Crypto module tests
 *
 * Runs with Node.js (no external test framework required).
 * Uses the Web Crypto API polyfill available in Node 16+.
 */

const { webcrypto } = require("crypto");
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
if (!globalThis.TextEncoder) {
  const { TextEncoder, TextDecoder } = require("util");
  globalThis.TextEncoder = TextEncoder;
  globalThis.TextDecoder = TextDecoder;
}
if (!globalThis.btoa) {
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
}
if (!globalThis.atob) {
  globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
}
if (!globalThis.unescape) {
  globalThis.unescape = (s) =>
    s.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
}
if (!globalThis.escape) {
  globalThis.escape = (s) =>
    s.replace(/[^\x20-\x7E]/g, (c) =>
      "%" + c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
    );
}

const CryptMail = require("../src/crypto.js");

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${msg}`);
  } else {
    failed++;
    console.error(`  ✗ ${msg}`);
  }
}

async function run() {
  console.log("CryptMail crypto tests\n");

  // --- isEncrypted ---
  console.log("isEncrypted:");
  assert(
    CryptMail.isEncrypted("-----BEGIN CRYPTMAIL-----\nabc\n-----END CRYPTMAIL-----"),
    "recognises envelope"
  );
  assert(!CryptMail.isEncrypted("Hello world"), "rejects plain text");
  assert(!CryptMail.isEncrypted(null), "rejects null");
  assert(!CryptMail.isEncrypted(123), "rejects number");

  // --- encrypt produces envelope ---
  console.log("\nencrypt:");
  const armored = await CryptMail.encrypt("Hello, World!", "secret", 3);
  assert(armored.startsWith(CryptMail.ENVELOPE_PREFIX), "starts with prefix");
  assert(armored.endsWith(CryptMail.ENVELOPE_SUFFIX), "ends with suffix");
  assert(CryptMail.isEncrypted(armored), "is recognised as encrypted");
  assert(!armored.includes("Hello, World!"), "plaintext not visible");

  // --- decrypt round-trip ---
  console.log("\ndecrypt:");
  const decrypted = await CryptMail.decrypt(armored, "secret");
  assert(decrypted === "Hello, World!", "round-trip 3 rounds matches");

  // --- round-trip with default rounds ---
  console.log("\ndefault rounds:");
  const armored100 = await CryptMail.encrypt("Test default", "pw123");
  const dec100 = await CryptMail.decrypt(armored100, "pw123");
  assert(dec100 === "Test default", "round-trip default (100) rounds matches");

  // --- wrong passphrase ---
  console.log("\nwrong passphrase:");
  let wrongKeyError = false;
  try {
    await CryptMail.decrypt(armored, "wrong-password");
  } catch {
    wrongKeyError = true;
  }
  assert(wrongKeyError, "decryption with wrong key throws");

  // --- empty input errors ---
  console.log("\ninput validation:");
  let emptyPlainError = false;
  try {
    await CryptMail.encrypt("", "key");
  } catch {
    emptyPlainError = true;
  }
  assert(emptyPlainError, "encrypt rejects empty plaintext");

  let emptyKeyError = false;
  try {
    await CryptMail.encrypt("text", "");
  } catch {
    emptyKeyError = true;
  }
  assert(emptyKeyError, "encrypt rejects empty passphrase");

  // --- unicode support ---
  console.log("\nunicode:");
  const uni = "Ünïcödé 🎉 日本語";
  const armoredUni = await CryptMail.encrypt(uni, "key", 5);
  const decUni = await CryptMail.decrypt(armoredUni, "key");
  assert(decUni === uni, "unicode round-trip matches");

  // --- different ciphertext for same input ---
  console.log("\nrandomness:");
  const a1 = await CryptMail.encrypt("same", "key", 2);
  const a2 = await CryptMail.encrypt("same", "key", 2);
  assert(a1 !== a2, "two encryptions of same text differ");

  // --- summary ---
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
