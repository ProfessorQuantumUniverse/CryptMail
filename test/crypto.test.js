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
  assert(dec100 === "Test default", "round-trip default (1) rounds matches");

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

  // --- progress callback for encrypt ---
  console.log("\nprogress callback (encrypt):");
  const encProgress = [];
  await CryptMail.encrypt("progress test", "key", 5, (p) => encProgress.push(p));
  assert(encProgress.length === 5, "encrypt progress called for each round");
  assert(encProgress[encProgress.length - 1] === 100, "encrypt progress ends at 100%");
  assert(encProgress[0] === Math.round(100 / 5), "encrypt first round reports correct percentage");

  // --- progress callback for decrypt ---
  console.log("\nprogress callback (decrypt):");
  const armoredProg = await CryptMail.encrypt("progress test", "key", 5);
  const decProgress = [];
  await CryptMail.decrypt(armoredProg, "key", (p) => decProgress.push(p));
  assert(decProgress.length === 5, "decrypt progress called for each round");
  assert(decProgress[decProgress.length - 1] === 100, "decrypt progress ends at 100%");

  // --- encrypt/decrypt without progress callback still works ---
  console.log("\nno progress callback:");
  const armoredNoProg = await CryptMail.encrypt("no progress", "key", 3);
  const decNoProg = await CryptMail.decrypt(armoredNoProg, "key");
  assert(decNoProg === "no progress", "round-trip without progress callback works");

  // --- subject encryption ---
  console.log("\nsubject encryption:");
  const subjectToken = await CryptMail.encryptSubject("Meeting tomorrow", "secret");
  assert(subjectToken.startsWith(CryptMail.SUBJECT_PREFIX), "subject token has [CM] prefix");
  assert(CryptMail.isSubjectEncrypted(subjectToken), "isSubjectEncrypted recognises token");
  assert(!CryptMail.isSubjectEncrypted("Normal subject"), "isSubjectEncrypted rejects plain text");

  const subjectPlain = await CryptMail.decryptSubject(subjectToken, "secret");
  assert(subjectPlain === "Meeting tomorrow", "subject round-trip matches");

  // Subject token must be short enough for email subject lines
  assert(subjectToken.length < 250, "subject token fits in ~250 chars (got " + subjectToken.length + ")");

  // Wrong passphrase on subject should throw
  let subjectWrongKey = false;
  try {
    await CryptMail.decryptSubject(subjectToken, "wrong");
  } catch {
    subjectWrongKey = true;
  }
  assert(subjectWrongKey, "subject decryption with wrong key throws");

  // Unicode subject
  const uniSubject = "Ünîcödé 🎉";
  const uniSubToken = await CryptMail.encryptSubject(uniSubject, "key");
  const uniSubDec = await CryptMail.decryptSubject(uniSubToken, "key");
  assert(uniSubDec === uniSubject, "unicode subject round-trip matches");

  // --- summary ---
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
