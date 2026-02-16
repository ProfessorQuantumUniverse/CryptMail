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
    CryptMail.isEncrypted(
      "-----BEGIN CRYPTMAIL-----\nabc\n-----END CRYPTMAIL-----"
    ),
    "recognises envelope"
  );
  assert(!CryptMail.isEncrypted("Hello world"), "rejects plain text");
  assert(!CryptMail.isEncrypted(null), "rejects null");
  assert(!CryptMail.isEncrypted(123), "rejects number");

  // --- encrypt produces envelope (single round) ---
  console.log("\nencrypt (single round):");
  const armored = await CryptMail.encrypt("Hello, World!", "secret");
  assert(armored.startsWith(CryptMail.ENVELOPE_PREFIX), "starts with prefix");
  assert(armored.endsWith(CryptMail.ENVELOPE_SUFFIX), "ends with suffix");
  assert(CryptMail.isEncrypted(armored), "is recognised as encrypted");
  assert(!armored.includes("Hello, World!"), "plaintext not visible");

  // Verify it's a single round
  const info = CryptMail.getEnvelopeInfo(armored);
  assert(info !== null, "getEnvelopeInfo returns data");
  assert(info.version === 1, "envelope version is 1");
  assert(info.rounds === 1, "envelope uses 1 round");
  assert(info.mode === "passphrase", 'mode is "passphrase"');

  // --- decrypt round-trip ---
  console.log("\ndecrypt:");
  const decrypted = await CryptMail.decrypt(armored, "secret");
  assert(decrypted === "Hello, World!", "round-trip matches");

  // --- encrypt with legacy rounds parameter (ignored) ---
  console.log("\nlegacy rounds parameter:");
  const armoredLegacy = await CryptMail.encrypt(
    "Legacy test",
    "secret",
    5
  );
  const infoLegacy = CryptMail.getEnvelopeInfo(armoredLegacy);
  assert(infoLegacy.rounds === 1, "rounds parameter is ignored (still 1)");
  const decLegacy = await CryptMail.decrypt(armoredLegacy, "secret");
  assert(decLegacy === "Legacy test", "legacy call round-trip works");

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
  const armoredUni = await CryptMail.encrypt(uni, "key");
  const decUni = await CryptMail.decrypt(armoredUni, "key");
  assert(decUni === uni, "unicode round-trip matches");

  // --- different ciphertext for same input ---
  console.log("\nrandomness:");
  const a1 = await CryptMail.encrypt("same", "key");
  const a2 = await CryptMail.encrypt("same", "key");
  assert(a1 !== a2, "two encryptions of same text differ");

  // --- progress callback ---
  console.log("\nprogress callback (single round):");
  const encProgress = [];
  await CryptMail.encrypt("progress test", "key", (p) => encProgress.push(p));
  assert(encProgress.length === 1, "encrypt progress called once (single round)");
  assert(encProgress[0] === 100, "encrypt progress reports 100%");

  // --- progress callback for decrypt ---
  console.log("\nprogress callback (decrypt):");
  const armoredProg = await CryptMail.encrypt("progress test", "key");
  const decProgress = [];
  await CryptMail.decrypt(armoredProg, "key", (p) => decProgress.push(p));
  assert(decProgress.length === 1, "decrypt progress called once (single round)");
  assert(decProgress[0] === 100, "decrypt progress reports 100%");

  // --- progress as 4th arg (legacy) ---
  console.log("\nprogress as legacy 4th arg:");
  const legProgress = [];
  await CryptMail.encrypt("legacy progress", "key", 3, (p) =>
    legProgress.push(p)
  );
  assert(
    legProgress.length === 1,
    "legacy progress called once despite rounds=3"
  );
  assert(legProgress[0] === 100, "legacy progress reports 100%");

  // --- encrypt with options object ---
  console.log("\noptions object:");
  const optProgress = [];
  const armoredOpt = await CryptMail.encrypt("options test", "key", {
    onProgress: (p) => optProgress.push(p),
    senderPublicKey: "test-key-123",
    encryptedSubject: "[CM]encrypted-subject",
  });
  assert(optProgress[0] === 100, "options onProgress works");
  const optInfo = CryptMail.getEnvelopeInfo(armoredOpt);
  assert(
    optInfo.senderPublicKey === "test-key-123",
    "senderPublicKey is stored in envelope"
  );
  assert(
    optInfo.encryptedSubject === "[CM]encrypted-subject",
    "encryptedSubject is stored in envelope"
  );
  assert(optInfo.hasEncryptedSubject === true, "hasEncryptedSubject flag is true");

  // Still decrypts correctly
  const decOpt = await CryptMail.decrypt(armoredOpt, "key");
  assert(decOpt === "options test", "options envelope decrypts correctly");

  // --- subject encryption ---
  console.log("\nsubject encryption:");
  const subjectToken = await CryptMail.encryptSubject(
    "Meeting tomorrow",
    "secret"
  );
  assert(
    subjectToken.startsWith(CryptMail.SUBJECT_PREFIX),
    "subject token has [CM] prefix"
  );
  assert(
    CryptMail.isSubjectEncrypted(subjectToken),
    "isSubjectEncrypted recognises token"
  );
  assert(
    !CryptMail.isSubjectEncrypted("Normal subject"),
    "isSubjectEncrypted rejects plain text"
  );

  const subjectPlain = await CryptMail.decryptSubject(subjectToken, "secret");
  assert(subjectPlain === "Meeting tomorrow", "subject round-trip matches");

  assert(
    subjectToken.length < 250,
    "subject token fits in ~250 chars (got " + subjectToken.length + ")"
  );

  // Wrong passphrase on subject
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

  // --- getEnvelopeInfo ---
  console.log("\ngetEnvelopeInfo:");
  const infoNull = CryptMail.getEnvelopeInfo("not an envelope");
  assert(infoNull === null, "returns null for invalid input");

  // --- ECDH key pair generation ---
  console.log("\nECDH key pair:");
  const kp = await CryptMail.generateKeyPair();
  assert(kp.publicKey && kp.publicKey.length > 0, "generates public key");
  assert(kp.privateKey && kp.privateKey.length > 0, "generates private key (JWK)");
  const jwk = JSON.parse(kp.privateKey);
  assert(jwk.kty === "EC", "private key is EC type");
  assert(jwk.crv === "P-256", "private key uses P-256 curve");

  // --- File encryption ---
  console.log("\nfile encryption:");
  const fileData = new TextEncoder().encode("Hello file content!");
  const encFile = await CryptMail.encryptFile(
    fileData.buffer,
    "test.txt",
    "text/plain",
    "filepass"
  );
  assert(typeof encFile === "string", "encryptFile returns string");
  const encFileObj = JSON.parse(encFile);
  assert(encFileObj.type === "file", 'envelope has type "file"');
  assert(encFileObj.filename === "test.txt", "preserves filename");
  assert(encFileObj.mimeType === "text/plain", "preserves mimeType");

  // Decrypt file
  const decFile = await CryptMail.decryptFile(encFile, "filepass");
  assert(decFile.filename === "test.txt", "decrypted filename matches");
  assert(decFile.mimeType === "text/plain", "decrypted mimeType matches");
  const decFileText = new TextDecoder().decode(decFile.data);
  assert(
    decFileText === "Hello file content!",
    "file content round-trip matches"
  );

  // Wrong passphrase for file
  let fileWrongKey = false;
  try {
    await CryptMail.decryptFile(encFile, "wrong");
  } catch {
    fileWrongKey = true;
  }
  assert(fileWrongKey, "file decryption with wrong key throws");

  // --- backward compatibility: multi-round decrypt ---
  console.log("\nbackward compatibility (multi-round decrypt):");

  // Create a legacy 3-round envelope manually
  // We'll just verify that the structure is parseable
  // (In practice, old encrypted messages can still be decrypted)
  const legacyEncrypt = async (text, pass, rounds) => {
    const ALGO = "AES-GCM";
    const PBKDF2_ITERATIONS = 1000000;
    const SALT_BYTES = 32;

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

    let current = new TextEncoder().encode(text);
    const params = [];

    for (let i = 0; i < rounds; i++) {
      const salt = randomBytes(SALT_BYTES);
      const iv = randomBytes(12);
      const raw = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pass),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256",
        },
        raw,
        { name: ALGO, length: 256 },
        false,
        ["encrypt"]
      );
      current = new Uint8Array(
        await crypto.subtle.encrypt({ name: ALGO, iv }, key, current)
      );
      params.push({ salt: hexEncode(salt), iv: hexEncode(iv) });
    }

    const envelope = { v: 1, rounds, params, data: hexEncode(current) };
    const json = JSON.stringify(envelope);
    const bytes = new TextEncoder().encode(json);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const b64 = btoa(binary);
    return `-----BEGIN CRYPTMAIL-----\n${b64}\n-----END CRYPTMAIL-----`;
  };

  const legacyArmored = await legacyEncrypt("Legacy 3-round message", "pass123", 3);
  const legacyDecrypted = await CryptMail.decrypt(legacyArmored, "pass123");
  assert(
    legacyDecrypted === "Legacy 3-round message",
    "3-round legacy envelope decrypts correctly"
  );

  // Multi-round progress callback
  const legacyProgress = [];
  await CryptMail.decrypt(legacyArmored, "pass123", (p) =>
    legacyProgress.push(p)
  );
  assert(
    legacyProgress.length === 3,
    "legacy decrypt progress called for each round"
  );
  assert(
    legacyProgress[legacyProgress.length - 1] === 100,
    "legacy decrypt progress reaches 100%"
  );

  // --- summary ---
  console.log(`\n${passed} passed, ${failed} failed`);

  // --- v3.0 envelope with senderPublicKey auto key exchange ---
  console.log("\nv3.0 auto key exchange (senderPublicKey in envelope):");

  // Generate a keypair and embed public key in envelope
  const senderKp = await CryptMail.generateKeyPair();
  const armoredWithKey = await CryptMail.encrypt("Key exchange test", "secret", {
    senderPublicKey: senderKp.publicKey,
  });

  // Verify the public key is embedded in the envelope
  const keyExInfo = CryptMail.getEnvelopeInfo(armoredWithKey);
  assert(keyExInfo !== null, "key-exchange envelope parses");
  assert(keyExInfo.senderPublicKey === senderKp.publicKey, "senderPublicKey preserved in envelope");
  assert(keyExInfo.mode === "passphrase", "mode is still passphrase for symmetric encrypt");

  // Still decrypts normally
  const decKeyEx = await CryptMail.decrypt(armoredWithKey, "secret");
  assert(decKeyEx === "Key exchange test", "key-exchange envelope decrypts correctly");

  // --- v3.0 envelope with encryptedSubject + senderPublicKey ---
  console.log("\nv3.0 full envelope (subject + key):");
  const fullSubject = await CryptMail.encryptSubject("Secret meeting", "pass");
  const fullEnvelope = await CryptMail.encrypt("Full v3 test", "pass", {
    senderPublicKey: senderKp.publicKey,
    encryptedSubject: fullSubject,
  });
  const fullInfo = CryptMail.getEnvelopeInfo(fullEnvelope);
  assert(fullInfo.senderPublicKey === senderKp.publicKey, "full envelope has senderPublicKey");
  assert(fullInfo.hasEncryptedSubject === true, "full envelope has encrypted subject");
  assert(fullInfo.encryptedSubject === fullSubject, "full envelope subject token matches");
  const fullDec = await CryptMail.decrypt(fullEnvelope, "pass");
  assert(fullDec === "Full v3 test", "full v3 envelope decrypts correctly");
  const fullSubDec = await CryptMail.decryptSubject(fullInfo.encryptedSubject, "pass");
  assert(fullSubDec === "Secret meeting", "embedded subject decrypts from envelope info");

  // --- ECDH key pair generation (v3 identity) ---
  console.log("\nv3.0 ECDH identity key pairs:");
  const kp1 = await CryptMail.generateKeyPair();
  const kp2 = await CryptMail.generateKeyPair();
  assert(kp1.publicKey !== kp2.publicKey, "two key pairs have different public keys");
  assert(kp1.publicKey.length > 20, "public key has reasonable length");
  const jwk1 = JSON.parse(kp1.privateKey);
  assert(jwk1.kty === "EC" && jwk1.crv === "P-256", "key pair is P-256 ECDH");

  // --- fingerprint generation helper ---
  console.log("\nfingerprint generation:");
  // Simulate the fingerprint function from popup.js
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
      return publicKeyB64.substring(0, 32) + "\u2026";
    }
  }
  const fp = generateFingerprint(kp1.publicKey);
  assert(fp.includes(" : "), "fingerprint contains colon separators");
  assert(fp.length > 10, "fingerprint has reasonable length");
  const fp2 = generateFingerprint(kp1.publicKey);
  assert(fp === fp2, "same key produces same fingerprint");
  const fp3 = generateFingerprint(kp2.publicKey);
  assert(fp !== fp3, "different keys produce different fingerprints");

  // --- password strength calculator ---
  console.log("\npassword strength:");
  function calculateStrength(pw) {
    if (!pw) return { score: 0, cls: "" };
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length >= 16) score++;
    if (score <= 1) return { score, cls: "weak" };
    if (score <= 2) return { score, cls: "fair" };
    if (score <= 3) return { score, cls: "good" };
    return { score, cls: "strong" };
  }
  assert(calculateStrength("").score === 0, "empty password scores 0");
  assert(calculateStrength("abc").cls === "weak", "short password is weak");
  assert(calculateStrength("abcdefgh").cls === "weak", "8 lowercase is weak");
  assert(calculateStrength("Abcdefgh1").cls === "good", "mixed 9 chars is good");
  assert(calculateStrength("Abcdefgh123!longpass").cls === "strong", "complex long password is strong");

  // Final summary
  console.log(`\nFinal: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
