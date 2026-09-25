import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { oaepWebCryptoEncrypt, oaepWebCryptoDecrypt, generateOaepKeyPair } from '../../src/adapters/webcrypto/oaep.js';
import { K_BYTES, MAX_MESSAGE_LEN_BYTES } from '../../src/contract/oaep.js';

// Traceability: exercises all 13 oaep.* clauses (sec:contract-traceability
// convention) against the WebCrypto realization. RSA-3072/SHA-256 key pair
// generated once and shared across tests -- RSA keygen at this size is
// non-trivial, and nothing in this suite requires per-test fresh keys.

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair; // a second pair, for the key-role-mismatch tests

before(async () => {
  keyPair = await generateOaepKeyPair();
  otherKeyPair = await generateOaepKeyPair();
});

function normalMessage(): Uint8Array {
  return new TextEncoder().encode('the quick brown fox jumps over the lazy dog');
}

// --- 1. Keygen/import + encrypt -> decrypt round trip (normal message) ---

test('oaep.key/oaep.ciphertext: encrypt -> decrypt round trip recovers the exact plaintext', async () => {
  const plaintext = normalMessage();
  const encRecord = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext, label: undefined });
  assert.equal(encRecord.outcome.kind, 'accept');
  if (encRecord.outcome.kind !== 'accept') return;

  const decRecord = await oaepWebCryptoDecrypt({
    key: keyPair.privateKey,
    ciphertext: Uint8Array.from(Buffer.from(encRecord.outcome.ciphertextHex, 'hex')),
    label: undefined,
  });
  assert.equal(decRecord.outcome.kind, 'accept');
  if (decRecord.outcome.kind === 'accept') {
    assert.equal(decRecord.outcome.plaintextHex, Buffer.from(plaintext).toString('hex'));
  }
});

// --- 2. Message-length boundary: 318 accepted, 319 rejected ---

test('oaep.message: mLen=318 (exact bound) accepted, mLen=319 rejected as invalid_parameter', async () => {
  const at318 = await oaepWebCryptoEncrypt({
    key: keyPair.publicKey,
    plaintext: new Uint8Array(MAX_MESSAGE_LEN_BYTES),
    label: undefined,
  });
  assert.equal(at318.outcome.kind, 'accept');

  const at319 = await oaepWebCryptoEncrypt({
    key: keyPair.publicKey,
    plaintext: new Uint8Array(MAX_MESSAGE_LEN_BYTES + 1),
    label: undefined,
  });
  assert.equal(at319.outcome.kind, 'reject');
  if (at319.outcome.kind === 'reject') {
    assert.equal(at319.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(at319.clauseIds, ['oaep.message']);
});

// --- 3. Ciphertext output is exactly 384 bytes ---

test('oaep.ciphertextLength: successful encryption always produces exactly 384 bytes', async () => {
  const record = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext: normalMessage(), label: undefined });
  assert.equal(record.outcome.kind, 'accept');
  if (record.outcome.kind === 'accept') {
    assert.equal(record.outcome.ciphertextHex.length, K_BYTES * 2);
  }
});

// --- 4. Label absent === label empty ---

test('oaep.label: absent and explicit empty labels both accepted, and cross-compatible at decrypt', async () => {
  const plaintext = normalMessage();
  const absentRecord = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext, label: undefined });
  const emptyRecord = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext, label: new Uint8Array(0) });
  assert.equal(absentRecord.outcome.kind, 'accept');
  assert.equal(emptyRecord.outcome.kind, 'accept');

  if (absentRecord.outcome.kind === 'accept' && emptyRecord.outcome.kind === 'accept') {
    // Cross-check: ciphertext encrypted with absent label must decrypt
    // correctly when empty label is supplied at decrypt, and vice versa --
    // confirming L_absent === L_empty through the full round trip, not
    // just at the encrypt call (same pattern as gcm.aad's cross-check).
    const decAbsentWithEmpty = await oaepWebCryptoDecrypt({
      key: keyPair.privateKey,
      ciphertext: Uint8Array.from(Buffer.from(absentRecord.outcome.ciphertextHex, 'hex')),
      label: new Uint8Array(0),
    });
    const decEmptyWithAbsent = await oaepWebCryptoDecrypt({
      key: keyPair.privateKey,
      ciphertext: Uint8Array.from(Buffer.from(emptyRecord.outcome.ciphertextHex, 'hex')),
      label: undefined,
    });
    assert.equal(decAbsentWithEmpty.outcome.kind, 'accept');
    assert.equal(decEmptyWithAbsent.outcome.kind, 'accept');
  }
});

test('oaep.label: non-empty label rejected as invalid_parameter (D-030)', async () => {
  const record = await oaepWebCryptoEncrypt({
    key: keyPair.publicKey,
    plaintext: normalMessage(),
    label: new Uint8Array([0x01, 0x02]),
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['oaep.label']);
});

// --- 5. Hash/MGF coupling fixed to SHA-256, derived from the CryptoKey itself ---

test('oaep.hash/oaep.mgfCoupling: hash and mgfHash in the evidence record are read from the CryptoKey material (SHA-256), not an independently-suppliable field', async () => {
  const record = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext: normalMessage(), label: undefined });
  assert.equal(record.outcome.kind, 'accept');
  assert.equal(record.input.hash, 'SHA-256');
  assert.equal(record.input.mgfHash, 'SHA-256');
});

// --- 6. Corrupted ciphertext -> decryption_error ---

test('oaep.error: corrupted ciphertext (single flipped byte) rejected as decryption_error', async () => {
  const encRecord = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext: normalMessage(), label: undefined });
  assert.equal(encRecord.outcome.kind, 'accept');
  if (encRecord.outcome.kind !== 'accept') return;

  const corrupted = Uint8Array.from(Buffer.from(encRecord.outcome.ciphertextHex, 'hex'));
  corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;

  const decRecord = await oaepWebCryptoDecrypt({ key: keyPair.privateKey, ciphertext: corrupted, label: undefined });
  assert.equal(decRecord.outcome.kind, 'reject');
  if (decRecord.outcome.kind === 'reject') {
    assert.equal(decRecord.outcome.errorClass, 'decryption_error');
  }
});

// --- 7. Wrong-length ciphertext -> ALSO decryption_error, not invalid_parameter ---
// This is the single most dangerous point of divergence from AES-GCM's
// adapters, where pre-backend structural checks were the norm. Here, the
// wrong-length ciphertext is deliberately passed straight through
// Accept_C (which never checks it, per D-034) and reaches subtle.decrypt
// itself; whatever WebCrypto throws is caught WITHOUT inspection and
// normalized to decryption_error -- confirmed empirically here, not just
// argued in the contract-layer unit test.

test('oaep.error: ciphertext shorter than 384 bytes rejected as decryption_error (NOT invalid_parameter), confirmed through the actual adapter call path', async () => {
  const decRecord = await oaepWebCryptoDecrypt({
    key: keyPair.privateKey,
    ciphertext: new Uint8Array(10), // far short of K_BYTES=384
    label: undefined,
  });
  assert.equal(decRecord.outcome.kind, 'reject');
  if (decRecord.outcome.kind === 'reject') {
    assert.equal(decRecord.outcome.errorClass, 'decryption_error');
  }
});

test('oaep.error: ciphertext longer than 384 bytes rejected as decryption_error (NOT invalid_parameter)', async () => {
  const decRecord = await oaepWebCryptoDecrypt({
    key: keyPair.privateKey,
    ciphertext: new Uint8Array(K_BYTES + 10),
    label: undefined,
  });
  assert.equal(decRecord.outcome.kind, 'reject');
  if (decRecord.outcome.kind === 'reject') {
    assert.equal(decRecord.outcome.errorClass, 'decryption_error');
  }
});

// --- 8. Key-role mismatch -> invalid_key ---

test('oaep.key: encrypt with a private key rejected as invalid_key', async () => {
  const record = await oaepWebCryptoEncrypt({
    key: keyPair.privateKey, // wrong role for encrypt
    plaintext: normalMessage(),
    label: undefined,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_key');
  }
  assert.deepEqual(record.clauseIds, ['oaep.key']);
});

test('oaep.key: decrypt with a public key rejected as invalid_key', async () => {
  const record = await oaepWebCryptoDecrypt({
    key: keyPair.publicKey, // wrong role for decrypt
    ciphertext: new Uint8Array(K_BYTES),
    label: undefined,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_key');
  }
  assert.deepEqual(record.clauseIds, ['oaep.key']);
});

// --- 9. modulus mismatch -> invalid_parameter (a 2048-bit key is out of the portable profile) ---

test('oaep.modulus: a non-3072-bit key is rejected as invalid_parameter', async () => {
  const smallKeyPair = await webcryptoGenerateSmallKey();
  const record = await oaepWebCryptoEncrypt({ key: smallKeyPair.publicKey, plaintext: normalMessage(), label: undefined });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['oaep.modulus']);
});

async function webcryptoGenerateSmallKey(): Promise<CryptoKeyPair> {
  const { webcrypto } = await import('node:crypto');
  return webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  ) as unknown as Promise<CryptoKeyPair>;
}

// --- 10. Decrypting with an unrelated key pair also collapses to decryption_error ---
// (a genuine RSA-representative-out-of-range / lHash-mismatch style failure,
// exercised through the real backend rather than a synthetic length error)

test('oaep.error: decrypting a valid ciphertext with an unrelated private key is rejected as decryption_error', async () => {
  const encRecord = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext: normalMessage(), label: undefined });
  assert.equal(encRecord.outcome.kind, 'accept');
  if (encRecord.outcome.kind !== 'accept') return;

  const decRecord = await oaepWebCryptoDecrypt({
    key: otherKeyPair.privateKey, // unrelated key
    ciphertext: Uint8Array.from(Buffer.from(encRecord.outcome.ciphertextHex, 'hex')),
    label: undefined,
  });
  assert.equal(decRecord.outcome.kind, 'reject');
  if (decRecord.outcome.kind === 'reject') {
    assert.equal(decRecord.outcome.errorClass, 'decryption_error');
  }
});

// --- 11. Non-determinism control: two encrypts of the SAME (K,M) differ ---
// Documented deliberately as a CONTROL demonstrating why R_byte is N/A for
// OAEP (v0.6, D-033: "OAEP encryption remains probabilistic under the
// portable contract... even within a single backend"), NOT as a positive
// conformance obligation. The actual contractual obligation remains
// Dec(Enc(M)) = M (R_interop), verified separately above -- "ciphertexts
// must differ" is never itself a contract clause, and is not tested as one.

test('CONTROL (not a conformance obligation): two encryptions of the identical (K,M) produce DIFFERENT ciphertexts, both of which still decrypt to the same M -- material evidence for R_byte = N/A on OAEP, D-033', async () => {
  const plaintext = normalMessage();
  const r1 = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext, label: undefined });
  const r2 = await oaepWebCryptoEncrypt({ key: keyPair.publicKey, plaintext, label: undefined });
  assert.equal(r1.outcome.kind, 'accept');
  assert.equal(r2.outcome.kind, 'accept');
  if (r1.outcome.kind !== 'accept' || r2.outcome.kind !== 'accept') return;

  // This is the control's point: ciphertexts DIFFER (internal OAEP seed is
  // randomized and not portably controllable, D-033) -- unlike AES-GCM's
  // gcm.ciphertext clause, there is no oaep.* clause asserting byte
  // equality here, and none is being invented for this test.
  assert.notEqual(r1.outcome.ciphertextHex, r2.outcome.ciphertextHex);

  // The actual contractual obligation: both still decrypt to the same M.
  const d1 = await oaepWebCryptoDecrypt({
    key: keyPair.privateKey,
    ciphertext: Uint8Array.from(Buffer.from(r1.outcome.ciphertextHex, 'hex')),
    label: undefined,
  });
  const d2 = await oaepWebCryptoDecrypt({
    key: keyPair.privateKey,
    ciphertext: Uint8Array.from(Buffer.from(r2.outcome.ciphertextHex, 'hex')),
    label: undefined,
  });
  assert.equal(d1.outcome.kind, 'accept');
  assert.equal(d2.outcome.kind, 'accept');
  if (d1.outcome.kind === 'accept' && d2.outcome.kind === 'accept') {
    assert.equal(d1.outcome.plaintextHex, Buffer.from(plaintext).toString('hex'));
    assert.equal(d2.outcome.plaintextHex, Buffer.from(plaintext).toString('hex'));
  }
});
