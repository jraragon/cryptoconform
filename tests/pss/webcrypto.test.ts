import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { pssWebCryptoSign, pssWebCryptoVerify, generatePssKeyPair } from '../../src/adapters/webcrypto/pss.js';
import { K_BYTES } from '../../src/contract/pss.js';

// Traceability: exercises all 15 pss.* clauses (sec:contract-traceability
// convention) against the WebCrypto realization. RSA-3072/SHA-256 key pair
// generated once and shared across tests.

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair; // unrelated pair, for the wrong-key test

before(async () => {
  keyPair = await generatePssKeyPair();
  otherKeyPair = await generatePssKeyPair();
});

function normalMessage(): Uint8Array {
  return new TextEncoder().encode('the quick brown fox jumps over the lazy dog');
}

async function signMessage(): Promise<Uint8Array> {
  const record = await pssWebCryptoSign({ key: keyPair.privateKey, message: normalMessage() });
  assert.equal(record.outcome.kind, 'accept');
  if (record.outcome.kind !== 'accept') throw new Error('unreachable');
  return Uint8Array.from(Buffer.from(record.outcome.signatureHex, 'hex'));
}

// --- 1. Sign -> verify round trip ---

test('pss.signature/pss.verification: sign -> verify round trip yields a valid signature', async () => {
  const signature = await signMessage();
  assert.equal(signature.length, K_BYTES);

  const verifyRecord = await pssWebCryptoVerify({ key: keyPair.publicKey, message: normalMessage(), signature });
  assert.equal(verifyRecord.outcome.kind, 'verified');
  if (verifyRecord.outcome.kind === 'verified') {
    assert.equal(verifyRecord.outcome.valid, true);
  }
  assert.deepEqual(verifyRecord.clauseIds, [
    'pss.key',
    'pss.modulus',
    'pss.hash',
    'pss.mgfCoupling',
    'pss.saltLength',
    'pss.verification',
  ]);
});

// --- 2. Signature output is exactly 384 bytes ---

test('pss.signatureLength: successful sign always produces exactly 384 bytes', async () => {
  const signature = await signMessage();
  assert.equal(signature.length, K_BYTES);
});

// --- 3. Corrupted signature -> verified(false), never a reject ---

test('pss.verification: corrupted signature (single flipped byte) yields verified(valid:false), NOT a reject', async () => {
  const signature = await signMessage();
  const corrupted = signature.slice();
  corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;

  const record = await pssWebCryptoVerify({ key: keyPair.publicKey, message: normalMessage(), signature: corrupted });
  assert.equal(record.outcome.kind, 'verified');
  if (record.outcome.kind === 'verified') {
    assert.equal(record.outcome.valid, false);
  }
});

// --- 4. Truncated signature -> verified(false), NOT a reject ---
// The most dangerous point of implementation, mirroring OAEP's D-034 but
// grounded in an even more direct RFC 8017 rule (D-046): |sigma|!=k is
// part of Verify's own {true,false} result domain, not an SDK error.

test('pss.verification: signature shorter than 384 bytes yields verified(valid:false), NOT invalid_parameter -- confirmed through the actual adapter call path', async () => {
  const record = await pssWebCryptoVerify({
    key: keyPair.publicKey,
    message: normalMessage(),
    signature: new Uint8Array(10), // far short of K_BYTES=384
  });
  assert.equal(record.outcome.kind, 'verified');
  if (record.outcome.kind === 'verified') {
    assert.equal(record.outcome.valid, false);
  }
});

// --- 5. Lengthened signature -> verified(false), NOT a reject ---

test('pss.verification: signature longer than 384 bytes yields verified(valid:false), NOT invalid_parameter', async () => {
  const record = await pssWebCryptoVerify({
    key: keyPair.publicKey,
    message: normalMessage(),
    signature: new Uint8Array(K_BYTES + 10),
  });
  assert.equal(record.outcome.kind, 'verified');
  if (record.outcome.kind === 'verified') {
    assert.equal(record.outcome.valid, false);
  }
});

// --- 6. Wrong-key verification -> verified(false) ---

test('pss.verification: verifying with an unrelated public key yields verified(valid:false)', async () => {
  const signature = await signMessage();
  const record = await pssWebCryptoVerify({ key: otherKeyPair.publicKey, message: normalMessage(), signature });
  assert.equal(record.outcome.kind, 'verified');
  if (record.outcome.kind === 'verified') {
    assert.equal(record.outcome.valid, false);
  }
});

// --- 7. Key-role mismatch -> invalid_key ---

test('pss.key: sign with a public key rejected as invalid_key', async () => {
  const record = await pssWebCryptoSign({ key: keyPair.publicKey, message: normalMessage() }); // wrong role
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_key');
  }
  assert.deepEqual(record.clauseIds, ['pss.key']);
});

test('pss.key: verify with a private key rejected as invalid_key', async () => {
  const record = await pssWebCryptoVerify({
    key: keyPair.privateKey, // wrong role
    message: normalMessage(),
    signature: new Uint8Array(K_BYTES),
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_key');
  }
  assert.deepEqual(record.clauseIds, ['pss.key']);
});

// --- 8. Non-3072-bit key -> invalid_parameter ---

test('pss.modulus: a non-3072-bit key is rejected as invalid_parameter', async () => {
  const smallKeyPair = await webcrypto2048();
  const record = await pssWebCryptoSign({ key: smallKeyPair.privateKey, message: normalMessage() });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['pss.modulus']);
});

async function webcrypto2048(): Promise<CryptoKeyPair> {
  const { webcrypto } = await import('node:crypto');
  return webcrypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ) as unknown as Promise<CryptoKeyPair>;
}

// --- 9. Non-determinism control ---

test('CONTROL (not a conformance obligation): two signatures of the identical (K,M) differ (random salt), both still verify true -- material evidence for R_byte = N/A on PSS', async () => {
  const message = normalMessage();
  const r1 = await pssWebCryptoSign({ key: keyPair.privateKey, message });
  const r2 = await pssWebCryptoSign({ key: keyPair.privateKey, message });
  assert.equal(r1.outcome.kind, 'accept');
  assert.equal(r2.outcome.kind, 'accept');
  if (r1.outcome.kind !== 'accept' || r2.outcome.kind !== 'accept') return;

  // The control's point: signatures DIFFER (random salt, D-042: no
  // portable RNG/salt-bytes control) -- no pss.* clause asserts signature
  // equality, and none is being invented for this test.
  assert.notEqual(r1.outcome.signatureHex, r2.outcome.signatureHex);

  const sig1 = Uint8Array.from(Buffer.from(r1.outcome.signatureHex, 'hex'));
  const sig2 = Uint8Array.from(Buffer.from(r2.outcome.signatureHex, 'hex'));
  const v1 = await pssWebCryptoVerify({ key: keyPair.publicKey, message, signature: sig1 });
  const v2 = await pssWebCryptoVerify({ key: keyPair.publicKey, message, signature: sig2 });
  assert.equal(v1.outcome.kind, 'verified');
  assert.equal(v2.outcome.kind, 'verified');
  if (v1.outcome.kind === 'verified' && v2.outcome.kind === 'verified') {
    assert.equal(v1.outcome.valid, true);
    assert.equal(v2.outcome.valid, true);
  }
});

// --- 10. A false verdict must never be turned into any error category ---

test('D-047 discipline: a false verify outcome carries NO errorClass field at all -- it is a functional result, not an SDK error', async () => {
  const record = await pssWebCryptoVerify({
    key: keyPair.publicKey,
    message: normalMessage(),
    signature: new Uint8Array(K_BYTES), // all-zero signature, cryptographically invalid but structurally well-formed length
  });
  assert.equal(record.outcome.kind, 'verified');
  // TypeScript's discriminated union already makes it impossible for a
  // 'verified' outcome to carry an errorClass field (only 'reject' does) --
  // this assertion is a runtime double-check of that static guarantee,
  // confirming no stray field leaks through in the actual JSON shape.
  assert.ok(!('errorClass' in record.outcome), 'a verified outcome must never carry an errorClass field');
});
