import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hkdfWebCrypto } from '../../src/adapters/webcrypto/hkdf.js';
import { fromHex } from '../../src/evidence/record.js';

// Traceability: this file exercises hkdf.ikm, hkdf.salt, hkdf.info, hkdf.hash,
// hkdf.length, hkdf.output (RFC 5869 KAT: sec:contract-traceability convention).

test('hkdf.output: RFC 5869 Test Case 1 KAT matches exactly', async () => {
  const record = await hkdfWebCrypto({
    ikm: fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    salt: fromHex('000102030405060708090a0b0c'),
    info: fromHex('f0f1f2f3f4f5f6f7f8f9'),
    length: 42,
  });
  assert.equal(record.outcome.kind, 'accept');
  if (record.outcome.kind === 'accept') {
    assert.equal(
      record.outcome.okmHex,
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  }
});

test('hkdf.length: L=0 rejected as invalid_parameter (D-068 lower bound)', async () => {
  const record = await hkdfWebCrypto({
    ikm: fromHex('0b0b'),
    salt: undefined,
    info: fromHex(''),
    length: 0,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['hkdf.length']);
});

test('hkdf.length: L=8161 rejected as invalid_parameter (D-068 upper bound)', async () => {
  const record = await hkdfWebCrypto({
    ikm: fromHex('0b0b'),
    salt: undefined,
    info: fromHex(''),
    length: 8161,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
});

test('hkdf.length: L=8160 (exact upper bound) is accepted', async () => {
  const record = await hkdfWebCrypto({
    ikm: fromHex('0b0b'),
    salt: undefined,
    info: fromHex(''),
    length: 8160,
  });
  assert.equal(record.outcome.kind, 'accept');
});

test('hkdf.salt: absent salt, explicit zero-length salt, and explicit HashLen zero-byte salt are all contractually equivalent (all accepted, identical OKM)', async () => {
  const absentSalt = await hkdfWebCrypto({
    ikm: fromHex('0b0b0b0b'),
    salt: undefined,
    info: fromHex(''),
    length: 16,
  });
  const explicitEmptySalt = await hkdfWebCrypto({
    ikm: fromHex('0b0b0b0b'),
    salt: new Uint8Array(0),
    info: fromHex(''),
    length: 16,
  });
  // HashLen = 32 for HKDF-SHA-256. This third case was ADDED when closing
  // HKDF coverage parity across all three backends (Experimental Evidence
  // Base v0.2 -> v0.3): the original test compared only absent vs.
  // zero-length salt; Bouncy Castle's runner additionally checked an
  // explicit 32-zero-byte salt, and this closes that gap for WebCrypto too.
  const explicitHashLenZeroSalt = await hkdfWebCrypto({
    ikm: fromHex('0b0b0b0b'),
    salt: new Uint8Array(32),
    info: fromHex(''),
    length: 16,
  });
  assert.equal(absentSalt.outcome.kind, 'accept');
  assert.equal(explicitEmptySalt.outcome.kind, 'accept');
  assert.equal(explicitHashLenZeroSalt.outcome.kind, 'accept');
  // Per RFC 5869 + HMAC's own zero-padding, all three are cryptographically
  // equivalent (all pad to the same HMAC key) -- confirmed by identical
  // OKM here across all three representations, not assumed.
  if (
    absentSalt.outcome.kind === 'accept' &&
    explicitEmptySalt.outcome.kind === 'accept' &&
    explicitHashLenZeroSalt.outcome.kind === 'accept'
  ) {
    assert.equal(absentSalt.outcome.okmHex, explicitEmptySalt.outcome.okmHex);
    assert.equal(explicitEmptySalt.outcome.okmHex, explicitHashLenZeroSalt.outcome.okmHex);
  }
});
