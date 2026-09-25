import { test } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalEncode, UnsupportedCanonicalValueError } from '../../../harness/canonical/canonical-encode.js';
import { TOY_PRIVATE_MATERIAL as RSA_PRIVATE, TOY_PUBLIC_MATERIAL as RSA_PUBLIC } from '../../../harness/mutations/rsa-ser.js';
import { TOY_PRIVATE_MATERIAL as EC_PRIVATE, TOY_PUBLIC_MATERIAL as EC_PUBLIC } from '../../../harness/mutations/ec-ser.js';

// ---------------------------------------------------------------------
// M3-H2 regression -- discovered during M3.2.4a-5's own inspection, before
// the frozen material pool was designed. The pre-existing canonicalize()
// (JSON.stringify + sortKeysDeep) was in use as BaselineCache's key
// function in the M3.2.3 orchestrator, and is not type-safe for
// cryptographic fixtures:
//   H2a  bigint  -> TypeError, crashing outright
//   H2b  Uint8Array -> structural COLLISION with a plain index-keyed object
// 31 rsa-ser/ec-ser classes have R_byte applicable and would have routed
// bigint-bearing material into that key function. Neither manifestation was
// reachable from the single real precedent (HKDF, raw bytes only).
// ---------------------------------------------------------------------

test('M3-H2a: bigint does not throw -- the exact crash reproduced before the fix', () => {
  assert.doesNotThrow(() => canonicalEncode({ n: 3233n }));
  // The real structured material of the 31 affected classes.
  assert.doesNotThrow(() => canonicalEncode(RSA_PRIVATE));
  assert.doesNotThrow(() => canonicalEncode(RSA_PUBLIC));
  assert.doesNotThrow(() => canonicalEncode(EC_PRIVATE));
  assert.doesNotThrow(() => canonicalEncode(EC_PUBLIC));
});

test('M3-H2b: Uint8Array does not collide with a plain index-keyed object -- the exact collision reproduced before the fix', () => {
  const asBytes = canonicalEncode({ k: new Uint8Array([1, 2]) });
  const asObject = canonicalEncode({ k: { '0': 1, '1': 2 } });
  assert.notEqual(asBytes, asObject);
});

test('M3-H2: Uint8Array does not collide with an array of the same numbers', () => {
  assert.notEqual(canonicalEncode(new Uint8Array([1, 2])), canonicalEncode([1, 2]));
});

test('M3-H2: 1n, 1 and "1" are three mutually distinct encodings', () => {
  const encodings = new Set([canonicalEncode(1n), canonicalEncode(1), canonicalEncode('1')]);
  assert.equal(encodings.size, 3);
});

test('M3-H2: byte length is unambiguously part of the representation', () => {
  // Same leading bytes, different length -- must never share an encoding.
  assert.notEqual(canonicalEncode(new Uint8Array([1, 2])), canonicalEncode(new Uint8Array([1, 2, 0])));
  // An all-zero array's length must still be distinguishable.
  assert.notEqual(canonicalEncode(new Uint8Array(2)), canonicalEncode(new Uint8Array(3)));
});

test('M3-H2: object encoding is independent of property insertion order', () => {
  const a: Record<string, unknown> = {};
  a['z'] = 1; a['a'] = 2;
  const b: Record<string, unknown> = {};
  b['a'] = 2; b['z'] = 1;
  assert.equal(canonicalEncode(a), canonicalEncode(b));
});

test('M3-H2: arrays preserve order (a sequence is never treated as a set)', () => {
  assert.notEqual(canonicalEncode([1, 2]), canonicalEncode([2, 1]));
});

test('M3-H2: length-prefixing prevents a crafted key from imitating separate entries', () => {
  // Without length-prefixed keys/values these could be made to collide.
  assert.notEqual(
    canonicalEncode({ 'a': 'b', 'c': 'd' }),
    canonicalEncode({ 'a:1:b': 'c:1:d' }),
  );
  assert.notEqual(canonicalEncode({ ab: 1 }), canonicalEncode({ a: 'b1' }));
});

test('M3-H2: null, undefined and the empty string are mutually distinct', () => {
  const encodings = new Set([canonicalEncode(null), canonicalEncode(undefined), canonicalEncode('')]);
  assert.equal(encodings.size, 3);
});

test('M3-H2: unsupported types fail CLOSED, never silently degraded', () => {
  assert.throws(() => canonicalEncode(() => 1), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(Symbol('x')), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(new Map([[1, 2]])), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(new Set([1])), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(new Date()), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(Number.NaN), UnsupportedCanonicalValueError);
  assert.throws(() => canonicalEncode(Number.POSITIVE_INFINITY), UnsupportedCanonicalValueError);
});

test('M3-H2: nested RSA/EC structures encode, and distinct material never collides', () => {
  const encodings = new Set([
    canonicalEncode(RSA_PRIVATE), canonicalEncode(RSA_PUBLIC),
    canonicalEncode(EC_PRIVATE), canonicalEncode(EC_PUBLIC),
  ]);
  assert.equal(encodings.size, 4, 'four distinct materials must produce four distinct encodings');
});

test('M3-H2: repeated invocation on the same value is byte-identical (deterministic)', () => {
  for (const value of [RSA_PRIVATE, EC_PRIVATE, { a: new Uint8Array([9, 9]), b: 3n, c: [1, 'x', null] }]) {
    assert.equal(canonicalEncode(value), canonicalEncode(value));
  }
});

test('M3-H2: negative and positive bigints of equal magnitude are distinct', () => {
  assert.notEqual(canonicalEncode(-5n), canonicalEncode(5n));
});

test('M3-H2: bigint magnitude is canonical -- no arbitrary zero padding (field-width normalization is the schema\'s job, not this encoder\'s)', () => {
  // 2n encodes by its own canonical magnitude; this encoder never invents a
  // width, because it cannot know whether a bigint is a P-256 scalar, an RSA
  // exponent, or a modulus. That is FieldNormalization, deliberately separate.
  assert.equal(canonicalEncode(2n), canonicalEncode(BigInt('0x2')));
  assert.notEqual(canonicalEncode(2n), canonicalEncode(32n));
});
