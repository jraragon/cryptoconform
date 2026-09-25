import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateOaepEncryptRequest,
  validateOaepDecryptRequest,
  MODULUS_BITS,
  MAX_MESSAGE_LEN_BYTES,
  OAEP_HASH,
  K_BYTES,
} from '../../src/contract/oaep.js';
import { SdkContractError } from '../../src/contract/errors.js';

// Traceability: exercises oaep.key, oaep.modulus, oaep.message, oaep.hash,
// oaep.mgfCoupling, oaep.label (Accept_C for encrypt/decrypt), independent
// of any adapter -- sec:contract-traceability convention.

const PUB = { role: 'public' as const, modulusBits: MODULUS_BITS };
const PRIV = { role: 'private' as const, modulusBits: MODULUS_BITS };

test('oaep.key: valid encrypt request (public key) is accepted', () => {
  assert.doesNotThrow(() =>
    validateOaepEncryptRequest({
      key: PUB,
      plaintext: new Uint8Array(0),
      label: undefined,
      hash: OAEP_HASH,
      mgfHash: OAEP_HASH,
    }),
  );
});

test('oaep.key: encrypt with a private key rejected as invalid_key (not invalid_parameter)', () => {
  assert.throws(
    () =>
      validateOaepEncryptRequest({
        key: PRIV,
        plaintext: new Uint8Array(0),
        label: undefined,
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['oaep.key']);
      return true;
    },
  );
});

test('oaep.key: decrypt with a public key rejected as invalid_key', () => {
  assert.throws(
    () =>
      validateOaepDecryptRequest({
        key: PUB,
        ciphertext: new Uint8Array(K_BYTES),
        label: undefined,
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['oaep.key']);
      return true;
    },
  );
});

test('oaep.modulus: modulus != 3072 bits rejected as invalid_parameter (encrypt and decrypt)', () => {
  for (const badModulus of [2048, 4096]) {
    assert.throws(
      () =>
        validateOaepEncryptRequest({
          key: { role: 'public', modulusBits: badModulus },
          plaintext: new Uint8Array(0),
          label: undefined,
          hash: OAEP_HASH,
          mgfHash: OAEP_HASH,
        }),
      (err: unknown) => {
        assert.ok(err instanceof SdkContractError);
        assert.equal(err.errorClass, 'invalid_parameter');
        assert.deepEqual(err.clauseIds, ['oaep.modulus']);
        return true;
      },
    );
  }
});

test('oaep.hash: non-SHA-256 hash rejected as invalid_parameter, not unsupported (D-031)', () => {
  assert.throws(
    () =>
      validateOaepEncryptRequest({
        key: PUB,
        plaintext: new Uint8Array(0),
        label: undefined,
        hash: 'SHA-512',
        mgfHash: 'SHA-512',
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['oaep.hash']);
      return true;
    },
  );
});

test('oaep.mgfCoupling: decoupled hash/MGF1 (Bouncy-Castle-valid, non-portable) rejected as invalid_parameter, not unsupported (D-028)', () => {
  assert.throws(
    () =>
      validateOaepEncryptRequest({
        key: PUB,
        plaintext: new Uint8Array(0),
        label: undefined,
        hash: 'SHA-256',
        mgfHash: 'SHA-1', // BC alone can realize this; still non-portable
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['oaep.mgfCoupling']);
      return true;
    },
  );
});

test('oaep.label: non-empty label rejected as invalid_parameter (D-030), encrypt and decrypt', () => {
  assert.throws(
    () =>
      validateOaepEncryptRequest({
        key: PUB,
        plaintext: new Uint8Array(0),
        label: new Uint8Array([0x01]),
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['oaep.label']);
      return true;
    },
  );
  assert.throws(
    () =>
      validateOaepDecryptRequest({
        key: PRIV,
        ciphertext: new Uint8Array(K_BYTES),
        label: new Uint8Array([0x01]),
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['oaep.label']);
      return true;
    },
  );
});

test('oaep.label: absent and explicit empty are both accepted (L_absent === L_empty, all three backends)', () => {
  assert.doesNotThrow(() =>
    validateOaepEncryptRequest({ key: PUB, plaintext: new Uint8Array(0), label: undefined, hash: OAEP_HASH, mgfHash: OAEP_HASH }),
  );
  assert.doesNotThrow(() =>
    validateOaepEncryptRequest({
      key: PUB,
      plaintext: new Uint8Array(0),
      label: new Uint8Array(0),
      hash: OAEP_HASH,
      mgfHash: OAEP_HASH,
    }),
  );
});

test('oaep.message: mLen=318 (exact bound) accepted, mLen=319 rejected as invalid_parameter (D-032)', () => {
  assert.doesNotThrow(() =>
    validateOaepEncryptRequest({
      key: PUB,
      plaintext: new Uint8Array(MAX_MESSAGE_LEN_BYTES),
      label: undefined,
      hash: OAEP_HASH,
      mgfHash: OAEP_HASH,
    }),
  );
  assert.throws(
    () =>
      validateOaepEncryptRequest({
        key: PUB,
        plaintext: new Uint8Array(MAX_MESSAGE_LEN_BYTES + 1),
        label: undefined,
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['oaep.message']);
      return true;
    },
  );
});

// --- The two "red comment" invariants from this session's design review ---

test('RED COMMENT 1: validateOaepDecryptRequest does NOT check ciphertext length -- a wrong-length ciphertext must NOT be rejected here as invalid_parameter (v0.6 D-034: it collapses to decryption_error at the backend call, not at Accept_C)', () => {
  // A ciphertext of the WRONG length (not 384 bytes) must still pass
  // Accept_C cleanly -- if this test ever fails, someone has added a
  // ciphertext-length check to validateOaepDecryptRequest, which would be
  // a direct contradiction of v0.6's frozen decision.
  assert.doesNotThrow(() =>
    validateOaepDecryptRequest({
      key: PRIV,
      ciphertext: new Uint8Array(10), // deliberately NOT 384 bytes
      label: undefined,
      hash: OAEP_HASH,
      mgfHash: OAEP_HASH,
    }),
  );
  assert.doesNotThrow(() =>
    validateOaepDecryptRequest({
      key: PRIV,
      ciphertext: new Uint8Array(0), // even empty -- still not Accept_C's job to reject this
      label: undefined,
      hash: OAEP_HASH,
      mgfHash: OAEP_HASH,
    }),
  );
});
