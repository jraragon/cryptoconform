import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validatePssSignRequest,
  validatePssVerifyRequest,
  MODULUS_BITS,
  SALT_LEN_BYTES,
  PSS_HASH,
  K_BYTES,
} from '../../src/contract/pss.js';
import { SdkContractError } from '../../src/contract/errors.js';

// Traceability: exercises pss.key, pss.modulus, pss.hash, pss.mgfCoupling,
// pss.saltLength, pss.message (Accept_C for sign/verify), independent of
// any adapter -- sec:contract-traceability convention.

const PUB = { role: 'public' as const, modulusBits: MODULUS_BITS };
const PRIV = { role: 'private' as const, modulusBits: MODULUS_BITS };

test('pss.key: valid sign request (private key) is accepted', () => {
  assert.doesNotThrow(() =>
    validatePssSignRequest({
      key: PRIV,
      message: new Uint8Array(0),
      hash: PSS_HASH,
      mgfHash: PSS_HASH,
      saltLengthBytes: SALT_LEN_BYTES,
    }),
  );
});

test('pss.key: sign with a public key rejected as invalid_key (not invalid_parameter)', () => {
  assert.throws(
    () =>
      validatePssSignRequest({
        key: PUB,
        message: new Uint8Array(0),
        hash: PSS_HASH,
        mgfHash: PSS_HASH,
        saltLengthBytes: SALT_LEN_BYTES,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['pss.key']);
      return true;
    },
  );
});

test('pss.key: verify with a private key rejected as invalid_key', () => {
  assert.throws(
    () =>
      validatePssVerifyRequest({
        key: PRIV,
        message: new Uint8Array(0),
        signature: new Uint8Array(K_BYTES),
        hash: PSS_HASH,
        mgfHash: PSS_HASH,
        saltLengthBytes: SALT_LEN_BYTES,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['pss.key']);
      return true;
    },
  );
});

test('pss.modulus: modulus != 3072 bits rejected as invalid_parameter (sign and verify)', () => {
  for (const badModulus of [2048, 4096]) {
    assert.throws(
      () =>
        validatePssSignRequest({
          key: { role: 'private', modulusBits: badModulus },
          message: new Uint8Array(0),
          hash: PSS_HASH,
          mgfHash: PSS_HASH,
          saltLengthBytes: SALT_LEN_BYTES,
        }),
      (err: unknown) => {
        assert.ok(err instanceof SdkContractError);
        assert.equal(err.errorClass, 'invalid_parameter');
        assert.deepEqual(err.clauseIds, ['pss.modulus']);
        return true;
      },
    );
  }
});

test('pss.hash: non-SHA-256 hash rejected as invalid_parameter, not unsupported (D-043)', () => {
  assert.throws(
    () =>
      validatePssSignRequest({
        key: PRIV,
        message: new Uint8Array(0),
        hash: 'SHA-512',
        mgfHash: 'SHA-512',
        saltLengthBytes: SALT_LEN_BYTES,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['pss.hash']);
      return true;
    },
  );
});

test('pss.mgfCoupling: decoupled hash/MGF1 (Bouncy-Castle-valid, non-portable) rejected as invalid_parameter, not unsupported (D-040)', () => {
  assert.throws(
    () =>
      validatePssSignRequest({
        key: PRIV,
        message: new Uint8Array(0),
        hash: 'SHA-256',
        mgfHash: 'SHA-1', // BC alone can realize this; still non-portable
        saltLengthBytes: SALT_LEN_BYTES,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['pss.mgfCoupling']);
      return true;
    },
  );
});

test('pss.saltLength: saltLength != 32 bytes rejected as invalid_parameter (D-041), e.g. WebCrypto-valid sLen=20', () => {
  assert.throws(
    () =>
      validatePssSignRequest({
        key: PRIV,
        message: new Uint8Array(0),
        hash: PSS_HASH,
        mgfHash: PSS_HASH,
        saltLengthBytes: 20, // WebCrypto natively permits many values here; still non-portable
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['pss.saltLength']);
      return true;
    },
  );
});

test('pss.message: NO portable length boundary exists -- arbitrarily long messages are accepted at Accept_C (unlike oaep.message)', () => {
  // Deliberately large (64 KiB) -- there is no D-032-style mLen_max for PSS
  // (v0.6, sec:pss note 3: EMSA-PSS bounds the ENCODED message via
  // modulus/hash/salt, never the original message length itself).
  assert.doesNotThrow(() =>
    validatePssSignRequest({
      key: PRIV,
      message: new Uint8Array(65536),
      hash: PSS_HASH,
      mgfHash: PSS_HASH,
      saltLengthBytes: SALT_LEN_BYTES,
    }),
  );
});

// --- The "red comment" invariant from this session's design review ---

test("RED COMMENT: validatePssVerifyRequest does NOT check signature length -- a wrong-length signature must NOT be rejected here as invalid_parameter (v0.6 D-046: |sigma|!=k is part of Verify's own {true,false} result domain, not an SDK error at all)", () => {
  // A signature of the WRONG length (not 384 bytes) must still pass
  // Accept_C cleanly -- if this test ever fails, someone has added a
  // signature-length check to validatePssVerifyRequest, directly
  // contradicting v0.6's corrected D-046 decision (the mirror image of the
  // OAEP-ciphertext-length mistake this project already made and fixed once).
  assert.doesNotThrow(() =>
    validatePssVerifyRequest({
      key: PUB,
      message: new Uint8Array(0),
      signature: new Uint8Array(10), // deliberately NOT 384 bytes
      hash: PSS_HASH,
      mgfHash: PSS_HASH,
      saltLengthBytes: SALT_LEN_BYTES,
    }),
  );
  assert.doesNotThrow(() =>
    validatePssVerifyRequest({
      key: PUB,
      message: new Uint8Array(0),
      signature: new Uint8Array(0), // even empty
      hash: PSS_HASH,
      mgfHash: PSS_HASH,
      saltLengthBytes: SALT_LEN_BYTES,
    }),
  );
});
