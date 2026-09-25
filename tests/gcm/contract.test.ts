import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateGcmEncryptRequest,
  validateGcmDecryptRequest,
  buildAeadArtifact,
  parseAeadArtifact,
  KEY_LEN_BYTES,
  IV_LEN_BYTES,
  TAG_LEN_BYTES,
  TAG_LEN_BITS,
  ARTIFACT_VERSION,
  MIN_ARTIFACT_LEN_BYTES,
} from '../../src/contract/gcm.js';
import { SdkContractError } from '../../src/contract/errors.js';

// Traceability: this file exercises gcm.key, gcm.iv, gcm.tagLength, gcm.plaintext,
// gcm.aad (Accept_C for encrypt/decrypt) and gcm.artifact (AEADArtifact codec),
// independent of any adapter -- these are the contract-layer obligations every
// backend adapter must delegate to, per sec:contract-traceability's convention.

test('gcm.key/gcm.iv/gcm.tagLength: valid encrypt request is accepted', () => {
  assert.doesNotThrow(() =>
    validateGcmEncryptRequest({
      key: new Uint8Array(KEY_LEN_BYTES),
      plaintext: new Uint8Array(0),
      aad: undefined,
      iv: new Uint8Array(IV_LEN_BYTES),
      tagLengthBits: TAG_LEN_BITS,
    }),
  );
});

test('gcm.key: key length !== 256 bits rejected as invalid_parameter', () => {
  for (const badLen of [16, 24, 31, 33, 0]) {
    assert.throws(
      () =>
        validateGcmEncryptRequest({
          key: new Uint8Array(badLen),
          plaintext: new Uint8Array(0),
          aad: undefined,
          iv: new Uint8Array(IV_LEN_BYTES),
          tagLengthBits: TAG_LEN_BITS,
        }),
      (err: unknown) => {
        assert.ok(err instanceof SdkContractError);
        assert.equal(err.errorClass, 'invalid_parameter');
        assert.deepEqual(err.clauseIds, ['gcm.key']);
        return true;
      },
    );
  }
});

test('gcm.iv: IV length !== 96 bits rejected as invalid_parameter', () => {
  for (const badLen of [0, 8, 11, 13, 16]) {
    assert.throws(
      () =>
        validateGcmEncryptRequest({
          key: new Uint8Array(KEY_LEN_BYTES),
          plaintext: new Uint8Array(0),
          aad: undefined,
          iv: new Uint8Array(badLen),
          tagLengthBits: TAG_LEN_BITS,
        }),
      (err: unknown) => {
        assert.ok(err instanceof SdkContractError);
        assert.equal(err.errorClass, 'invalid_parameter');
        assert.deepEqual(err.clauseIds, ['gcm.iv']);
        return true;
      },
    );
  }
});

test('gcm.tagLength: t=80 (provider-valid on Bouncy Castle, non-portable) rejected as invalid_parameter, per D-068-style disambiguation rule', () => {
  assert.throws(
    () =>
      validateGcmEncryptRequest({
        key: new Uint8Array(KEY_LEN_BYTES),
        plaintext: new Uint8Array(0),
        aad: undefined,
        iv: new Uint8Array(IV_LEN_BYTES),
        tagLengthBits: 80,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['gcm.tagLength']);
      return true;
    },
  );
});

test('gcm.tagLength: t=0 (accepted by Crypto++\'s generic API path with NO native floor) rejected as invalid_parameter -- the single most adapter-critical bound in this operation', () => {
  assert.throws(
    () =>
      validateGcmEncryptRequest({
        key: new Uint8Array(KEY_LEN_BYTES),
        plaintext: new Uint8Array(0),
        aad: undefined,
        iv: new Uint8Array(IV_LEN_BYTES),
        tagLengthBits: 0,
      }),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['gcm.tagLength']);
      return true;
    },
  );
});

test('gcm.aad: absent (undefined) and explicit empty are both accepted (AAD_absent === AAD_empty, unlike hkdf.salt)', () => {
  const base = {
    key: new Uint8Array(KEY_LEN_BYTES),
    plaintext: new Uint8Array(0),
    iv: new Uint8Array(IV_LEN_BYTES),
    tagLengthBits: TAG_LEN_BITS,
  };
  assert.doesNotThrow(() => validateGcmEncryptRequest({ ...base, aad: undefined }));
  assert.doesNotThrow(() => validateGcmEncryptRequest({ ...base, aad: new Uint8Array(0) }));
});

test('gcm.key (decrypt path): valid decrypt request is accepted at the Accept_C stage', () => {
  const artifact = buildAeadArtifact(new Uint8Array(IV_LEN_BYTES), new Uint8Array(4), new Uint8Array(TAG_LEN_BYTES));
  assert.doesNotThrow(() =>
    validateGcmDecryptRequest({ key: new Uint8Array(KEY_LEN_BYTES), artifact, aad: undefined }),
  );
});

test('gcm.artifact: encode/decode round-trip preserves IV, ciphertext, and tag exactly', () => {
  const iv = new Uint8Array(IV_LEN_BYTES).map((_, i) => i);
  const ciphertext = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
  const tag = new Uint8Array(TAG_LEN_BYTES).map((_, i) => 0xa0 + i);

  const artifact = buildAeadArtifact(iv, ciphertext, tag);
  assert.equal(artifact.length, 1 + IV_LEN_BYTES + ciphertext.length + TAG_LEN_BYTES);
  assert.equal(artifact[0], ARTIFACT_VERSION);

  const parsed = parseAeadArtifact(artifact);
  assert.equal(parsed.version, ARTIFACT_VERSION);
  assert.deepEqual(parsed.iv, iv);
  assert.deepEqual(parsed.ciphertext, ciphertext);
  assert.deepEqual(parsed.tag, tag);
});

test('gcm.artifact: empty-plaintext artifact (minimum length, 29 bytes) round-trips correctly', () => {
  const iv = new Uint8Array(IV_LEN_BYTES);
  const tag = new Uint8Array(TAG_LEN_BYTES);
  const artifact = buildAeadArtifact(iv, new Uint8Array(0), tag);
  assert.equal(artifact.length, MIN_ARTIFACT_LEN_BYTES);

  const parsed = parseAeadArtifact(artifact);
  assert.equal(parsed.ciphertext.length, 0);
  assert.deepEqual(parsed.iv, iv);
  assert.deepEqual(parsed.tag, tag);
});

test('gcm.artifact: below-minimum-length artifact rejected as malformed_artifact', () => {
  for (const len of [0, 1, 12, 28]) {
    assert.throws(
      () => parseAeadArtifact(new Uint8Array(len)),
      (err: unknown) => {
        assert.ok(err instanceof SdkContractError);
        assert.equal(err.errorClass, 'malformed_artifact');
        assert.deepEqual(err.clauseIds, ['gcm.artifact']);
        return true;
      },
    );
  }
});

test('gcm.artifact: wrong version byte rejected as malformed_artifact', () => {
  const artifact = buildAeadArtifact(new Uint8Array(IV_LEN_BYTES), new Uint8Array(0), new Uint8Array(TAG_LEN_BYTES));
  artifact[0] = ARTIFACT_VERSION + 1; // corrupt the version byte
  assert.throws(
    () => parseAeadArtifact(artifact),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      assert.deepEqual(err.clauseIds, ['gcm.artifact']);
      return true;
    },
  );
});
