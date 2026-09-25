import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gcmWebCryptoEncrypt, gcmWebCryptoDecrypt } from '../../src/adapters/webcrypto/gcm.js';
import { fromHex, toHex } from '../../src/evidence/record.js';
import { KEY_LEN_BYTES, IV_LEN_BYTES, TAG_LEN_BITS, buildAeadArtifact } from '../../src/contract/gcm.js';

// Traceability: exercises all 12 gcm.* clauses (sec:contract-traceability
// convention) against the WebCrypto realization. Source of the KAT below:
// NIST CAVS 14.0 GCM Encrypt (keysize 256) vectors, Keylen=256/IVlen=96/
// PTlen=128/AADlen=160/Taglen=128, Count=0 -- INDEPENDENTLY RE-VERIFIED in
// this session by running it through Node's actual webcrypto.subtle.encrypt
// and confirming byte-for-byte agreement with the published CT/Tag, not
// merely transcribed from a secondary source.
const KAT = {
  keyHex: '83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a',
  ivHex: '0b459724904e010a46901cf3',
  ptHex: '33d893a2114ce06fc15d55e454cf90c3',
  aadHex: '794a14ccd178c8ebfd1379dc704c5e208f9d8424',
  expectedCtHex: 'cc66bee423e3fcd4c0865715e9586696',
  expectedTagHex: '0fb291bd3dba94a1dfd8b286cfb97ac5',
};

// --- 1. Known vector: exact C and T (R_byte) ---

test('gcm.ciphertext/gcm.artifact: NIST KAT produces exact C and T, and the correct AEADArtifact', async () => {
  const record = await gcmWebCryptoEncrypt({
    key: fromHex(KAT.keyHex),
    plaintext: fromHex(KAT.ptHex),
    aad: fromHex(KAT.aadHex),
    iv: fromHex(KAT.ivHex),
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(record.outcome.kind, 'accept');
  if (record.outcome.kind !== 'accept') return;
  const artifact = fromHex(record.outcome.artifactHex);
  // version(1) || IV(12) || C(16) || T(16)
  assert.equal(artifact.length, 1 + 12 + 16 + 16);
  const ct = toHex(artifact.slice(13, 13 + 16));
  const tag = toHex(artifact.slice(13 + 16));
  assert.equal(ct, KAT.expectedCtHex);
  assert.equal(tag, KAT.expectedTagHex);
  assert.deepEqual(
    Array.from(record.clauseIds).sort(),
    ['gcm.aad', 'gcm.artifact', 'gcm.ciphertext', 'gcm.iv', 'gcm.key', 'gcm.plaintext', 'gcm.tagLength'].sort(),
  );
});

test('gcm.ciphertext: equal K, IV, AAD, M produce identical ciphertext bytes across two independent calls', async () => {
  const req = {
    key: fromHex(KAT.keyHex),
    plaintext: fromHex(KAT.ptHex),
    aad: fromHex(KAT.aadHex),
    iv: fromHex(KAT.ivHex),
    tagLengthBits: TAG_LEN_BITS,
  };
  const r1 = await gcmWebCryptoEncrypt(req);
  const r2 = await gcmWebCryptoEncrypt(req);
  assert.equal(r1.outcome.kind, 'accept');
  assert.equal(r2.outcome.kind, 'accept');
  if (r1.outcome.kind === 'accept' && r2.outcome.kind === 'accept') {
    assert.equal(r1.outcome.artifactHex, r2.outcome.artifactHex);
  }
});

// --- 2. Encrypt -> decrypt local round-trip ---

test('gcm.authentication: encrypt -> decrypt round-trip recovers the exact plaintext', async () => {
  const key = fromHex(KAT.keyHex);
  const encRecord = await gcmWebCryptoEncrypt({
    key,
    plaintext: fromHex(KAT.ptHex),
    aad: fromHex(KAT.aadHex),
    iv: fromHex(KAT.ivHex),
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(encRecord.outcome.kind, 'accept');
  if (encRecord.outcome.kind !== 'accept') return;

  const decRecord = await gcmWebCryptoDecrypt({
    key,
    artifact: fromHex(encRecord.outcome.artifactHex),
    aad: fromHex(KAT.aadHex),
  });
  assert.equal(decRecord.outcome.kind, 'accept');
  if (decRecord.outcome.kind === 'accept') {
    assert.equal(decRecord.outcome.plaintextHex, KAT.ptHex);
  }
  assert.deepEqual(decRecord.clauseIds, ['gcm.key', 'gcm.aad', 'gcm.artifact', 'gcm.authentication']);
});

// --- 3. AAD absent === AAD empty === explicit-length-0 (contract, unlike hkdf.salt) ---

test('gcm.aad: AAD absent and AAD empty produce byte-identical artifacts, and both decrypt correctly under either AAD shape', async () => {
  const key = fromHex(KAT.keyHex);
  const iv = fromHex(KAT.ivHex);
  const plaintext = fromHex(KAT.ptHex);

  const absentRecord = await gcmWebCryptoEncrypt({ key, plaintext, aad: undefined, iv, tagLengthBits: TAG_LEN_BITS });
  const emptyRecord = await gcmWebCryptoEncrypt({
    key,
    plaintext,
    aad: new Uint8Array(0),
    iv,
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(absentRecord.outcome.kind, 'accept');
  assert.equal(emptyRecord.outcome.kind, 'accept');
  if (absentRecord.outcome.kind === 'accept' && emptyRecord.outcome.kind === 'accept') {
    assert.equal(absentRecord.outcome.artifactHex, emptyRecord.outcome.artifactHex);

    // Cross-check: an artifact encrypted with AAD absent must decrypt
    // correctly when AAD is supplied as explicit-empty at decrypt time, and
    // vice versa -- confirming AAD_absent === AAD_empty holds through the
    // full encrypt/decrypt round trip, not just at the encrypt call.
    const decAbsentWithEmpty = await gcmWebCryptoDecrypt({
      key,
      artifact: fromHex(absentRecord.outcome.artifactHex),
      aad: new Uint8Array(0),
    });
    const decEmptyWithAbsent = await gcmWebCryptoDecrypt({
      key,
      artifact: fromHex(emptyRecord.outcome.artifactHex),
      aad: undefined,
    });
    assert.equal(decAbsentWithEmpty.outcome.kind, 'accept');
    assert.equal(decEmptyWithAbsent.outcome.kind, 'accept');
  }
});

// --- 4. Tamper -> authentication_failure (T, C, AAD) ---

async function encryptKat() {
  const record = await gcmWebCryptoEncrypt({
    key: fromHex(KAT.keyHex),
    plaintext: fromHex(KAT.ptHex),
    aad: fromHex(KAT.aadHex),
    iv: fromHex(KAT.ivHex),
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(record.outcome.kind, 'accept');
  if (record.outcome.kind !== 'accept') throw new Error('unreachable');
  return fromHex(record.outcome.artifactHex);
}

test('gcm.authentication: tampering the tag (last byte) is rejected as authentication_failure', async () => {
  const artifact = await encryptKat();
  const tampered = artifact.slice();
  tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
  const record = await gcmWebCryptoDecrypt({ key: fromHex(KAT.keyHex), artifact: tampered, aad: fromHex(KAT.aadHex) });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'authentication_failure');
  }
  assert.deepEqual(record.clauseIds, ['gcm.authentication']);
});

test('gcm.authentication: tampering the ciphertext (first byte after IV) is rejected as authentication_failure', async () => {
  const artifact = await encryptKat();
  const tampered = artifact.slice();
  tampered[13] = (tampered[13] ?? 0) ^ 0xff; // byte 0 = version, bytes 1-12 = IV, byte 13 = first ciphertext byte
  const record = await gcmWebCryptoDecrypt({ key: fromHex(KAT.keyHex), artifact: tampered, aad: fromHex(KAT.aadHex) });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'authentication_failure');
  }
});

test('gcm.authentication: tampering the AAD at decrypt time is rejected as authentication_failure', async () => {
  const artifact = await encryptKat();
  const tamperedAad = fromHex(KAT.aadHex);
  tamperedAad[0] = (tamperedAad[0] ?? 0) ^ 0xff;
  const record = await gcmWebCryptoDecrypt({ key: fromHex(KAT.keyHex), artifact, aad: tamperedAad });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'authentication_failure');
  }
});

test('gcm.authentication: tampering the IV at decrypt time (via a hand-rebuilt artifact) is rejected as authentication_failure', async () => {
  const artifact = await encryptKat();
  const tampered = artifact.slice();
  tampered[1] = (tampered[1] ?? 0) ^ 0xff; // first IV byte
  const record = await gcmWebCryptoDecrypt({ key: fromHex(KAT.keyHex), artifact: tampered, aad: fromHex(KAT.aadHex) });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'authentication_failure');
  }
});

// --- 5. Pre-subtle.* rejection: key/IV/tagLength boundaries, malformed artifact ---

test('gcm.key: encrypt with key length !== 256 bits rejected as invalid_parameter, before any subtle.* call', async () => {
  const record = await gcmWebCryptoEncrypt({
    key: new Uint8Array(16), // AES-128 length, syntactically a valid AES key, just not our portable profile
    plaintext: fromHex(KAT.ptHex),
    aad: undefined,
    iv: fromHex(KAT.ivHex),
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['gcm.key']);
});

test('gcm.iv: encrypt with IV length !== 96 bits rejected as invalid_parameter', async () => {
  const record = await gcmWebCryptoEncrypt({
    key: new Uint8Array(KEY_LEN_BYTES),
    plaintext: fromHex(KAT.ptHex),
    aad: undefined,
    iv: new Uint8Array(16), // a length WebCrypto's own API would happily accept -- must be rejected by us first
    tagLengthBits: TAG_LEN_BITS,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['gcm.iv']);
});

test('gcm.tagLength: encrypt with tagLength=80 (WebCrypto-valid, non-portable) rejected as invalid_parameter, not unsupported', async () => {
  const record = await gcmWebCryptoEncrypt({
    key: new Uint8Array(KEY_LEN_BYTES),
    plaintext: fromHex(KAT.ptHex),
    aad: undefined,
    iv: new Uint8Array(IV_LEN_BYTES),
    tagLengthBits: 80,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter'); // D-068-style disambiguation, NOT 'unsupported'
  }
  assert.deepEqual(record.clauseIds, ['gcm.tagLength']);
});

test('gcm.key: decrypt with key length !== 256 bits rejected as invalid_parameter, before parsing the artifact', async () => {
  const artifact = buildAeadArtifact(new Uint8Array(IV_LEN_BYTES), new Uint8Array(4), new Uint8Array(16));
  const record = await gcmWebCryptoDecrypt({ key: new Uint8Array(24), artifact, aad: undefined });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['gcm.key']);
});

test('gcm.artifact: decrypt with a structurally malformed artifact (too short) rejected as malformed_artifact, not authentication_failure', async () => {
  const record = await gcmWebCryptoDecrypt({
    key: new Uint8Array(KEY_LEN_BYTES),
    artifact: new Uint8Array(10), // below the 29-byte minimum
    aad: undefined,
  });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'malformed_artifact');
  }
  assert.deepEqual(record.clauseIds, ['gcm.artifact']);
});

test('gcm.aad: decrypt with a well-formed artifact but non-byte-sequence aad is rejected as invalid_parameter, AFTER the artifact structure check', async () => {
  const artifact = buildAeadArtifact(new Uint8Array(IV_LEN_BYTES), new Uint8Array(4), new Uint8Array(16));
  // @ts-expect-error deliberately passing a non-Uint8Array to exercise the runtime guard
  const record = await gcmWebCryptoDecrypt({ key: new Uint8Array(KEY_LEN_BYTES), artifact, aad: 'not-a-byte-sequence' });
  assert.equal(record.outcome.kind, 'reject');
  if (record.outcome.kind === 'reject') {
    assert.equal(record.outcome.errorClass, 'invalid_parameter');
  }
  assert.deepEqual(record.clauseIds, ['gcm.aad']);
});
