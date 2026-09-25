import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadFrozenMaterialPool, loadFrozenMaterialRecords, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { verifyMaterialRecord, MaterialIdentityViolationError } from '../../../../harness/phase-c/material/canonical-identity.js';
import { FrozenMaterialPool } from '../../../../harness/phase-c/material/pool.js';
import type { EcP256KeyPairMaterial, Rsa3072KeyPairMaterial, AesBaseMaterial, PssValidSignatureArtifact, GcmValidArtifact } from '../../../../harness/phase-c/material/schema.js';
import { isOnCurve, isPair, isValidScalar } from '../../../../src/contract/p256.js';

// ---------------------------------------------------------------------
// M3.2.4a-6 -- tests over the REAL frozen corpus, deliberately kept
// SEPARATE from material-pool.test.ts, which exercises the machinery with
// synthetic placeholder fixtures. Two levels, preserved on purpose:
//   Tests_schema/pool  = synthetic fixtures (machinery, corpus-independent)
//   Tests_real-material = the actual frozen corpus (this file)
// This file loads from disk in a process that did NOT generate the corpus,
// so a hash that only matched in the generating process would fail here.
// ---------------------------------------------------------------------

function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(b).toString('hex'));
}

test('frozen corpus: loads from disk and every record passes fail-closed verification', () => {
  const pool = loadFrozenMaterialPool();
  // 9: 6 original + pss-valid-signature-02 (M3.2.4b-2.8) + the two SDK-format
  // GCM artifacts (M3.2.4b-2.13).
  assert.equal(pool.materialIds().length, 9);
});

test('frozen corpus: contains exactly the pinned canonical materials -- no missing, no extra', () => {
  const pool = loadFrozenMaterialPool();
  assert.deepEqual(
    [...pool.materialIds()].sort(),
    [...Object.values(PHASE_C_MATERIAL_IDS)].sort(),
    'no missing and no extra material -- the corpus is exactly the pinned set',
  );
});

test('frozen corpus: every stored sha256 is reproduced by recomputation from the value alone', () => {
  for (const record of loadFrozenMaterialRecords()) {
    assert.doesNotThrow(() => verifyMaterialRecord(record), `${record.materialId} must reverify`);
    assert.equal(record.sha256.length, 64);
  }
});

test('frozen corpus: EC material is cryptographically valid -- V_scalar, V_curve, V_pair via M1 own p256.ts, not the generator word', () => {
  const pool = loadFrozenMaterialPool();
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const d = bytesToBigInt(ec.d);
  const q = { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) };
  assert.equal(isValidScalar(d), true);
  assert.equal(isOnCurve(q), true);
  assert.equal(isPair(d, q), true, 'Q must genuinely equal dG');
});

test('frozen corpus: field widths are exactly normalized -- the H4 defect class cannot recur here', () => {
  const pool = loadFrozenMaterialPool();
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  for (const f of ['x', 'y', 'd'] as const) assert.equal(ec[f].length, 32, `EC ${f}`);

  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  assert.equal(rsa.n.length, 384);
  assert.equal(rsa.d.length, 384);
  for (const f of ['p', 'q', 'dp', 'dq', 'qi'] as const) assert.equal(rsa[f].length, 192, `RSA ${f}`);

  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  assert.equal(aes.key.length, 32);
  assert.equal(aes.iv.length, 12);
});

test('frozen corpus: RSA components satisfy the real arithmetic relations n=pq and ed=1 mod lambda', () => {
  const pool = loadFrozenMaterialPool();
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const n = bytesToBigInt(r.n), e = bytesToBigInt(r.e), d = bytesToBigInt(r.d);
  const p = bytesToBigInt(r.p), q = bytesToBigInt(r.q);
  assert.equal(p * q, n, 'n must genuinely be p*q');

  const gcd = (a: bigint, b: bigint): bigint => (b === 0n ? a : gcd(b, a % b));
  const lambda = ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n);
  assert.equal((e * d) % lambda, 1n, 'e*d must be 1 mod lambda(n)');

  // CRT components must be consistent too, not merely present.
  assert.equal(d % (p - 1n), bytesToBigInt(r.dp), 'dp = d mod (p-1)');
  assert.equal(d % (q - 1n), bytesToBigInt(r.dq), 'dq = d mod (q-1)');
  assert.equal((bytesToBigInt(r.qi) * q) % p, 1n, 'qi = q^-1 mod p');
});

test('frozen corpus: the A0 artifacts declare their real source material, which is present', () => {
  const pool = loadFrozenMaterialPool();
  // gcmArtifact is SUPERSEDED since M3.2.4b-2.13 (raw webcrypto-output, not
  // an SDK artifact); its SDK-format replacements are the active ones.
  const gcm = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact');
  assert.equal(gcm.sourceMaterialId, PHASE_C_MATERIAL_IDS.aes);
  assert.ok(gcm.ciphertext.length > 16, 'ciphertext must carry payload plus a 16-byte tag');

  const pss = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');
  assert.equal(pss.sourceMaterialId, PHASE_C_MATERIAL_IDS.rsa);
  assert.equal(pss.signature.length, 384, 'an RSA-3072 PSS signature is exactly one modulus wide');
  assert.ok(pss.message.length > 0);
});

test('frozen corpus: A0_GCM really decrypts back to the frozen plaintext under the frozen AES material', async () => {
  const { webcrypto } = await import('node:crypto');
  const { parseAeadArtifact, TAG_LEN_BYTES } = await import('../../../../src/contract/gcm.js');
  const pool = loadFrozenMaterialPool();
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  // Since M3.2.4b-2.13 the active artifact is in SDK format
  // (version||IV||C||tag), so it must be parsed before decryption -- the
  // very step whose absence made the original artifact pass a check it
  // should not have.
  const gcm = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact');
  const parts = parseAeadArtifact(gcm.ciphertext);

  const key = await webcrypto.subtle.importKey('raw', aes.key, 'AES-GCM', false, ['decrypt']);
  const combined = new Uint8Array(parts.ciphertext.length + parts.tag.length);
  combined.set(parts.ciphertext); combined.set(parts.tag, parts.ciphertext.length);
  const params: Record<string, unknown> = { name: 'AES-GCM', iv: parts.iv, tagLength: TAG_LEN_BYTES * 8 };
  if (aes.aad !== undefined) params['additionalData'] = aes.aad;
  const out = new Uint8Array(await webcrypto.subtle.decrypt(params as never, key, combined));
  assert.deepEqual(Buffer.from(out), Buffer.from(aes.plaintext));
});

test('frozen corpus: A0_PSS really verifies under the frozen RSA material', async () => {
  const { webcrypto } = await import('node:crypto');
  const pool = loadFrozenMaterialPool();
  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const pss = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');

  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const pub = await webcrypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: b64u(rsa.n), e: b64u(rsa.e) }, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify'],
  );
  const ok = await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, pss.signature, pss.message);
  assert.equal(ok, true, 'Verify(K_pub, M, A0) == true, re-verified from the frozen bytes');
});

test('frozen corpus: a single flipped byte in any record is detected fail-closed', () => {
  const records = loadFrozenMaterialRecords();
  const target = records.find((r) => r.materialId === PHASE_C_MATERIAL_IDS.ec)!;
  const ec = target.value as EcP256KeyPairMaterial;
  const flipped = new Uint8Array(ec.d);
  flipped[0] = flipped[0]! ^ 0x01;
  const tampered = { ...target, value: { ...ec, d: flipped } };
  assert.throws(() => verifyMaterialRecord(tampered as never), MaterialIdentityViolationError);
  assert.throws(() => new FrozenMaterialPool([tampered as never]), MaterialIdentityViolationError);
});

test('frozen corpus: provenance records generation during M3, and artifacts name their source', () => {
  for (const record of loadFrozenMaterialRecords()) {
    assert.equal(record.provenance.origin, 'generated-during-m3');
    // Every record was generated during M3, but not all in the same step:
    // the corpus extension carries its own generator version, which is how
    // its later provenance stays visible rather than being flattened.
    assert.ok(['M3.2.4a-6', 'M3.2.4b-2.8', 'M3.2.4b-2.13'].includes(record.provenance.generatorVersion!));
  }
  const artifacts = loadFrozenMaterialRecords().filter((r) => r.provenance.sourceMaterialIds !== undefined);
  assert.equal(artifacts.length, 5,
    'the two original A0 artifacts, the M3.2.4b-2.8 second signature, and the two M3.2.4b-2.13 SDK-format GCM artifacts');
});
