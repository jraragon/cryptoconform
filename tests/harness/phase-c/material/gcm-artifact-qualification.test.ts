import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadFrozenMaterialPool, loadFrozenMaterialRecords, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { MaterialPoolError } from '../../../../harness/phase-c/material/pool.js';
import type { GcmValidArtifact, AesBaseMaterial } from '../../../../harness/phase-c/material/schema.js';
import {
  parseAeadArtifact, buildAeadArtifact, ARTIFACT_VERSION, TAG_LEN_BYTES, IV_LEN_BYTES,
} from '../../../../src/contract/gcm.js';

const pool = loadFrozenMaterialPool();

// ---------------------------------------------------------------------
// M3.2.4b-2.13 -- frozen-corpus QUALIFICATION defect and its remediation.
//
// Found while binding GCM x artifact-transform, before any resolver was
// written. gcm-valid-artifact-01 was frozen holding webcrypto.subtle.
// encrypt's raw output (C||tag), which decrypts correctly -- so
// M3.2.4a-6's check was TRUE -- but is not an artifact of the SDK contract
// under experiment (version||IV||C||tag). The generation was reproducible
// and its validation honest; the QUALIFICATION CRITERION was insufficient:
//     Decrypt_WebCrypto(A) = PT   =/=>   Valid_SDK(A) = true
// ---------------------------------------------------------------------

test('M3.2.4b-2.13: the defect is real -- the superseded artifact does NOT parse under the SDK contract', () => {
  const record = pool.getHistorical(PHASE_C_MATERIAL_IDS.gcmArtifact);
  const bytes = (record.value as GcmValidArtifact).ciphertext;
  assert.throws(() => parseAeadArtifact(bytes), 'it must genuinely fail, not merely be suspected');
  // 51 = |PT|(35) + |tag|(16): raw provider output, with no version byte and
  // no embedded IV.
  assert.equal(bytes.length, 51);
  assert.notEqual(bytes[0], ARTIFACT_VERSION, 'its first byte is ciphertext, not a version');
});

test('M3.2.4b-2.13: supersession left the record byte-identical -- annotation lives on the RECORD, not in `value`', () => {
  const record = pool.getHistorical(PHASE_C_MATERIAL_IDS.gcmArtifact);
  assert.equal(record.sha256, '0e0da716e1bd6aad33dd49a859427ef644f1db90cb5099c8cad42093d4ee022f',
    '(materialType, sha256) must stay stable across M3/M4 even while eligibility is corrected');
  assert.equal(record.provenance.generatorVersion, 'M3.2.4a-6', 'its original provenance is preserved');
  assert.equal(record.qualification, 'webcrypto-output');
  assert.deepEqual([...record.supersededBy!].sort(),
    [PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen, PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral].sort());
});

test('M3.2.4b-2.13: the superseded artifact is NOT selectable as active material -- fail-closed by default', () => {
  assert.throws(() => pool.get(PHASE_C_MATERIAL_IDS.gcmArtifact), MaterialPoolError);
  assert.throws(() => pool.valueOf(PHASE_C_MATERIAL_IDS.gcmArtifact, 'gcm-valid-artifact'), MaterialPoolError);
  assert.equal(pool.isSuperseded(PHASE_C_MATERIAL_IDS.gcmArtifact), true);
  // Still reachable for audit, which is the whole point of retaining it.
  assert.doesNotThrow(() => pool.getHistorical(PHASE_C_MATERIAL_IDS.gcmArtifact));
});

test('M3.2.4b-2.13: no non-superseded record is accidentally blocked', () => {
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    if (id === PHASE_C_MATERIAL_IDS.gcmArtifact) continue;
    assert.doesNotThrow(() => pool.get(id), `${id} must remain active`);
  }
});

// --- The two replacements, held to the strengthened gate -------------------

const SDK_ARTIFACTS = [
  PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral,
  PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen,
] as const;

test('M3.2.4b-2.13: both replacements parse under the SDK contract, with the expected structure', () => {
  for (const id of SDK_ARTIFACTS) {
    const a = pool.valueOf<GcmValidArtifact>(id, 'gcm-valid-artifact');
    const parts = parseAeadArtifact(a.ciphertext);
    assert.equal(parts.version, ARTIFACT_VERSION, id);
    assert.equal(parts.iv.length, IV_LEN_BYTES, id);
    assert.equal(parts.tag.length, TAG_LEN_BYTES, id);
  }
});

test('M3.2.4b-2.13: serialize(parse(A)) === A -- canonical, not merely parseable', () => {
  for (const id of SDK_ARTIFACTS) {
    const a = pool.valueOf<GcmValidArtifact>(id, 'gcm-valid-artifact');
    const p = parseAeadArtifact(a.ciphertext);
    assert.deepEqual(
      Buffer.from(buildAeadArtifact(p.iv, p.ciphertext, p.tag)),
      Buffer.from(a.ciphertext), id,
    );
  }
});

test('M3.2.4b-2.13: the embedded IV is the frozen AES IV, not an independent one', () => {
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  for (const id of SDK_ARTIFACTS) {
    const a = pool.valueOf<GcmValidArtifact>(id, 'gcm-valid-artifact');
    assert.deepEqual(Buffer.from(parseAeadArtifact(a.ciphertext).iv), Buffer.from(aes.iv), id);
  }
});

test('M3.2.4b-2.13: both replacements are cryptographically genuine -- they decrypt to their own plaintext', async () => {
  const { webcrypto } = await import('node:crypto');
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  const key = await webcrypto.subtle.importKey('raw', aes.key, 'AES-GCM', false, ['decrypt']);

  for (const id of SDK_ARTIFACTS) {
    const a = pool.valueOf<GcmValidArtifact>(id, 'gcm-valid-artifact');
    const p = parseAeadArtifact(a.ciphertext);
    const combined = new Uint8Array(p.ciphertext.length + p.tag.length);
    combined.set(p.ciphertext); combined.set(p.tag, p.ciphertext.length);
    const params: Record<string, unknown> = { name: 'AES-GCM', iv: p.iv, tagLength: TAG_LEN_BYTES * 8 };
    if (aes.aad !== undefined) params['additionalData'] = aes.aad;
    const out = new Uint8Array(await webcrypto.subtle.decrypt(params as never, key, combined));
    assert.ok(out.length > 0, `${id} must decrypt to a non-empty plaintext`);
    assert.equal(out.length, p.ciphertext.length, 'AES-GCM is a stream mode: |PT| = |C|');
  }
});

test("M3.2.4b-2.13: the swap artifact satisfies C-T-SWAP's own stated precondition |C| = TAG_LEN_BYTES", () => {
  const swap = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen, 'gcm-valid-artifact');
  assert.equal(parseAeadArtifact(swap.ciphertext).ciphertext.length, TAG_LEN_BYTES);

  // And the general one deliberately does NOT -- two artifacts are required
  // because M2's own contract demands it, not to pad the corpus.
  const general = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact');
  assert.notEqual(parseAeadArtifact(general.ciphertext).ciphertext.length, TAG_LEN_BYTES);
});

test('M3.2.4b-2.13: both replacements are qualified as SDK artifacts and declare their source material', () => {
  for (const id of SDK_ARTIFACTS) {
    const record = loadFrozenMaterialRecords().find((r) => r.materialId === id)!;
    assert.equal(record.qualification, 'sdk-aead-artifact', id);
    assert.equal(record.supersededBy, undefined, `${id} must not itself be superseded`);
    assert.equal(record.provenance.generatorVersion, 'M3.2.4b-2.13');
    assert.deepEqual(record.provenance.sourceMaterialIds, [PHASE_C_MATERIAL_IDS.aes]);
  }
});

test('M3.2.4b-2.13: qualification distinguishes the two artifact domains, machine-checkably', () => {
  const records = loadFrozenMaterialRecords().filter((r) => r.materialType === 'gcm-valid-artifact');
  assert.equal(records.length, 3, 'the superseded one plus its two replacements');
  const byQualification = new Map(records.map((r) => [r.materialId, r.qualification]));
  assert.equal(byQualification.get(PHASE_C_MATERIAL_IDS.gcmArtifact), 'webcrypto-output');
  assert.equal(byQualification.get(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral), 'sdk-aead-artifact');
  assert.equal(byQualification.get(PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen), 'sdk-aead-artifact');
  // Naming alone could not have prevented the defect: all three share the
  // same materialType, and the original id even contains the word "valid".
  assert.equal(new Set(records.map((r) => r.materialType)).size, 1);
});

test('M3.2.4b-2.13: the whole corpus still verifies fail-closed after the remediation', () => {
  assert.doesNotThrow(() => loadFrozenMaterialPool());
  assert.equal(loadFrozenMaterialRecords().length, 9);
});
