import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveGcmRequestFixture, GCM_REQUEST_MUTATION_IDS, GCM_REQUEST_STIMULUS_PAIRS,
  GCM_BASELINE_TAG_LENGTH_BITS,
} from '../../../../harness/phase-c/fixtures/gcm-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { AesBaseMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validateGcmEncryptRequest, TAG_LEN_BYTES, KEY_LEN_BYTES, IV_LEN_BYTES } from '../../../../src/contract/gcm.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.2: GCMRequestMutationIDs == ResolvedGCMRequestMutationIDs (8 classes)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'gcm' && e.mechanism === 'request-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...GCM_REQUEST_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 8);
});

test('M3.2.4b-2.2: GCMRequestStimulusPairs == ResolvedGCMRequestStimulusPairs (10 pairs, not 8)', () => {
  assert.equal(GCM_REQUEST_STIMULUS_PAIRS.length, 10,
    'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS carries three stimuli');
  for (const [mutationId, stimulusInstanceId] of GCM_REQUEST_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveGcmRequestFixture(mutationId, stimulusInstanceId, pool));
  }
  const keys = GCM_REQUEST_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length, 'H5: each pair resolves exactly once');
});

// --- H1 / H2 ---------------------------------------------------------------

test('M3.2.4b-2.2 (H1,H2): every byte field comes verbatim from aes-phasec-primary-01', () => {
  const material = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  for (const [mutationId, stimulusInstanceId] of GCM_REQUEST_STIMULUS_PAIRS) {
    const f = resolveGcmRequestFixture(mutationId, stimulusInstanceId, pool);
    assert.deepEqual(Buffer.from(f.key), Buffer.from(material.key), 'key');
    assert.deepEqual(Buffer.from(f.iv), Buffer.from(material.iv), 'iv');
    assert.deepEqual(Buffer.from(f.plaintext), Buffer.from(material.plaintext), 'plaintext');
    assert.deepEqual(Buffer.from(f.aad!), Buffer.from(material.aad!), 'aad');
  }
});

test('M3.2.4b-2.2 (H2): byte fields are COPIES, so a downstream mutate() cannot reach into the pool', () => {
  const material = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  const f = resolveGcmRequestFixture('GCM-AAD-IGNORED', 'default', pool);
  assert.notEqual(f.key, material.key);
  f.key[0] = f.key[0]! ^ 0xff;
  const again = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  assert.deepEqual(Buffer.from(again.key), Buffer.from(material.key), 'the pool material is unchanged');
});

test('M3.2.4b-2.2 (H1): the resolver references no material id other than the AES one -- A0_GCM belongs to artifact-transform', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-request.ts', import.meta.url), 'utf8');
  for (const [key, id] of Object.entries(PHASE_C_MATERIAL_IDS)) {
    if (key === 'aes') continue;
    assert.ok(!src.includes(id), `resolver must not reference '${id}'`);
  }
});

// --- H3 --------------------------------------------------------------------

test('M3.2.4b-2.2 (H3): the resolver never calls mutate() -- confirmed structurally', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-request.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));
});

test('M3.2.4b-2.2 (H3): the resolved fixture is the UNMUTATED baseline for every class in the group', () => {
  for (const [mutationId, stimulusInstanceId] of GCM_REQUEST_STIMULUS_PAIRS) {
    const base = resolveGcmRequestFixture(mutationId, stimulusInstanceId, pool);
    const mutated = getMutationImplementation(mutationId).mutate(base, stimulusInstanceId) as typeof base;
    assert.notDeepEqual(mutated, base, `${mutationId}::${stimulusInstanceId} must genuinely change under mutation`);
  }
});

// --- H4 --------------------------------------------------------------------

test('M3.2.4b-2.2 (H4): every resolved fixture passes the real frozen Accept_C (validateGcmEncryptRequest)', () => {
  for (const [mutationId, stimulusInstanceId] of GCM_REQUEST_STIMULUS_PAIRS) {
    const f = resolveGcmRequestFixture(mutationId, stimulusInstanceId, pool);
    assert.doesNotThrow(() => validateGcmEncryptRequest(f),
      `${mutationId}::${stimulusInstanceId} must be contractually valid BEFORE mutation`);
  }
});

test('M3.2.4b-2.2 (H4): the baseline matches the frozen portable profile exactly', () => {
  const f = resolveGcmRequestFixture('GCM-AAD-IGNORED', 'default', pool);
  assert.equal(f.key.length, KEY_LEN_BYTES);
  assert.equal(f.iv.length, IV_LEN_BYTES);
  assert.equal(GCM_BASELINE_TAG_LENGTH_BITS, TAG_LEN_BYTES * 8);
  assert.equal(f.tagLengthBits, GCM_BASELINE_TAG_LENGTH_BITS);
});

// --- The two stimulus-independence checks required after the HKDF finding --

test('M3.2.4b-2.2: stimulus ignored by resolver <=> baseFixture is stimulus-independent', () => {
  // The one multi-stimulus class in this group: all three base fixtures
  // must be identical, because the differentiation lives in mutate().
  const tag80 = resolveGcmRequestFixture('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', pool);
  const tag16 = resolveGcmRequestFixture('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-16', pool);
  const tag0 = resolveGcmRequestFixture('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-0', pool);
  assert.deepEqual(tag80, tag16);
  assert.deepEqual(tag16, tag0);
});

test('M3.2.4b-2.2: mutate(F0,s1) != mutate(F0,s2) -- the experimental differentiation is preserved, just in the correct layer', () => {
  const impl = getMutationImplementation('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS');
  const base = resolveGcmRequestFixture('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', pool);
  const m80 = impl.mutate(base, 'tagLength-80') as typeof base;
  const m16 = impl.mutate(base, 'tagLength-below-floor-16') as typeof base;
  const m0 = impl.mutate(base, 'tagLength-below-floor-0') as typeof base;
  assert.equal(new Set([m80.tagLengthBits, m16.tagLengthBits, m0.tagLengthBits]).size, 3,
    'three stimuli must yield three distinct mutated tag lengths');
  assert.notEqual(m80.tagLengthBits, base.tagLengthBits);
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.2: unregistered pairs, wrong operation, and right-operation/wrong-mechanism all fail closed', () => {
  assert.throws(() => resolveGcmRequestFixture('GCM-AAD-IGNORED', 'no-such-stimulus', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmRequestFixture('HKDF-INFO-TAMPER', 'default', pool), FixtureResolutionError);
  // artifact-transform and capability-transform classes of the SAME operation
  assert.throws(() => resolveGcmRequestFixture('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmRequestFixture('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.2: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-request.ts', import.meta.url), 'utf8');
  for (const id of GCM_REQUEST_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
