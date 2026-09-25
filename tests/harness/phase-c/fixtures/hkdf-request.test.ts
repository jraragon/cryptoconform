import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveHkdfRequestFixture, HKDF_REQUEST_MUTATION_IDS, HKDF_REQUEST_STIMULUS_PAIRS,
  HKDF_BASELINE_L, FixtureResolutionError,
} from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { HkdfBaseMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validateHkdfRequest, MIN_L, MAX_L } from '../../../../src/contract/hkdf.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.1: HKDFRequestMutationIDs == ResolvedHKDFRequestMutationIDs', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'hkdf' && e.mechanism === 'request-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...HKDF_REQUEST_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 5);
});

test('M3.2.4b-2.1: HKDFRequestStimulusPairs == ResolvedHKDFRequestStimulusPairs (6 pairs, not 5)', () => {
  assert.equal(HKDF_REQUEST_STIMULUS_PAIRS.length, 6,
    'HKDF-LENGTH-BOUNDARY-CROSSING carries two stimuli, so the group has 6 pairs across 5 classes');
  for (const [mutationId, stimulusInstanceId] of HKDF_REQUEST_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveHkdfRequestFixture(mutationId, stimulusInstanceId, pool));
  }
});

test('M3.2.4b-2.1 (H5): every registered pair resolves exactly once -- no duplicates in the derived set', () => {
  const keys = HKDF_REQUEST_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length);
});

// --- H1 / H2: uses only the frozen pool, invents no bytes ------------------

test('M3.2.4b-2.1 (H1,H2): every byte field comes verbatim from hkdf-phasec-primary-01', () => {
  const material = pool.valueOf<HkdfBaseMaterial>(PHASE_C_MATERIAL_IDS.hkdf, 'hkdf-base-material');
  for (const [mutationId, stimulusInstanceId] of HKDF_REQUEST_STIMULUS_PAIRS) {
    const f = resolveHkdfRequestFixture(mutationId, stimulusInstanceId, pool);
    assert.deepEqual(Buffer.from(f.ikm), Buffer.from(material.ikm), 'ikm');
    assert.deepEqual(Buffer.from(f.salt!), Buffer.from(material.salt), 'salt');
    assert.deepEqual(Buffer.from(f.info), Buffer.from(material.info), 'info');
  }
});

test('M3.2.4b-2.1 (H2): byte fields are COPIES, so a downstream mutate() cannot reach back into the pool', () => {
  const material = pool.valueOf<HkdfBaseMaterial>(PHASE_C_MATERIAL_IDS.hkdf, 'hkdf-base-material');
  const f = resolveHkdfRequestFixture('HKDF-INFO-TAMPER', 'default', pool);
  assert.notEqual(f.ikm, material.ikm, 'must not alias the pool own array');
  f.ikm[0] = f.ikm[0]! ^ 0xff;
  const again = pool.valueOf<HkdfBaseMaterial>(PHASE_C_MATERIAL_IDS.hkdf, 'hkdf-base-material');
  assert.deepEqual(Buffer.from(again.ikm), Buffer.from(material.ikm), 'the pool material is unchanged');
});

test('M3.2.4b-2.1: the resolver source references no material id other than the HKDF one (H1)', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-request.ts', import.meta.url), 'utf8');
  for (const [key, id] of Object.entries(PHASE_C_MATERIAL_IDS)) {
    if (key === 'hkdf') continue;
    assert.ok(!src.includes(id), `resolver must not reference '${id}'`);
  }
});

// --- H3: never mutates -----------------------------------------------------

test('M3.2.4b-2.1 (H3): the resolver never calls mutate() -- confirmed structurally', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-request.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden), 'no mutate() invocation may appear in a fixture resolver');
});

test('M3.2.4b-2.1 (H3): the resolved fixture is the UNMUTATED baseline -- mutate() genuinely changes it', () => {
  const base = resolveHkdfRequestFixture('HKDF-INFO-TAMPER', 'default', pool);
  const mutated = getMutationImplementation('HKDF-INFO-TAMPER').mutate(base, 'default') as typeof base;
  assert.notDeepEqual(Buffer.from(mutated.info), Buffer.from(base.info),
    'if these matched, the resolver would already be delivering mutated input');
});

// --- H4: exactly the real TFixture ----------------------------------------

test('M3.2.4b-2.1 (H4): every resolved fixture passes the real frozen Accept_C (validateHkdfRequest)', () => {
  for (const [mutationId, stimulusInstanceId] of HKDF_REQUEST_STIMULUS_PAIRS) {
    const f = resolveHkdfRequestFixture(mutationId, stimulusInstanceId, pool);
    assert.doesNotThrow(() => validateHkdfRequest(f),
      `${mutationId}::${stimulusInstanceId} must be contractually valid BEFORE mutation`);
  }
});

test('M3.2.4b-2.1 (H4): the baseline L sits strictly inside the portable-profile bound (D-068)', () => {
  assert.ok(Number.isInteger(HKDF_BASELINE_L));
  assert.ok(HKDF_BASELINE_L >= MIN_L && HKDF_BASELINE_L <= MAX_L);
  // Strictly inside, so that a boundary mutation genuinely crosses a boundary.
  assert.ok(HKDF_BASELINE_L > MIN_L && HKDF_BASELINE_L < MAX_L);
});

// --- Multi-stimulus finding ------------------------------------------------

test('M3.2.4b-2.1: for this group the base fixture does NOT vary by stimulus -- the difference IS the mutation', () => {
  const l0 = resolveHkdfRequestFixture('HKDF-LENGTH-BOUNDARY-CROSSING', 'L=0', pool);
  const l8161 = resolveHkdfRequestFixture('HKDF-LENGTH-BOUNDARY-CROSSING', 'L=8161', pool);
  assert.deepEqual(l0, l8161, 'identical base fixture: stimulus differentiation lives inside mutate()');

  // And mutate() does genuinely differentiate them, so nothing is lost.
  const impl = getMutationImplementation('HKDF-LENGTH-BOUNDARY-CROSSING');
  const m0 = impl.mutate(l0, 'L=0') as typeof l0;
  const m1 = impl.mutate(l8161, 'L=8161') as typeof l8161;
  assert.equal(m0.length, 0);
  assert.equal(m1.length, MAX_L + 1);
  assert.notEqual(m0.length, m1.length);
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.1: an unregistered (mutationId, stimulusInstanceId) pair fails closed', () => {
  assert.throws(() => resolveHkdfRequestFixture('HKDF-INFO-TAMPER', 'no-such-stimulus', pool), FixtureResolutionError);
  assert.throws(() => resolveHkdfRequestFixture('GCM-IV-REUSE', 'default', pool), FixtureResolutionError);
  // A class from the right operation but the wrong mechanism must not resolve here.
  assert.throws(() => resolveHkdfRequestFixture('HKDF-HASH-MISMATCH', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.1: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-request.ts', import.meta.url), 'utf8');
  for (const id of HKDF_REQUEST_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear in the resolver; found '${id}'`);
  }
});
