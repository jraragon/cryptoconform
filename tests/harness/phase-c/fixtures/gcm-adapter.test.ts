import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveGcmAdapterFixture, GCM_ADAPTER_MUTATION_IDS, GCM_ADAPTER_STIMULUS_PAIRS,
  GCM_BASELINE_TRIGGERING_CONDITION, GCM_BASELINE_DECLARED_ERROR_CLASS, GCM_ARTIFACT_FLOOR_BYTES,
} from '../../../../harness/phase-c/fixtures/gcm-adapter.js';
import { resolveGcmRequestFixture } from '../../../../harness/phase-c/fixtures/gcm-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { MIN_ARTIFACT_LEN_BYTES } from '../../../../src/contract/gcm.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.3: GCMAdapterMutationIDs == ResolvedGCMAdapterMutationIDs', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'gcm' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...GCM_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 1);
});

test('M3.2.4b-2.3: every registered pair resolves exactly once (H5)', () => {
  assert.equal(GCM_ADAPTER_STIMULUS_PAIRS.length, 1);
  for (const [m, s] of GCM_ADAPTER_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveGcmAdapterFixture(m, s, pool));
  }
  const keys = GCM_ADAPTER_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length);
});

// --- The new case: no pool material at all ---------------------------------

test('M3.2.4b-2.3: this group needs NO frozen material -- the resolver references no material id whatsoever', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-adapter.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `an adapter-transform fixture must reference no material; found '${id}'`);
  }
});

test('M3.2.4b-2.3: the resolved fixture carries no byte material -- it is adapter configuration, not cryptographic input', () => {
  const [m, s] = GCM_ADAPTER_STIMULUS_PAIRS[0]!;
  const f = resolveGcmAdapterFixture(m, s, pool);
  for (const value of Object.values(f)) {
    assert.equal(typeof value, 'string', 'every field of an error-mapping intervention is a string');
    assert.ok(!(value instanceof Uint8Array));
  }
});

// --- AdapterFixture != RequestFixture --------------------------------------

test('M3.2.4b-2.3: AdapterFixture != RequestFixture -- structurally disjoint, sharing no field', () => {
  const [m, s] = GCM_ADAPTER_STIMULUS_PAIRS[0]!;
  const adapterFixture = resolveGcmAdapterFixture(m, s, pool);
  const requestFixture = resolveGcmRequestFixture('GCM-AAD-IGNORED', 'default', pool);

  const adapterKeys = new Set(Object.keys(adapterFixture));
  const requestKeys = new Set(Object.keys(requestFixture));
  const shared = [...adapterKeys].filter((k) => requestKeys.has(k));
  assert.deepEqual(shared, [], 'the two mechanisms intervene on different experimental state; no field may be shared');

  // And neither is derivable from the other by accident.
  assert.notDeepEqual(adapterFixture, requestFixture);
});

test('M3.2.4b-2.3: the adapter resolver does not delegate to the request resolver', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['resolveGcm', 'RequestFixture'].join('');
  assert.ok(!src.includes(forbidden), 'reusing the request resolver would erase the mechanism distinction');
});

// --- H3 / H4 ---------------------------------------------------------------

test('M3.2.4b-2.3 (H3): the resolver never calls mutate(), and its output is genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  const [m, s] = GCM_ADAPTER_STIMULUS_PAIRS[0]!;
  const base = resolveGcmAdapterFixture(m, s, pool);
  const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
  assert.notEqual(mutated.declaredErrorClass, base.declaredErrorClass, 'the mutation must genuinely change the declared class');
  assert.equal(mutated.triggeringCondition, base.triggeringCondition, 'only the declared class is a direct intervention target');
});

test('M3.2.4b-2.3 (H4): the baseline declares the CONTRACTUALLY CORRECT class for its triggering condition', () => {
  // parseAeadArtifact rejects an artifact below the floor with
  // 'malformed_artifact'; that is what a correct adapter must report, so it
  // is what the unmutated baseline declares.
  assert.equal(GCM_BASELINE_DECLARED_ERROR_CLASS, 'malformed_artifact');
  assert.equal(GCM_BASELINE_TRIGGERING_CONDITION, 'undersized-ciphertext');
  assert.equal(GCM_ARTIFACT_FLOOR_BYTES, MIN_ARTIFACT_LEN_BYTES);
});

test('M3.2.4b-2.3: the mutation departs from correct behaviour, rather than swapping one wrong answer for another', () => {
  const [m, s] = GCM_ADAPTER_STIMULUS_PAIRS[0]!;
  const base = resolveGcmAdapterFixture(m, s, pool);
  const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
  // The baseline is neither of the two classes mutate() toggles between, so
  // the mutated value is necessarily a misclassification of a real condition.
  assert.notEqual(base.declaredErrorClass, 'authentication_failure');
  assert.notEqual(base.declaredErrorClass, 'invalid_parameter');
  assert.ok(['authentication_failure', 'invalid_parameter'].includes(mutated.declaredErrorClass));
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.3: right-operation/wrong-mechanism and wrong-operation ids both fail closed', () => {
  assert.throws(() => resolveGcmAdapterFixture('GCM-AAD-IGNORED', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmAdapterFixture('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmAdapterFixture('HKDF-HASH-MISMATCH', 'default', pool), FixtureResolutionError);
  const [m] = GCM_ADAPTER_STIMULUS_PAIRS[0]!;
  assert.throws(() => resolveGcmAdapterFixture(m, 'no-such-stimulus', pool), FixtureResolutionError);
});

test('M3.2.4b-2.3: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-adapter.ts', import.meta.url), 'utf8');
  for (const id of GCM_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
