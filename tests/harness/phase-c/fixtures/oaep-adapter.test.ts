import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveOaepAdapterFixture, resolveOaepErrorMappingFixture, resolveOaepAdapterInvocationFixture,
  isOaepAdapterInvocationClass, OAEP_ADAPTER_MUTATION_IDS, OAEP_ADAPTER_STIMULUS_PAIRS,
  OAEP_BASELINE_DECLARED_ERROR_CLASS, OAEP_BASELINE_TRIGGERING_CONDITION,
  OAEP_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED,
} from '../../../../harness/phase-c/fixtures/oaep-adapter.js';
import { resolveOaepEncryptRequestFixture } from '../../../../harness/phase-c/fixtures/oaep-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validateOaepEncryptRequest } from '../../../../src/contract/oaep.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.5: OAEPAdapterMutationIDs == ResolvedOAEPAdapterMutationIDs (2 classes, 2 pairs)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'oaep' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...OAEP_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 2);
  assert.equal(OAEP_ADAPTER_STIMULUS_PAIRS.length, 2);
  for (const [m, s] of OAEP_ADAPTER_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveOaepAdapterFixture(m, s, pool), `${m}::${s}`);
  }
});

test('M3.2.4b-2.5: GCM_adapter shape =/=> OAEP_adapter shape -- this group is TWO shapes, one per class', () => {
  const invocation = OAEP_ADAPTER_MUTATION_IDS.filter((id) => isOaepAdapterInvocationClass(id));
  assert.equal(invocation.length, 1);
  assert.equal(OAEP_ADAPTER_MUTATION_IDS.length - invocation.length, 1);
});

// --- Finding 1: composition, not disjointness ------------------------------

test('M3.2.4b-2.5: OaepAdapterInvocation COMPOSES the request fixture -- delegation is required here, unlike GCM', () => {
  const invocationId = OAEP_ADAPTER_MUTATION_IDS.find((id) => isOaepAdapterInvocationClass(id))!;
  const f = resolveOaepAdapterInvocationFixture(invocationId, 'default', pool);

  // The embedded object really is a full, contractually valid encrypt request.
  assert.doesNotThrow(() => validateOaepEncryptRequest(f.request));
  assert.equal(typeof f.externalRandomnessProvided, 'boolean');

  // And it is byte-for-byte the SAME baseline the request-transform group
  // serves: one definition of an unmutated OAEP encrypt request, not two.
  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'oaep' && e.mechanism === 'request-transform' && e.stimulusInstances.length === 1,
  )!.mutationId;
  assert.deepEqual(f.request, resolveOaepEncryptRequestFixture(carrierId, 'default', pool));
});

test('M3.2.4b-2.5: the error-mapping shape remains disjoint from the request, as in GCM', () => {
  const errorId = OAEP_ADAPTER_MUTATION_IDS.find((id) => !isOaepAdapterInvocationClass(id))!;
  const f = resolveOaepErrorMappingFixture(errorId, 'default', pool);
  const request = resolveOaepEncryptRequestFixture('OAEP-MESSAGE-NORMALIZATION', 'default', pool);
  const shared = Object.keys(f).filter((k) => Object.keys(request).includes(k));
  assert.deepEqual(shared, [], 'no field is shared between the error-mapping fixture and a request');
  for (const v of Object.values(f)) assert.equal(typeof v, 'string');
});

// --- Finding 2: the baseline is the COLLAPSED anti-oracle class ------------

test('M3.2.4b-2.5: the baseline declares the generic collapsed class the frozen contract requires (D-034)', () => {
  const errorId = OAEP_ADAPTER_MUTATION_IDS.find((id) => !isOaepAdapterInvocationClass(id))!;
  const f = resolveOaepErrorMappingFixture(errorId, 'default', pool);
  assert.equal(f.declaredErrorClass, OAEP_BASELINE_DECLARED_ERROR_CLASS);
  assert.equal(f.declaredErrorClass, 'decryption_error');
  assert.equal(f.triggeringCondition, OAEP_BASELINE_TRIGGERING_CONDITION);
});

test('M3.2.4b-2.5: the mutation makes the class MORE SPECIFIC -- the oracle leak, inverse of the GCM argument', () => {
  const errorId = OAEP_ADAPTER_MUTATION_IDS.find((id) => !isOaepAdapterInvocationClass(id))!;
  const base = resolveOaepErrorMappingFixture(errorId, 'default', pool);
  const mutated = getMutationImplementation(errorId).mutate(base, 'default') as typeof base;

  // Unlike GCM, the correct baseline IS one of the two toggled values, and
  // the mutation moves AWAY from it toward a narrower class.
  assert.equal(base.declaredErrorClass, 'decryption_error');
  assert.equal(mutated.declaredErrorClass, 'invalid_key');
  assert.notEqual(mutated.declaredErrorClass, base.declaredErrorClass);
  assert.equal(mutated.triggeringCondition, base.triggeringCondition, 'only the declared class is intervened on');
});

test('M3.2.4b-2.5: the randomness baseline provides NO external randomness, and the mutation exposes it', () => {
  const invocationId = OAEP_ADAPTER_MUTATION_IDS.find((id) => isOaepAdapterInvocationClass(id))!;
  const base = resolveOaepAdapterInvocationFixture(invocationId, 'default', pool);
  assert.equal(base.externalRandomnessProvided, OAEP_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED);
  assert.equal(base.externalRandomnessProvided, false, 'the portable request carries no such control');

  const mutated = getMutationImplementation(invocationId).mutate(base, 'default') as typeof base;
  assert.equal(mutated.externalRandomnessProvided, true);
  assert.deepEqual(mutated.request, base.request, 'the embedded request is not a direct intervention target');
});

// --- H1 / H3 ---------------------------------------------------------------

test('M3.2.4b-2.5: no frozen material is referenced anywhere in this group', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-adapter.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.5 (H3): no mutate() call, and both pairs are genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of OAEP_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveOaepAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

test('M3.2.4b-2.5: shape selection is derived from the frozen Gamma_0, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-adapter.ts', import.meta.url), 'utf8');
  for (const id of OAEP_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
  // And the derivation genuinely matches the registry.
  for (const id of OAEP_ADAPTER_MUTATION_IDS) {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === id)!;
    const byGamma0 = entry.gamma0.some((c) => c.includes('randomness'));
    assert.equal(isOaepAdapterInvocationClass(id), byGamma0);
  }
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.5: the two typed resolvers refuse each other classes', () => {
  const invocationId = OAEP_ADAPTER_MUTATION_IDS.find((id) => isOaepAdapterInvocationClass(id))!;
  const errorId = OAEP_ADAPTER_MUTATION_IDS.find((id) => !isOaepAdapterInvocationClass(id))!;
  assert.throws(() => resolveOaepErrorMappingFixture(invocationId, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepAdapterInvocationFixture(errorId, 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.5: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  const anyId = OAEP_ADAPTER_MUTATION_IDS[0]!;
  assert.throws(() => resolveOaepAdapterFixture(anyId, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepAdapterFixture('GCM-ERROR-MISCLASSIFICATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepAdapterFixture('OAEP-MESSAGE-NORMALIZATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepAdapterFixture('OAEP-PROVIDER-CAPABILITY-MISREPORT', 'default', pool), FixtureResolutionError);
});
