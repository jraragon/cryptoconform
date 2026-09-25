import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveRsaSerAdapterFixture, RSA_SER_ADAPTER_MUTATION_IDS, RSA_SER_ADAPTER_STIMULUS_PAIRS,
  RSA_SER_BASELINE_DECLARED_ERROR_CLASS, RSA_SER_BASELINE_TRIGGERING_CONDITION,
  RSA_SER_UNTOGGLED_ERROR_CLASS,
} from '../../../../harness/phase-c/fixtures/rsa-ser-adapter.js';
import { resolveGcmAdapterFixture } from '../../../../harness/phase-c/fixtures/gcm-adapter.js';
import { resolvePssErrorMappingFixture } from '../../../../harness/phase-c/fixtures/pss-adapter.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';

const pool = loadFrozenMaterialPool();
const onlyId = () => RSA_SER_ADAPTER_MUTATION_IDS[0]!;

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.10: the minimal group -- 1 class, 1 pair, resolving exactly once', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'rsa-ser' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...RSA_SER_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 1);
  assert.equal(RSA_SER_ADAPTER_STIMULUS_PAIRS.length, 1);
  assert.doesNotThrow(() => resolveRsaSerAdapterFixture(onlyId(), 'default', pool));
});

// --- Shape recurrence across four operations -------------------------------

test('M3.2.4b-2.10: the error-mapping shape recurs for a FOURTH operation, unchanged', () => {
  const rsaSer = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  const gcm = resolveGcmAdapterFixture('GCM-ERROR-MISCLASSIFICATION', 'default', pool);
  const pss = resolvePssErrorMappingFixture('PSS-ERROR-MISCLASSIFICATION', 'default', pool);
  const shape = (o: object) => Object.keys(o).sort();
  assert.deepEqual(shape(rsaSer), shape(gcm));
  assert.deepEqual(shape(rsaSer), shape(pss));
  assert.deepEqual(shape(rsaSer), ['declaredErrorClass', 'triggeringCondition']);
});

test('M3.2.4b-2.10: same shape, DIFFERENT content -- the four are not interchangeable fixtures', () => {
  const rsaSer = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  const gcm = resolveGcmAdapterFixture('GCM-ERROR-MISCLASSIFICATION', 'default', pool);
  const pss = resolvePssErrorMappingFixture('PSS-ERROR-MISCLASSIFICATION', 'default', pool);
  // Each operation's own contract dictates its own correct class, so a
  // shared shape must not become a shared value.
  assert.equal(new Set([rsaSer.triggeringCondition, gcm.triggeringCondition, pss.triggeringCondition]).size, 3);
  assert.notDeepEqual(rsaSer, gcm);
  assert.notDeepEqual(rsaSer, pss);
});

// --- The baseline, and the choice between two available arguments ----------

test('M3.2.4b-2.10: the baseline declares the class the frozen contract raises for its condition', () => {
  const f = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  assert.equal(f.declaredErrorClass, RSA_SER_BASELINE_DECLARED_ERROR_CLASS);
  assert.equal(f.declaredErrorClass, 'invalid_key', 'checkPublicValidity failing raises invalid_key');
  assert.equal(f.triggeringCondition, RSA_SER_BASELINE_TRIGGERING_CONDITION);
});

test('M3.2.4b-2.10: a THIRD class exists that this mutation never toggles -- the choice of argument was deliberate', () => {
  // Both argument shapes were available here (unlike GCM, where only the
  // untoggled-third option existed, or OAEP, where only the toggled-pair
  // one did). Recording the untoggled class keeps that choice visible.
  assert.equal(RSA_SER_UNTOGGLED_ERROR_CLASS, 'invalid_parameter');
  const base = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  const mutated = getMutationImplementation(onlyId()).mutate(base, 'default') as typeof base;
  assert.notEqual(base.declaredErrorClass, RSA_SER_UNTOGGLED_ERROR_CLASS);
  assert.notEqual(mutated.declaredErrorClass, RSA_SER_UNTOGGLED_ERROR_CLASS);
});

test('M3.2.4b-2.10: the mutation collapses two distinct contract STAGES -- a math failure reported as a byte failure', () => {
  const base = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  const mutated = getMutationImplementation(onlyId()).mutate(base, 'default') as typeof base;
  assert.equal(base.declaredErrorClass, 'invalid_key');
  assert.equal(mutated.declaredErrorClass, 'malformed_artifact',
    'asserting the bytes were bad when they had already parsed successfully');
  assert.equal(mutated.triggeringCondition, base.triggeringCondition, 'only the declared class is intervened on');
});

test('M3.2.4b-2.10: both toggled classes are genuinely raised by the frozen contract, at different stages', async () => {
  const { readFileSync } = await import('node:fs');
  const contract = readFileSync(new URL('../../../../src/contract/rsa-ser.ts', import.meta.url), 'utf8');
  // DER/container stage.
  assert.ok(contract.includes("'malformed_artifact'"));
  assert.ok(contract.includes('rsa-ser.der-syntax') || contract.includes('rsa-ser.container'));
  // Mathematical-validity stage, which is only reached after parsing succeeds.
  assert.ok(contract.includes("'invalid_key'"));
  assert.ok(contract.includes('rsa-ser.public-validity'));
});

// --- H1 / H3 ---------------------------------------------------------------

test('M3.2.4b-2.10: no frozen material is referenced', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-adapter.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.10 (H3): no mutate() call, and the fixture is genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  const base = resolveRsaSerAdapterFixture(onlyId(), 'default', pool);
  const mutated = getMutationImplementation(onlyId()).mutate(base, 'default') as typeof base;
  assert.notDeepEqual(mutated, base);
});

// --- Fail-closed and derivation --------------------------------------------

test('M3.2.4b-2.10: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  assert.throws(() => resolveRsaSerAdapterFixture(onlyId(), 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaSerAdapterFixture('GCM-ERROR-MISCLASSIFICATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaSerAdapterFixture('RSA-SER-PROVIDER-CAPABILITY-MISREPORT', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.10: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-adapter.ts', import.meta.url), 'utf8');
  for (const id of RSA_SER_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
