import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveHkdfAdapterFixture, HKDF_ADAPTER_MUTATION_IDS, HKDF_ADAPTER_STIMULUS_PAIRS,
  HKDF_BASELINE_EFFECTIVE_HASH, HKDF_PROFILE_HASH_LEN,
} from '../../../../harness/phase-c/fixtures/hkdf-adapter.js';
import { resolveHkdfRequestFixture } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validateHkdfRequest, HASH_LEN } from '../../../../src/contract/hkdf.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.11: 2 classes, 2 pairs, each resolving exactly once', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'hkdf' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...HKDF_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 2);
  assert.equal(HKDF_ADAPTER_STIMULUS_PAIRS.length, 2);
  for (const [m, s] of HKDF_ADAPTER_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveHkdfAdapterFixture(m, s, pool), `${m}::${s}`);
  }
});

// --- The finer distribution: same shape, same target, same baseline --------

test('M3.2.4b-2.11: both classes declare the SAME single intervention target', () => {
  const targets = HKDF_ADAPTER_MUTATION_IDS.map(
    (id) => JSON.stringify(getMutationImplementation(id).directInterventionTargets),
  );
  assert.equal(new Set(targets).size, 1, 'unlike PSS x adapter, the targets do not distinguish them');
  assert.equal(targets[0], JSON.stringify(['effectiveHash']));
});

test('M3.2.4b-2.11: both receive an IDENTICAL base fixture -- one resolver is the only correct answer', () => {
  const [a, b] = HKDF_ADAPTER_MUTATION_IDS;
  assert.deepEqual(
    resolveHkdfAdapterFixture(a!, 'default', pool),
    resolveHkdfAdapterFixture(b!, 'default', pool),
  );
});

test('M3.2.4b-2.11: the distinction lives ENTIRELY in mutate() -- different values on the same field', () => {
  const mutatedHashes = new Map<string, string>();
  for (const [m, s] of HKDF_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveHkdfAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notEqual(mutated.effectiveHash, base.effectiveHash, `${m} must change the effective hash`);
    mutatedHashes.set(m, mutated.effectiveHash);
  }
  assert.equal(new Set(mutatedHashes.values()).size, 2,
    'two experimentally distinct classes must write two distinct values');
});

test('M3.2.4b-2.11: the two mutated values are experimentally different in KIND, not merely in string', () => {
  const byId = new Map(HKDF_ADAPTER_STIMULUS_PAIRS.map(([m, s]) => {
    const base = resolveHkdfAdapterFixture(m, s, pool);
    return [m, (getMutationImplementation(m).mutate(base, s) as typeof base).effectiveHash];
  }));
  const values = [...byId.values()];
  // One is a real, implementable hash (a byte-divergence concern); the other
  // is outside the recognized set entirely (a capability/validation concern).
  const real = values.filter((v) => /^SHA-\d+$/.test(v));
  const unrecognized = values.filter((v) => v.toUpperCase().includes('UNRECOGNIZED'));
  assert.equal(real.length, 1, `expected exactly one real hash, got ${JSON.stringify(values)}`);
  assert.equal(unrecognized.length, 1, `expected exactly one unrecognized algorithm, got ${JSON.stringify(values)}`);
});

// --- Baseline derivation ---------------------------------------------------

test('M3.2.4b-2.11: the baseline effectiveHash follows from the frozen profile, not from a sibling operation', () => {
  const f = resolveHkdfAdapterFixture(HKDF_ADAPTER_MUTATION_IDS[0]!, 'default', pool);
  assert.equal(f.effectiveHash, HKDF_BASELINE_EFFECTIVE_HASH);
  assert.equal(f.effectiveHash, 'SHA-256');
  // HKDF exports no hash-name constant (unlike OAEP_HASH / PSS_HASH); it
  // fixes the algorithm structurally via HASH_LEN, so the baseline is
  // anchored to that invariant.
  assert.equal(HKDF_PROFILE_HASH_LEN, HASH_LEN);
  assert.equal(HASH_LEN, 32, "SHA-256's own output length");
});

test('M3.2.4b-2.11: the baseline is the CORRECT hash -- neither mutation starts from an already-wrong value', () => {
  for (const [m, s] of HKDF_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveHkdfAdapterFixture(m, s, pool);
    assert.equal(base.effectiveHash, 'SHA-256');
  }
});

// --- Composition -----------------------------------------------------------

test('M3.2.4b-2.11: the invocation COMPOSES the same request the request group serves', () => {
  const f = resolveHkdfAdapterFixture(HKDF_ADAPTER_MUTATION_IDS[0]!, 'default', pool);
  assert.doesNotThrow(() => validateHkdfRequest(f.request));

  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'hkdf' && e.mechanism === 'request-transform' && e.stimulusInstances.length === 1,
  )!.mutationId;
  assert.deepEqual(f.request, resolveHkdfRequestFixture(carrierId, 'default', pool),
    'one canonical definition of an unmutated HKDF request, not two');
});

test('M3.2.4b-2.11: NEITHER mutation touches the embedded request -- confirmed, not taken from the comment', () => {
  for (const [m, s] of HKDF_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveHkdfAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.deepEqual(mutated.request, base.request, `${m} must leave the request untouched`);
  }
});

// --- H1 / H3 ---------------------------------------------------------------

test('M3.2.4b-2.11: no frozen material id is referenced -- the request arrives via composition', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-adapter.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.11 (H3): no mutate() call, and both pairs are genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of HKDF_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveHkdfAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

// --- Fail-closed and derivation --------------------------------------------

test('M3.2.4b-2.11: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  assert.throws(() => resolveHkdfAdapterFixture(HKDF_ADAPTER_MUTATION_IDS[0]!, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveHkdfAdapterFixture('GCM-ERROR-MISCLASSIFICATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveHkdfAdapterFixture('HKDF-INFO-TAMPER', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveHkdfAdapterFixture('HKDF-CAPABILITY-BOUNDARY-MISMATCH', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.11: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/hkdf-adapter.ts', import.meta.url), 'utf8');
  for (const id of HKDF_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
