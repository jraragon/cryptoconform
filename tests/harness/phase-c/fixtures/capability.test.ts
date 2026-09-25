import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveCapabilityFixture, providerSupportCapabilityId,
  CAPABILITY_MUTATION_IDS, CAPABILITY_STIMULUS_PAIRS, CAPABILITY_BASELINE_SUPPORT,
} from '../../../../harness/phase-c/fixtures/capability.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { CHROMIUM_DECLARATIONS } from '../../../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../../../manifests/providers/bc.js';
import { PORTABLE_DECLARATIONS } from '../../../../manifests/portable/profile.js';

const pool = loadFrozenMaterialPool();
const ALL_OPERATIONS = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'] as const;

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.9: six capability-transform classes, one per operation, 6 pairs', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.mechanism === 'capability-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...CAPABILITY_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 6);
  assert.equal(CAPABILITY_STIMULUS_PAIRS.length, 6);

  const operations = MUTATION_REGISTRY
    .filter((e) => e.mechanism === 'capability-transform')
    .map((e) => e.operation).sort();
  assert.deepEqual(operations, [...ALL_OPERATIONS].sort(), 'exactly one class per operation');
});

// --- Universality demonstrated PER OPERATION, not in aggregate -------------

test('M3.2.4b-2.9: EACH of the six operations resolves individually, with a correct, distinct capabilityId', () => {
  for (const [mutationId, stimulusInstanceId] of CAPABILITY_STIMULUS_PAIRS) {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const f = resolveCapabilityFixture(mutationId, stimulusInstanceId, pool);
    assert.equal(f.capabilityId, `${entry.operation}.provider.support`,
      `${entry.operation}: capabilityId must be derived from its own manifest entry`);
    assert.equal(f.kind, 'provider-support');
    assert.equal(f.support, CAPABILITY_BASELINE_SUPPORT);
  }
  // Six operations must yield six DISTINCT ids -- a single shared id would
  // mean the resolver had collapsed the operations.
  const ids = CAPABILITY_STIMULUS_PAIRS.map(([m, s]) => resolveCapabilityFixture(m, s, pool).capabilityId);
  assert.equal(new Set(ids).size, 6);
});

test('M3.2.4b-2.9: EACH of the six mutations genuinely changes its own resolved fixture', () => {
  for (const [mutationId, stimulusInstanceId] of CAPABILITY_STIMULUS_PAIRS) {
    const base = resolveCapabilityFixture(mutationId, stimulusInstanceId, pool);
    const mutated = getMutationImplementation(mutationId).mutate(base, stimulusInstanceId) as typeof base;
    assert.equal(mutated.support, 'unsupported', `${mutationId}: the declaration must be flipped`);
    assert.notEqual(mutated.support, base.support);
    assert.equal(mutated.capabilityId, base.capabilityId, 'only `support` is a direct intervention target');
    assert.equal(mutated.kind, base.kind);
  }
});

test('M3.2.4b-2.9: all six declare the same intervention target -- the semantic basis of the shared resolver', () => {
  const targets = CAPABILITY_MUTATION_IDS.map(
    (id) => JSON.stringify(getMutationImplementation(id).directInterventionTargets),
  );
  assert.equal(new Set(targets).size, 1);
  assert.equal(targets[0], JSON.stringify(['support']));
});

// --- Gamma_0 heterogeneity: real, but inert here ---------------------------

test('M3.2.4b-2.9: the six Gamma_0 are HETEROGENEOUS -- universality does not rest on them', () => {
  const gammas = CAPABILITY_MUTATION_IDS.map(
    (id) => JSON.stringify(MUTATION_REGISTRY.find((e) => e.mutationId === id)!.gamma0),
  );
  assert.ok(new Set(gammas).size > 1, 'they genuinely differ across operations');
  // Gamma_0 discriminates BETWEEN shapes elsewhere; with a single shape
  // there is nothing to discriminate, so the difference is inert here.
});

// --- The manifest derivation -----------------------------------------------

test('M3.2.4b-2.9: capabilityId is DERIVED from the frozen manifest, exactly one per operation', () => {
  for (const op of ALL_OPERATIONS) {
    const matches = CHROMIUM_DECLARATIONS.filter(
      (d) => d.kind === 'provider-support' && d.capabilityId === `${op}.provider.support`,
    );
    assert.equal(matches.length, 1, `${op} must declare exactly one provider-support capability under that id`);
    assert.equal(providerSupportCapabilityId(op), `${op}.provider.support`);
  }
});

test('M3.2.4b-2.9: the three pinned providers AGREE on the declared support -- so the baseline needs no provider parameter', () => {
  for (const op of ALL_OPERATIONS) {
    const values = [CHROMIUM_DECLARATIONS, CRYPTOPP_DECLARATIONS, BC_DECLARATIONS].map((decls) => {
      const d = decls.find((x) => x.capabilityId === `${op}.provider.support`);
      assert.ok(d, `${op} missing from a provider manifest`);
      return JSON.stringify((d as unknown as { support?: unknown }).support);
    });
    assert.equal(new Set(values).size, 1, `${op}: providers disagree, so the baseline would be provider-dependent`);
    assert.equal(values[0], JSON.stringify(CAPABILITY_BASELINE_SUPPORT));
  }
});

test('M3.2.4b-2.9: the PORTABLE profile could not have supplied these -- it covers only three of the six operations', () => {
  const covered = new Set(PORTABLE_DECLARATIONS.map((d) => d.capabilityId.split('.')[0]));
  for (const op of ['gcm', 'oaep', 'pss']) assert.ok(covered.has(op), `${op} expected in the portable profile`);
  for (const op of ['hkdf', 'rsa-ser', 'ec-ser']) {
    assert.ok(!covered.has(op),
      `${op} has a capability-transform class but no portable capability -- reaching for the portable profile first would have failed here`);
  }
});

test('M3.2.4b-2.9: an operation with no provider-support declaration fails closed', () => {
  assert.throws(() => providerSupportCapabilityId('no-such-operation' as never), FixtureResolutionError);
});

// --- Parameterization, not branching ---------------------------------------

test('M3.2.4b-2.9: the operation enters as DATA -- no per-operation branch anywhere in the resolver', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/capability.ts', import.meta.url), 'utf8');
  for (const op of ALL_OPERATIONS) {
    assert.ok(!src.includes(`=== '${op}'`), `found a comparison against operation '${op}'`);
    assert.ok(!src.includes(`case '${op}'`), `found a case branch for operation '${op}'`);
  }
  assert.ok(!src.includes('switch'), 'no switch statement may appear');
  for (const id of CAPABILITY_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});

// --- H1 / H3 ---------------------------------------------------------------

test('M3.2.4b-2.9: no frozen material is referenced -- a capability declaration is not cryptographic material', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/capability.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.9 (H3): the resolver never calls mutate()', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/capability.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.9: unregistered stimuli and non-capability classes fail closed', () => {
  assert.throws(() => resolveCapabilityFixture(CAPABILITY_MUTATION_IDS[0]!, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveCapabilityFixture('HKDF-INFO-TAMPER', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveCapabilityFixture('PSS-RNG-INTERFACE-LEAK', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveCapabilityFixture('PSS-VERIFICATION-FALSE-ACCEPT', 'default', pool), FixtureResolutionError);
});
