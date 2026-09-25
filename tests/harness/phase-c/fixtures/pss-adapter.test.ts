import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolvePssAdapterFixture, resolvePssAdapterInvocationFixture, resolvePssErrorMappingFixture,
  isPssErrorMappingClass, PSS_ADAPTER_MUTATION_IDS, PSS_ADAPTER_STIMULUS_PAIRS,
  PSS_BASELINE_DECLARED_ERROR_CLASS, PSS_BASELINE_TRIGGERING_CONDITION,
  PSS_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED, PSS_BASELINE_EXPLICIT_SALT_BYTES_PROVIDED,
} from '../../../../harness/phase-c/fixtures/pss-adapter.js';
import {
  resolvePssSignRequestFixture, isPssKeyRoleBypass, isPssVerifyRequestClass,
} from '../../../../harness/phase-c/fixtures/pss-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validatePssSignRequest } from '../../../../src/contract/pss.js';

const pool = loadFrozenMaterialPool();
const invocationIds = () => PSS_ADAPTER_MUTATION_IDS.filter((id) => !isPssErrorMappingClass(id));
const errorId = () => PSS_ADAPTER_MUTATION_IDS.find(isPssErrorMappingClass)!;

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.7: PSSAdapterMutationIDs == ResolvedPSSAdapterMutationIDs (3 classes, 3 pairs)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'pss' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...PSS_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 3);
  assert.equal(PSS_ADAPTER_STIMULUS_PAIRS.length, 3);
  for (const [m, s] of PSS_ADAPTER_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolvePssAdapterFixture(m, s, pool), `${m}::${s}`);
  }
});

// --- The new distribution pattern ------------------------------------------

test('M3.2.4b-2.7: a fourth distribution -- TWO classes share ONE composed shape', () => {
  assert.equal(invocationIds().length, 2, 'two classes served by a single resolver');
  assert.equal(PSS_ADAPTER_MUTATION_IDS.filter(isPssErrorMappingClass).length, 1);

  // Both receive an identical base fixture; only their intervention targets differ.
  const [a, b] = invocationIds();
  assert.deepEqual(
    resolvePssAdapterInvocationFixture(a!, 'default', pool),
    resolvePssAdapterInvocationFixture(b!, 'default', pool),
  );
});

test('M3.2.4b-2.7: the two shared-shape classes intervene on DIFFERENT fields, so they remain distinct experiments', () => {
  const targets = invocationIds().map((id) => getMutationImplementation(id).directInterventionTargets.join(','));
  assert.equal(new Set(targets).size, 2, 'distinct directInterventionTargets');

  for (const id of invocationIds()) {
    const base = resolvePssAdapterInvocationFixture(id, 'default', pool);
    const mutated = getMutationImplementation(id).mutate(base, 'default') as typeof base;
    const changed = (['externalRandomnessProvided', 'explicitSaltBytesProvided'] as const)
      .filter((k) => mutated[k] !== base[k]);
    assert.equal(changed.length, 1, `${id} must flip exactly one control flag`);
    assert.deepEqual(mutated.request, base.request, 'the embedded request is never a direct target');
  }
});

test('M3.2.4b-2.7: PssAdapterInvocation carries THREE fields -- assuming OAEP arity would have dropped one', () => {
  const f = resolvePssAdapterInvocationFixture(invocationIds()[0]!, 'default', pool);
  assert.deepEqual(Object.keys(f).sort(), ['explicitSaltBytesProvided', 'externalRandomnessProvided', 'request']);
});

// --- Composition, and coexisting disjointness ------------------------------

test('M3.2.4b-2.7: the invocation COMPOSES the same sign request the request group serves', () => {
  const f = resolvePssAdapterInvocationFixture(invocationIds()[0]!, 'default', pool);
  assert.doesNotThrow(() => validatePssSignRequest(f.request));

  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'pss' && e.mechanism === 'request-transform'
      && !isPssKeyRoleBypass(e.mutationId) && !isPssVerifyRequestClass(e.mutationId),
  )!.mutationId;
  assert.deepEqual(f.request, resolvePssSignRequestFixture(carrierId, 'default', pool),
    'one canonical definition of an unmutated PSS sign request, not two');
});

test('M3.2.4b-2.7: the error-mapping shape stays DISJOINT -- both relationships coexist in one group', () => {
  const f = resolvePssErrorMappingFixture(errorId(), 'default', pool);
  const invocation = resolvePssAdapterInvocationFixture(invocationIds()[0]!, 'default', pool);
  const shared = Object.keys(f).filter((k) => Object.keys(invocation).includes(k));
  assert.deepEqual(shared, []);
  for (const v of Object.values(f)) assert.equal(typeof v, 'string');
});

// --- The error-mapping baseline --------------------------------------------

test('M3.2.4b-2.7: the baseline declares the class the frozen contract raises for its condition', () => {
  const f = resolvePssErrorMappingFixture(errorId(), 'default', pool);
  assert.equal(f.declaredErrorClass, PSS_BASELINE_DECLARED_ERROR_CLASS);
  assert.equal(f.declaredErrorClass, 'invalid_key', 'validatePssSignRequest raises invalid_key for a non-private key');
  assert.equal(f.triggeringCondition, PSS_BASELINE_TRIGGERING_CONDITION);
});

test('M3.2.4b-2.7: the correct class IS one of the toggled values here -- the OAEP-shaped argument, not the GCM one', () => {
  const base = resolvePssErrorMappingFixture(errorId(), 'default', pool);
  const mutated = getMutationImplementation(errorId()).mutate(base, 'default') as typeof base;
  assert.equal(base.declaredErrorClass, 'invalid_key');
  assert.equal(mutated.declaredErrorClass, 'invalid_parameter', 'a key-role failure misreported as a parameter failure');
  assert.equal(mutated.triggeringCondition, base.triggeringCondition, 'only the declared class is intervened on');
});

// --- The control-surface baselines -----------------------------------------

test('M3.2.4b-2.7: both native control surfaces start absent, as the portable profile requires', () => {
  const f = resolvePssAdapterInvocationFixture(invocationIds()[0]!, 'default', pool);
  assert.equal(f.externalRandomnessProvided, PSS_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED);
  assert.equal(f.explicitSaltBytesProvided, PSS_BASELINE_EXPLICIT_SALT_BYTES_PROVIDED);
  assert.equal(f.externalRandomnessProvided, false);
  assert.equal(f.explicitSaltBytesProvided, false);
});

// --- H1 / H3 ---------------------------------------------------------------

test('M3.2.4b-2.7: no frozen material is referenced anywhere in this group', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-adapter.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.7 (H3): no mutate() call, and all 3 pairs are genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of PSS_ADAPTER_STIMULUS_PAIRS) {
    const base = resolvePssAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

// --- Derivation and fail-closed --------------------------------------------

test('M3.2.4b-2.7: shape selection is derived from Gamma_0, cross-checked against the registry', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-adapter.ts', import.meta.url), 'utf8');
  for (const id of PSS_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === id)!;
    assert.equal(isPssErrorMappingClass(id), entry.gamma0.some((c) => c.endsWith('.error')));
  }
});

test('M3.2.4b-2.7: the two typed resolvers refuse each other classes, and foreign ids fail closed', () => {
  assert.throws(() => resolvePssErrorMappingFixture(invocationIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssAdapterInvocationFixture(errorId(), 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssAdapterFixture(errorId(), 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolvePssAdapterFixture('OAEP-DECRYPT-ERROR-DISCLOSURE', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssAdapterFixture('PSS-HASH-PROFILE-BYPASS', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssAdapterFixture('PSS-VERIFICATION-FALSE-ACCEPT', 'default', pool), FixtureResolutionError);
});
