import { test } from 'node:test';
import assert from 'node:assert/strict';

import { HKDF_MUTATIONS, HKDF_HASH_MISMATCH, HKDF_UNSUPPORTED_HASH_DECLARATION, HKDF_CAPABILITY_BOUNDARY_MISMATCH, HKDF_ALL_MUTATION_IDS } from '../../../harness/mutations/hkdf.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';

function baseFixture(): HkdfRequest {
  return {
    ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    salt: undefined,
    info: new Uint8Array([9, 9, 9]),
    length: 32,
  };
}

for (const impl of HKDF_MUTATIONS) {
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId);

  test(`${impl.mutationId}: exists in the frozen registry (no phantom implementation)`, () => {
    assert.ok(registryEntry, `${impl.mutationId} must correspond to a registry entry`);
  });

  for (const instance of registryEntry?.stimulusInstances ?? [{ stimulusInstanceId: 'default' }]) {
    const stimulusId = instance.stimulusInstanceId;

    test(`${impl.mutationId} [${stimulusId}]: deterministic (no external entropy needed)`, () => {
      const fixture = baseFixture();
      const a = impl.mutate(fixture, stimulusId);
      const b = impl.mutate(fixture, stimulusId);
      assert.deepEqual(a, b);
    });

    test(`${impl.mutationId} [${stimulusId}]: fields outside directInterventionTargets are conserved`, () => {
      const fixture = baseFixture();
      const mutated = impl.mutate(fixture, stimulusId) as unknown as Record<string, unknown>;
      const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, mutated, impl.directInterventionTargets);
      assert.deepEqual(violations, [], `unexpected touched fields outside directInterventionTargets: ${violations.join(', ')}`);
    });

    test(`${impl.mutationId} [${stimulusId}]: the target field is actually changed`, () => {
      const fixture = baseFixture();
      const mutated = impl.mutate(fixture, stimulusId) as unknown as Record<string, unknown>;
      const anyChanged = impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, mutated, f));
      assert.ok(anyChanged, 'mutation must actually change at least one direct-intervention-target field');
    });

    test(`${impl.mutationId} [${stimulusId}]: does not mutate the input fixture in place`, () => {
      const fixture = baseFixture();
      const snapshot = {
        ikm: Array.from(fixture.ikm), salt: fixture.salt ? Array.from(fixture.salt) : undefined,
        info: Array.from(fixture.info), length: fixture.length,
      };
      impl.mutate(fixture, stimulusId);
      const after = {
        ikm: Array.from(fixture.ikm), salt: fixture.salt ? Array.from(fixture.salt) : undefined,
        info: Array.from(fixture.info), length: fixture.length,
      };
      assert.deepEqual(after, snapshot, 'the original fixture object must remain unchanged after mutate()');
    });
  }
}

test('HKDF-NULL-VS-EMPTY-SALT: toggles undefined <-> empty Uint8Array specifically', () => {
  const withUndefined = baseFixture(); // salt: undefined
  const r1 = HKDF_MUTATIONS[0]!.mutate(withUndefined, 'default');
  assert.deepEqual(r1.salt, new Uint8Array(0));

  const withEmpty = { ...baseFixture(), salt: new Uint8Array(0) };
  const r2 = HKDF_MUTATIONS[0]!.mutate(withEmpty, 'default');
  assert.equal(r2.salt, undefined);
});

test('HKDF-LENGTH-BOUNDARY-CROSSING: L=0 and L=8161 are the two distinct stimulus instances of ONE mutationId', () => {
  const impl = HKDF_MUTATIONS.find((m) => m.mutationId === 'HKDF-LENGTH-BOUNDARY-CROSSING')!;
  const r0 = impl.mutate(baseFixture(), 'L=0');
  const r1 = impl.mutate(baseFixture(), 'L=8161');
  assert.equal(r0.length, 0);
  assert.equal(r1.length, 8161);
  // One mutationId, not two.
  assert.equal(impl.mutationId, 'HKDF-LENGTH-BOUNDARY-CROSSING');
});

// ---------------------------------------------------------------------
// M2.4.6a: the three previously-blocked classes, now resolved with the
// corrected mechanism model (adapter-transform / capability-transform).
// ---------------------------------------------------------------------

test('HKDF-HASH-MISMATCH: mutates effectiveHash only, never HkdfRequest, never hkdf.output directly', () => {
  const state = { request: baseFixture(), effectiveHash: 'SHA-256' };
  const mutated = HKDF_HASH_MISMATCH.mutate(state, 'default');
  assert.notEqual(mutated.effectiveHash, 'SHA-256');
  assert.deepEqual(mutated.request, state.request, 'the portable request must remain untouched');
});

test('HKDF-UNSUPPORTED-HASH-DECLARATION: declares an algorithm outside the recognized set, distinct from HASH-MISMATCH', () => {
  const state = { request: baseFixture(), effectiveHash: 'SHA-256' };
  const mutated = HKDF_UNSUPPORTED_HASH_DECLARATION.mutate(state, 'default');
  const hashMismatchResult = HKDF_HASH_MISMATCH.mutate(state, 'default');
  assert.notEqual(mutated.effectiveHash, 'SHA-256');
  assert.notEqual(mutated.effectiveHash, hashMismatchResult.effectiveHash, 'the two hash-related mutations must be genuinely distinct interventions');
});

test('HKDF-CAPABILITY-BOUNDARY-MISMATCH: mutates a COPY, never the frozen manifest -- FrozenManifest != MutatedExperimentalView', () => {
  const declaration = Object.freeze({ capabilityId: 'hkdf.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = HKDF_CAPABILITY_BOUNDARY_MISMATCH.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  // The original, frozen declaration is untouched -- both by identity and by value.
  assert.equal(declaration.support, 'supported');
  assert.notEqual(mutated, declaration);
});

test('all three non-request mechanisms: DirectInterventionTargets is a SUBSET of Gamma0, never asserted equal to it', () => {
  const cases: Array<{ impl: { mutationId: string; directInterventionTargets: readonly string[] }; fieldToClause: Record<string, string> }> = [
    { impl: HKDF_HASH_MISMATCH, fieldToClause: { effectiveHash: 'hkdf.hash' } },
    { impl: HKDF_UNSUPPORTED_HASH_DECLARATION, fieldToClause: { effectiveHash: 'hkdf.hash' } },
    { impl: HKDF_CAPABILITY_BOUNDARY_MISMATCH, fieldToClause: { support: 'hkdf.cap' } },
  ];
  for (const { impl, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(impl.directInterventionTargets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${impl.mutationId}: direct targets not a subset of Gamma_0 -- unmapped: ${unmapped.join(', ')}`);
    // And Gamma_0 has strictly MORE members than the direct targets for
    // these three -- proving this is a genuine subset, not an accidental equality.
    assert.ok(registryEntry.gamma0.length > impl.directInterventionTargets.length,
      `${impl.mutationId}: Gamma_0 should include causally-downstream clauses beyond the direct targets`);
  }
});

test('M2.4.6a correspondence audit: HKDF is now 8/8, nothing flagged, nothing phantom, nothing silently missing', () => {
  const hkdfRegistryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'hkdf').map((e) => e.mutationId));
  const implementedIds = new Set(HKDF_ALL_MUTATION_IDS);

  assert.equal(hkdfRegistryIds.size, 8, 'HKDF registry must have exactly 8 classes');
  assert.equal(implementedIds.size, 8, 'all 8 now implemented under the corrected mechanism model');
  assert.deepEqual([...hkdfRegistryIds].sort(), [...implementedIds].sort());
});
