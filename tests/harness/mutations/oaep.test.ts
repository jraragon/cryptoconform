import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  OAEP_REQUEST_MUTATIONS, OAEP_KEY_ROLE_BYPASS, OAEP_RANDOMNESS_INTERFACE_LEAK,
  OAEP_DECRYPT_ERROR_DISCLOSURE, OAEP_PROVIDER_CAPABILITY_MISREPORT, OAEP_ALL_MUTATION_IDS,
} from '../../../harness/mutations/oaep.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { MAX_MESSAGE_LEN_BYTES, MODULUS_BITS, OAEP_HASH, type OaepEncryptRequest, type OaepDecryptRequest } from '../../../src/contract/oaep.js';

function baseFixture(): OaepEncryptRequest {
  return {
    key: { role: 'public', modulusBits: MODULUS_BITS },
    plaintext: new Uint8Array([1, 2, 3]),
    label: undefined,
    hash: OAEP_HASH,
    mgfHash: OAEP_HASH,
  };
}

// ---------------------------------------------------------------------
// request-transform: 8 classes, same four-property pattern as HKDF/GCM
// ---------------------------------------------------------------------
for (const impl of OAEP_REQUEST_MUTATIONS) {
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId);

  test(`${impl.mutationId}: exists in the frozen registry`, () => {
    assert.ok(registryEntry, `${impl.mutationId} must correspond to a registry entry`);
  });

  test(`${impl.mutationId}: deterministic`, () => {
    const fixture = baseFixture();
    assert.deepEqual(impl.mutate(fixture, 'default'), impl.mutate(fixture, 'default'));
  });

  test(`${impl.mutationId}: fields outside directInterventionTargets are conserved`, () => {
    const fixture = baseFixture();
    const mutated = impl.mutate(fixture, 'default') as unknown as Record<string, unknown>;
    const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, mutated, impl.directInterventionTargets);
    assert.deepEqual(violations, []);
  });

  test(`${impl.mutationId}: target field actually changes`, () => {
    const fixture = baseFixture();
    const mutated = impl.mutate(fixture, 'default') as unknown as Record<string, unknown>;
    assert.ok(impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, mutated, f)));
  });

  test(`${impl.mutationId}: does not mutate the input fixture in place`, () => {
    const fixture = baseFixture();
    const snap = JSON.stringify({ key: fixture.key, plaintext: Array.from(fixture.plaintext), label: fixture.label ? Array.from(fixture.label) : undefined, hash: fixture.hash, mgfHash: fixture.mgfHash });
    impl.mutate(fixture, 'default');
    const after = JSON.stringify({ key: fixture.key, plaintext: Array.from(fixture.plaintext), label: fixture.label ? Array.from(fixture.label) : undefined, hash: fixture.hash, mgfHash: fixture.mgfHash });
    assert.equal(after, snap);
  });
}

test('OAEP-HASH-PROFILE-BYPASS vs OAEP-MGF-COUPLING-BYPASS: genuinely distinct interventions, isolating hash choice from coupling', () => {
  const hashBypass = OAEP_REQUEST_MUTATIONS.find((m) => m.mutationId === 'OAEP-HASH-PROFILE-BYPASS')!;
  const mgfBypass = OAEP_REQUEST_MUTATIONS.find((m) => m.mutationId === 'OAEP-MGF-COUPLING-BYPASS')!;

  const hashResult = hashBypass.mutate(baseFixture(), 'default');
  // HASH-PROFILE-BYPASS: both hash and mgfHash move together (stays coupled, isolates the hash choice itself).
  assert.equal(hashResult.hash, hashResult.mgfHash);
  assert.notEqual(hashResult.hash, OAEP_HASH);

  const mgfResult = mgfBypass.mutate(baseFixture(), 'default');
  // MGF-COUPLING-BYPASS: hash stays at the portable SHA-256; only mgfHash decouples.
  assert.equal(mgfResult.hash, OAEP_HASH);
  assert.notEqual(mgfResult.mgfHash, mgfResult.hash);
});

test('OAEP-CIPHERTEXT-COMPUTATION-DIVERGENCE and OAEP-CIPHERTEXT-LENGTH-DIVERGENCE use genuinely distinct probes from MESSAGE-NORMALIZATION', () => {
  const norm = OAEP_REQUEST_MUTATIONS.find((m) => m.mutationId === 'OAEP-MESSAGE-NORMALIZATION')!.mutate(baseFixture(), 'default');
  const comp = OAEP_REQUEST_MUTATIONS.find((m) => m.mutationId === 'OAEP-CIPHERTEXT-COMPUTATION-DIVERGENCE')!.mutate(baseFixture(), 'default');
  const len = OAEP_REQUEST_MUTATIONS.find((m) => m.mutationId === 'OAEP-CIPHERTEXT-LENGTH-DIVERGENCE')!.mutate(baseFixture(), 'default');
  assert.notEqual(norm.plaintext.length, comp.plaintext.length);
  assert.equal(comp.plaintext.length, MAX_MESSAGE_LEN_BYTES);
  assert.equal(len.plaintext.length, 0);
});

// ---------------------------------------------------------------------
// OAEP-KEY-ROLE-BYPASS: discriminated union, two instances, one mutationId
// ---------------------------------------------------------------------

test('OAEP-KEY-ROLE-BYPASS: encrypt-with-private sets role=private on an encrypt request', () => {
  const state: { kind: 'encrypt'; request: OaepEncryptRequest } = { kind: 'encrypt', request: baseFixture() };
  const mutated = OAEP_KEY_ROLE_BYPASS.mutate(state, 'encrypt-with-private');
  assert.equal(mutated.kind, 'encrypt');
  assert.equal((mutated as typeof state).request.key.role, 'private');
});

test('OAEP-KEY-ROLE-BYPASS: decrypt-with-public sets role=public on a decrypt request', () => {
  const decryptRequest: OaepDecryptRequest = { key: { role: 'private', modulusBits: MODULUS_BITS }, ciphertext: new Uint8Array(384), label: undefined, hash: OAEP_HASH, mgfHash: OAEP_HASH };
  const state: { kind: 'decrypt'; request: OaepDecryptRequest } = { kind: 'decrypt', request: decryptRequest };
  const mutated = OAEP_KEY_ROLE_BYPASS.mutate(state, 'decrypt-with-public');
  assert.equal(mutated.kind, 'decrypt');
  assert.equal((mutated as typeof state).request.key.role, 'public');
});

test('OAEP-KEY-ROLE-BYPASS: one mutationId covers both instances -- never split into two classes', () => {
  assert.equal(OAEP_KEY_ROLE_BYPASS.mutationId, 'OAEP-KEY-ROLE-BYPASS');
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === 'OAEP-KEY-ROLE-BYPASS')!;
  assert.equal(registryEntry.stimulusInstances.length, 2);
});

// ---------------------------------------------------------------------
// adapter-transform and capability-transform: 3 classes
// ---------------------------------------------------------------------

test('OAEP-RANDOMNESS-INTERFACE-LEAK: toggles externalRandomnessProvided, a field with NO counterpart in OaepEncryptRequest -- confirming adapter-transform is the correct, not merely convenient, mechanism', () => {
  const state = { request: baseFixture(), externalRandomnessProvided: false };
  const mutated = OAEP_RANDOMNESS_INTERFACE_LEAK.mutate(state, 'default');
  assert.equal(mutated.externalRandomnessProvided, true);
  assert.deepEqual(mutated.request, state.request, 'the portable request must remain untouched');
  assert.ok(!('externalRandomnessProvided' in baseFixture()), 'OaepEncryptRequest genuinely has no such field');
});

test('OAEP-DECRYPT-ERROR-DISCLOSURE: mutates declaredErrorClass, distinguishing the frozen decryption_error collapse from a leaked, more specific class', () => {
  const state = { triggeringCondition: 'wrong-ciphertext-length', declaredErrorClass: 'decryption_error' };
  const mutated = OAEP_DECRYPT_ERROR_DISCLOSURE.mutate(state, 'default');
  assert.notEqual(mutated.declaredErrorClass, 'decryption_error');
});

test('OAEP-PROVIDER-CAPABILITY-MISREPORT: mutates a copy, never a frozen manifest object', () => {
  const declaration = Object.freeze({ capabilityId: 'oaep.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = OAEP_PROVIDER_CAPABILITY_MISREPORT.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  assert.equal(declaration.support, 'supported');
});

// ---------------------------------------------------------------------
// registry-level Gamma_0 subset checks
// ---------------------------------------------------------------------

test('OAEP non-request mechanisms: DirectInterventionTargets is a SUBSET of Gamma_0', () => {
  const cases: Array<{ mutationId: string; targets: readonly string[]; fieldToClause: Record<string, string> }> = [
    { mutationId: 'OAEP-RANDOMNESS-INTERFACE-LEAK', targets: OAEP_RANDOMNESS_INTERFACE_LEAK.directInterventionTargets, fieldToClause: { externalRandomnessProvided: 'oaep.randomness' } },
    { mutationId: 'OAEP-DECRYPT-ERROR-DISCLOSURE', targets: OAEP_DECRYPT_ERROR_DISCLOSURE.directInterventionTargets, fieldToClause: { declaredErrorClass: 'oaep.error' } },
    { mutationId: 'OAEP-PROVIDER-CAPABILITY-MISREPORT', targets: OAEP_PROVIDER_CAPABILITY_MISREPORT.directInterventionTargets, fieldToClause: { support: 'oaep.cap.provider' } },
  ];
  for (const { mutationId, targets, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(targets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${mutationId}: unmapped ${unmapped.join(', ')}`);
  }
});

test('M2.4.6 correspondence audit: OAEP is 12/12, nothing phantom, nothing missing', () => {
  const oaepRegistryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'oaep').map((e) => e.mutationId));
  const implementedIds = new Set(OAEP_ALL_MUTATION_IDS);
  assert.equal(oaepRegistryIds.size, 12);
  assert.equal(implementedIds.size, 12);
  assert.deepEqual([...oaepRegistryIds].sort(), [...implementedIds].sort());
});
