import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  PSS_REQUEST_MUTATIONS, PSS_VERIFY_MESSAGE_NORMALIZATION, PSS_KEY_ROLE_BYPASS,
  PSS_VERIFICATION_FALSE_ACCEPT, PSS_VERIFICATION_FALSE_REJECT,
  PSS_RNG_INTERFACE_LEAK, PSS_SALT_BYTES_INTERFACE_LEAK, PSS_ERROR_MISCLASSIFICATION,
  PSS_PROVIDER_CAPABILITY_MISREPORT, PSS_ALL_MUTATION_IDS,
  baseSignFixture, baseVerifyFixture,
} from '../../../harness/mutations/pss.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { SALT_LEN_BYTES } from '../../../src/contract/pss.js';

// ---------------------------------------------------------------------
// request-transform: 7 sign-side classes
// ---------------------------------------------------------------------
for (const impl of PSS_REQUEST_MUTATIONS) {
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId);

  test(`${impl.mutationId}: exists in the frozen registry`, () => {
    assert.ok(registryEntry, `${impl.mutationId} must correspond to a registry entry`);
  });

  test(`${impl.mutationId}: deterministic`, () => {
    const fixture = baseSignFixture();
    assert.deepEqual(impl.mutate(fixture, 'default'), impl.mutate(fixture, 'default'));
  });

  test(`${impl.mutationId}: fields outside directInterventionTargets are conserved`, () => {
    const fixture = baseSignFixture();
    const mutated = impl.mutate(fixture, 'default') as unknown as Record<string, unknown>;
    const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, mutated, impl.directInterventionTargets);
    assert.deepEqual(violations, []);
  });

  test(`${impl.mutationId}: target field actually changes`, () => {
    const fixture = baseSignFixture();
    const mutated = impl.mutate(fixture, 'default') as unknown as Record<string, unknown>;
    assert.ok(impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, mutated, f)));
  });

  test(`${impl.mutationId}: does not mutate the input fixture in place`, () => {
    const fixture = baseSignFixture();
    const snap = JSON.stringify({ key: fixture.key, message: Array.from(fixture.message), hash: fixture.hash, mgfHash: fixture.mgfHash, saltLengthBytes: fixture.saltLengthBytes });
    impl.mutate(fixture, 'default');
    const after = JSON.stringify({ key: fixture.key, message: Array.from(fixture.message), hash: fixture.hash, mgfHash: fixture.mgfHash, saltLengthBytes: fixture.saltLengthBytes });
    assert.equal(after, snap);
  });
}

test('PSS-HASH-PROFILE-BYPASS vs PSS-MGF-COUPLING-BYPASS: distinct interventions, same discipline as OAEP', () => {
  const hashResult = PSS_REQUEST_MUTATIONS.find((m) => m.mutationId === 'PSS-HASH-PROFILE-BYPASS')!.mutate(baseSignFixture(), 'default');
  assert.equal(hashResult.hash, hashResult.mgfHash);

  const mgfResult = PSS_REQUEST_MUTATIONS.find((m) => m.mutationId === 'PSS-MGF-COUPLING-BYPASS')!.mutate(baseSignFixture(), 'default');
  assert.notEqual(mgfResult.hash, mgfResult.mgfHash);
});

test('PSS-SALTLENGTH-PROFILE-BYPASS: changes saltLengthBytes away from the portable 32 (=hLen)', () => {
  const mutated = PSS_REQUEST_MUTATIONS.find((m) => m.mutationId === 'PSS-SALTLENGTH-PROFILE-BYPASS')!.mutate(baseSignFixture(), 'default');
  assert.notEqual(mutated.saltLengthBytes, SALT_LEN_BYTES);
});

// ---------------------------------------------------------------------
// PSS-VERIFY-MESSAGE-NORMALIZATION: verify-side request, distinct type
// ---------------------------------------------------------------------
test('PSS-VERIFY-MESSAGE-NORMALIZATION: acts on PssVerifyRequest, not PssSignRequest', () => {
  const fixture = baseVerifyFixture();
  const mutated = PSS_VERIFY_MESSAGE_NORMALIZATION.mutate(fixture, 'default');
  assert.notDeepEqual(mutated.message, fixture.message);
  assert.deepEqual(mutated.signature, fixture.signature, 'signature must be untouched');
});

// ---------------------------------------------------------------------
// PSS-KEY-ROLE-BYPASS: one frozen instance (sign-with-public)
// ---------------------------------------------------------------------
test('PSS-KEY-ROLE-BYPASS: default instance presents a public key where sign requires private', () => {
  const state: { kind: 'sign'; request: ReturnType<typeof baseSignFixture> } = { kind: 'sign', request: baseSignFixture() };
  const mutated = PSS_KEY_ROLE_BYPASS.mutate(state, 'default');
  assert.equal(mutated.kind, 'sign');
  assert.equal((mutated as typeof state).request.key.role, 'public');
});

// ---------------------------------------------------------------------
// artifact-transform: real RSA-PSS signatures via webcrypto
// ---------------------------------------------------------------------

async function realSignature(message: Uint8Array): Promise<Uint8Array> {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    false, ['sign', 'verify'],
  );
  const sig = await webcrypto.subtle.sign({ name: 'RSA-PSS', saltLength: SALT_LEN_BYTES }, keyPair.privateKey, message);
  return new Uint8Array(sig);
}

test('PSS-VERIFICATION-FALSE-ACCEPT: corrupts a genuinely valid signature, never mutates the input in place', async () => {
  const message = new Uint8Array([9, 9, 9]);
  const signature = await realSignature(message);
  const state = { message, signature };
  const snapshot = Array.from(signature);

  const mutated = PSS_VERIFICATION_FALSE_ACCEPT.mutate(state, 'default');
  assert.notDeepEqual(mutated.signature, signature, 'the corrupted signature must differ from the valid one');
  assert.deepEqual(Array.from(signature), snapshot, 'the original valid signature must remain unchanged');
  assert.deepEqual(mutated.message, message);
});

test('PSS-VERIFICATION-FALSE-REJECT: swaps between two independently-valid signatures, no cryptography executed inside mutate()', async () => {
  const message = new Uint8Array([7, 7, 7]);
  const sigA = await realSignature(message);
  const sigB = await realSignature(message); // independently generated -- fresh randomness, still valid for the same message
  assert.notDeepEqual(sigA, sigB, 'PSS signing is probabilistic -- two independent signatures for the same message must differ');

  const state = { message, signature: sigA, alternateSignature: sigB };
  const mutated = PSS_VERIFICATION_FALSE_REJECT.mutate(state, 'default');
  assert.deepEqual(mutated.signature, sigB);
  assert.deepEqual(mutated.alternateSignature, sigA);
  // Swapping back reproduces the original state exactly -- a genuine swap, not a corruption.
  const swappedBack = PSS_VERIFICATION_FALSE_REJECT.mutate(mutated, 'default');
  assert.deepEqual(swappedBack, state);
});

// ---------------------------------------------------------------------
// adapter-transform and capability-transform: 4 classes
// ---------------------------------------------------------------------

test('PSS-RNG-INTERFACE-LEAK and PSS-SALT-BYTES-INTERFACE-LEAK: genuinely distinct fields, neither present in PssSignRequest', () => {
  const state = { request: baseSignFixture(), externalRandomnessProvided: false, explicitSaltBytesProvided: false };
  const rngMutated = PSS_RNG_INTERFACE_LEAK.mutate(state, 'default');
  const saltMutated = PSS_SALT_BYTES_INTERFACE_LEAK.mutate(state, 'default');
  assert.equal(rngMutated.externalRandomnessProvided, true);
  assert.equal(rngMutated.explicitSaltBytesProvided, false, 'RNG-INTERFACE-LEAK must not touch explicitSaltBytesProvided');
  assert.equal(saltMutated.explicitSaltBytesProvided, true);
  assert.equal(saltMutated.externalRandomnessProvided, false, 'SALT-BYTES-INTERFACE-LEAK must not touch externalRandomnessProvided');
  assert.ok(!('externalRandomnessProvided' in baseSignFixture()) && !('explicitSaltBytesProvided' in baseSignFixture()));
});

test('PSS-ERROR-MISCLASSIFICATION: mutates declaredErrorClass within PSS own three-class taxonomy', () => {
  const state = { triggeringCondition: 'bad-modulus', declaredErrorClass: 'invalid_key' };
  const mutated = PSS_ERROR_MISCLASSIFICATION.mutate(state, 'default');
  assert.notEqual(mutated.declaredErrorClass, 'invalid_key');
});

test('PSS-PROVIDER-CAPABILITY-MISREPORT: mutates a copy, never a frozen manifest object', () => {
  const declaration = Object.freeze({ capabilityId: 'pss.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = PSS_PROVIDER_CAPABILITY_MISREPORT.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  assert.equal(declaration.support, 'supported');
});

// ---------------------------------------------------------------------
// registry-level Gamma_0 subset checks + correspondence audit
// ---------------------------------------------------------------------

test('PSS non-request mechanisms: DirectInterventionTargets is a SUBSET of Gamma_0', () => {
  const cases: Array<{ mutationId: string; targets: readonly string[]; fieldToClause: Record<string, string> }> = [
    { mutationId: 'PSS-RNG-INTERFACE-LEAK', targets: PSS_RNG_INTERFACE_LEAK.directInterventionTargets, fieldToClause: { externalRandomnessProvided: 'pss.rngControl' } },
    { mutationId: 'PSS-SALT-BYTES-INTERFACE-LEAK', targets: PSS_SALT_BYTES_INTERFACE_LEAK.directInterventionTargets, fieldToClause: { explicitSaltBytesProvided: 'pss.saltBytes' } },
    { mutationId: 'PSS-ERROR-MISCLASSIFICATION', targets: PSS_ERROR_MISCLASSIFICATION.directInterventionTargets, fieldToClause: { declaredErrorClass: 'pss.error' } },
    { mutationId: 'PSS-PROVIDER-CAPABILITY-MISREPORT', targets: PSS_PROVIDER_CAPABILITY_MISREPORT.directInterventionTargets, fieldToClause: { support: 'pss.cap.provider' } },
  ];
  for (const { mutationId, targets, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(targets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${mutationId}: unmapped ${unmapped.join(', ')}`);
  }
});

test('M2.4.6 correspondence audit: PSS is 15/15, nothing phantom, nothing missing', () => {
  const pssRegistryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'pss').map((e) => e.mutationId));
  const implementedIds = new Set(PSS_ALL_MUTATION_IDS);
  assert.equal(pssRegistryIds.size, 15);
  assert.equal(implementedIds.size, 15);
  assert.deepEqual([...pssRegistryIds].sort(), [...implementedIds].sort());
});
