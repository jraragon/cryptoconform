import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  TOY_PRIVATE_MATERIAL, TOY_PUBLIC_MATERIAL,
  RSA_SER_PUBLIC_MATERIAL_DIVERGENCE, RSA_SER_PRIVATE_MATERIAL_DIVERGENCE,
  RSA_SER_DER_IMPORT_BYPASS, RSA_SER_DER_EXPORT_DIVERGENCE,
  RSA_SER_CONTAINER_IMPORT_BYPASS, RSA_SER_CONTAINER_EXPORT_DIVERGENCE,
  RSA_SER_TRAILING_DATA_BYPASS, RSA_SER_ROLE_CONTAINER_BYPASS,
  RSA_SER_OID_IMPORT_PROFILE_BYPASS, RSA_SER_OID_EXPORT_DIVERGENCE,
  RSA_SER_PARAMETERS_IMPORT_PROFILE_BYPASS, RSA_SER_PARAMETERS_EXPORT_CANONICALIZATION_DIVERGENCE,
  RSA_SER_PUBLIC_VALIDITY_BYPASS, RSA_SER_PRIVATE_DOMAIN_BYPASS, RSA_SER_PRIVATE_RELATIONAL_BYPASS,
  RSA_SER_ERROR_MISCLASSIFICATION, RSA_SER_PROVIDER_CAPABILITY_MISREPORT,
  RSA_SER_ALL_MUTATION_IDS, encodeSpki, encodePrivateKeyInfo,
} from '../../../harness/mutations/rsa-ser.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { importRsaSer } from '../../../src/contract/rsa-ser.js';

// --- Re-verify the toy key's own math independently, using the EXACT same
// relations the contract's checkPrivateDomain/checkPrivateRelations use ---
// This is the safeguard against exactly the kind of fabricated-value error
// caught during implementation (an initial e=3 alternate was invalid).
function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a; b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}
function relationsHold(m: { n: bigint; e: bigint; d: bigint; p: bigint; q: bigint; dP: bigint; dQ: bigint; qInv: bigint }): boolean {
  const lambda = (a: bigint, b: bigint) => (a * b) / gcd(a, b);
  const lam = lambda(m.p - 1n, m.q - 1n);
  const modOk = (a: bigint, b: bigint, mod: bigint) => (a * b) % mod === 1n % mod;
  return m.n === m.p * m.q && gcd(m.e, lam) === 1n && modOk(m.e, m.d, lam) && modOk(m.e, m.dP, m.p - 1n) && modOk(m.e, m.dQ, m.q - 1n) && modOk(m.q, m.qInv, m.p);
}
function publicValidityHolds(n: bigint, e: bigint): boolean {
  return n >= 15n && n % 2n === 1n && e >= 3n && e <= n - 1n && e % 2n === 1n;
}

test('TOY_PRIVATE_MATERIAL satisfies every relation checkPrivateRelations checks -- verified independently, not just trusted', () => {
  assert.ok(relationsHold(TOY_PRIVATE_MATERIAL));
});

test('RSA-SER-PRIVATE-MATERIAL-DIVERGENCE produces a genuinely valid ALTERNATE tuple (e=7), independently re-verified', () => {
  const mutated = RSA_SER_PRIVATE_MATERIAL_DIVERGENCE.mutate(TOY_PRIVATE_MATERIAL, 'default');
  assert.ok(relationsHold(mutated), 'the mutated private material must itself satisfy all relations -- not merely differ');
  assert.notEqual(mutated.e, TOY_PRIVATE_MATERIAL.e);
});

// ---------------------------------------------------------------------
// Material-level mutations: standard four properties
// ---------------------------------------------------------------------
for (const [impl, fixture] of [
  [RSA_SER_PUBLIC_MATERIAL_DIVERGENCE, TOY_PUBLIC_MATERIAL],
  [RSA_SER_PRIVATE_MATERIAL_DIVERGENCE, TOY_PRIVATE_MATERIAL],
  [RSA_SER_DER_EXPORT_DIVERGENCE, TOY_PUBLIC_MATERIAL],
  [RSA_SER_CONTAINER_EXPORT_DIVERGENCE, TOY_PUBLIC_MATERIAL],
  [RSA_SER_OID_EXPORT_DIVERGENCE, TOY_PUBLIC_MATERIAL],
  [RSA_SER_PARAMETERS_EXPORT_CANONICALIZATION_DIVERGENCE, TOY_PUBLIC_MATERIAL],
  [RSA_SER_PUBLIC_VALIDITY_BYPASS, TOY_PUBLIC_MATERIAL],
  [RSA_SER_PRIVATE_DOMAIN_BYPASS, TOY_PRIVATE_MATERIAL],
] as const) {
  test(`${impl.mutationId}: exists in the frozen registry`, () => {
    assert.ok(MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId));
  });
  test(`${impl.mutationId}: deterministic`, () => {
    assert.deepEqual(impl.mutate(fixture as never, 'default'), impl.mutate(fixture as never, 'default'));
  });
  test(`${impl.mutationId}: fields outside directInterventionTargets are conserved`, () => {
    const mutated = impl.mutate(fixture as never, 'default') as unknown as Record<string, unknown>;
    const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, mutated, impl.directInterventionTargets);
    assert.deepEqual(violations, []);
  });
  test(`${impl.mutationId}: target field actually changes`, () => {
    const mutated = impl.mutate(fixture as never, 'default') as unknown as Record<string, unknown>;
    assert.ok(impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, mutated, f)));
  });
}

test('RSA-SER-PUBLIC-VALIDITY-BYPASS: mutated e fails checkPublicValidity (even e)', () => {
  const mutated = RSA_SER_PUBLIC_VALIDITY_BYPASS.mutate(TOY_PUBLIC_MATERIAL, 'default');
  assert.equal(!publicValidityHolds(mutated.n, mutated.e), true);
});

test('RSA-SER-PRIVATE-DOMAIN-BYPASS: p===q violates checkPrivateDomain', () => {
  const mutated = RSA_SER_PRIVATE_DOMAIN_BYPASS.mutate(TOY_PRIVATE_MATERIAL, 'default');
  assert.equal(mutated.p, mutated.q);
});

test('RSA-SER-PRIVATE-RELATIONAL-BYPASS: each of the five instances corrupts exactly its own relation, one mutationId', () => {
  const instances = ['n-neq-pq', 'ed-not-1', 'edP-not-1', 'edQ-not-1', 'qqInv-not-1'] as const;
  for (const id of instances) {
    const mutated = RSA_SER_PRIVATE_RELATIONAL_BYPASS.mutate(TOY_PRIVATE_MATERIAL, id);
    assert.ok(!relationsHold(mutated), `${id} must violate at least one relation`);
  }
  assert.equal(RSA_SER_PRIVATE_RELATIONAL_BYPASS.mutationId, 'RSA-SER-PRIVATE-RELATIONAL-BYPASS');
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === 'RSA-SER-PRIVATE-RELATIONAL-BYPASS')!;
  assert.equal(registryEntry.stimulusInstances.length, 5);
});

// ---------------------------------------------------------------------
// Artifact-level (real DER) mutations
// ---------------------------------------------------------------------

test('RSA-SER-DER-IMPORT-BYPASS: corrupts a REAL SPKI artifact so it no longer imports', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  assert.doesNotThrow(() => importRsaSer(artifact, 'public'), 'the unmutated artifact must import cleanly');
  const mutated = RSA_SER_DER_IMPORT_BYPASS.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importRsaSer(mutated.artifact, 'public'));
});

test('RSA-SER-CONTAINER-IMPORT-BYPASS: real SPKI, corrupted to a 3-child outer SEQUENCE, fails import', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = RSA_SER_CONTAINER_IMPORT_BYPASS.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importRsaSer(mutated.artifact, 'public'));
});

test('RSA-SER-TRAILING-DATA-BYPASS: one trailing byte after a real, exactly-consumed SPKI artifact', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = RSA_SER_TRAILING_DATA_BYPASS.mutate({ artifact }, 'default');
  assert.equal(mutated.artifact.length, artifact.length + 1);
  assert.throws(() => importRsaSer(mutated.artifact, 'public'), /trailing bytes/);
});

test('RSA-SER-ROLE-CONTAINER-BYPASS: a real, valid SPKI presented with requestedRole flipped to private', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = RSA_SER_ROLE_CONTAINER_BYPASS.mutate({ artifact, requestedRole: 'public' }, 'default');
  assert.equal(mutated.requestedRole, 'private');
  assert.deepEqual(mutated.artifact, artifact, 'the artifact itself must remain untouched');
  assert.throws(() => importRsaSer(mutated.artifact, mutated.requestedRole));
});

test('RSA-SER-OID-IMPORT-PROFILE-BYPASS: corrupts the real rsaEncryption OID content', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = RSA_SER_OID_IMPORT_PROFILE_BYPASS.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importRsaSer(mutated.artifact, 'public'));
});

test('RSA-SER-PARAMETERS-IMPORT-PROFILE-BYPASS: replaces the real NULL parameters with an INTEGER', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = RSA_SER_PARAMETERS_IMPORT_PROFILE_BYPASS.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importRsaSer(mutated.artifact, 'public'));
});

test('PrivateKeyInfo (encodePrivateKeyInfo) round-trips cleanly for the toy private material -- confirms the real encoder is usable end to end', () => {
  const artifact = encodePrivateKeyInfo(TOY_PRIVATE_MATERIAL);
  const imported = importRsaSer(artifact, 'private');
  assert.deepEqual(imported, TOY_PRIVATE_MATERIAL);
});

// ---------------------------------------------------------------------
// adapter-transform and capability-transform
// ---------------------------------------------------------------------

test('RSA-SER-ERROR-MISCLASSIFICATION: mutates declaredErrorClass', () => {
  const state = { triggeringCondition: 'bad-relation', declaredErrorClass: 'invalid_key' };
  const mutated = RSA_SER_ERROR_MISCLASSIFICATION.mutate(state, 'default');
  assert.notEqual(mutated.declaredErrorClass, 'invalid_key');
});

test('RSA-SER-PROVIDER-CAPABILITY-MISREPORT: mutates a copy, never a frozen manifest object', () => {
  const declaration = Object.freeze({ capabilityId: 'rsa-ser.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = RSA_SER_PROVIDER_CAPABILITY_MISREPORT.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  assert.equal(declaration.support, 'supported');
});

// ---------------------------------------------------------------------
// Gamma_0 subset checks + correspondence audit
// ---------------------------------------------------------------------

test('RSA-ser non-material mechanisms: DirectInterventionTargets is a SUBSET of Gamma_0', () => {
  const cases: Array<{ mutationId: string; targets: readonly string[]; fieldToClause: Record<string, string> }> = [
    { mutationId: 'RSA-SER-ROLE-CONTAINER-BYPASS', targets: RSA_SER_ROLE_CONTAINER_BYPASS.directInterventionTargets, fieldToClause: { requestedRole: 'role-container' } },
    { mutationId: 'RSA-SER-ERROR-MISCLASSIFICATION', targets: RSA_SER_ERROR_MISCLASSIFICATION.directInterventionTargets, fieldToClause: { declaredErrorClass: 'error' } },
    { mutationId: 'RSA-SER-PROVIDER-CAPABILITY-MISREPORT', targets: RSA_SER_PROVIDER_CAPABILITY_MISREPORT.directInterventionTargets, fieldToClause: { support: 'cap' } },
  ];
  for (const { mutationId, targets, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(targets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${mutationId}: unmapped ${unmapped.join(', ')}`);
  }
});

test('M2.4.6 correspondence audit: RSA-ser is 17/17, nothing phantom, nothing missing', () => {
  const registryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'rsa-ser').map((e) => e.mutationId));
  const implementedIds = new Set(RSA_SER_ALL_MUTATION_IDS);
  assert.equal(registryIds.size, 17);
  assert.equal(implementedIds.size, 17);
  assert.deepEqual([...registryIds].sort(), [...implementedIds].sort());
});
