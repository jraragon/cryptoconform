import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  TOY_PRIVATE_MATERIAL, TOY_PUBLIC_MATERIAL,
  EC_PUBLIC_OFF_CURVE, EC_PRIVATE_SCALAR_RANGE, EC_PRIVATE_PAIR_MISMATCH,
  EC_ROLE_CONTAINER_MISMATCH, EC_CURVE_SUBSTITUTION, EC_PUBLIC_POINT_ENCODING,
  EC_PUBLIC_DER_MALFORMED, EC_PRIVATE_DER_MALFORMED,
  EC_PRIVATE_PARAMS_ABSENT, EC_PRIVATE_PARAMS_MISMATCH, EC_PRIVATE_PUBKEY_ABSENT,
  EC_NATIVE_EXPORT_LEAK, EC_ERROR_MAP_SWAP, EC_CAPABILITY_MANIFEST_MISMATCH,
  EC_SER_ALL_MUTATION_IDS, encodeSpki, encodePkcs8, importEcSer, isOnCurve, isPair,
} from '../../../harness/mutations/ec-ser.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';

// --- Re-verify the toy material's own math independently ---
test('TOY_PRIVATE_MATERIAL is genuinely on-curve and Q=dG -- verified independently, not just trusted', () => {
  assert.ok(isOnCurve(TOY_PRIVATE_MATERIAL.q));
  assert.ok(isPair(TOY_PRIVATE_MATERIAL.d, TOY_PRIVATE_MATERIAL.q));
});

// ---------------------------------------------------------------------
// Material-level mutations
// ---------------------------------------------------------------------

test('EC-PUBLIC-OFF-CURVE: the mutated point is genuinely off-curve, independently re-verified', () => {
  const mutated = EC_PUBLIC_OFF_CURVE.mutate(TOY_PUBLIC_MATERIAL, 'default');
  assert.ok(isOnCurve(TOY_PUBLIC_MATERIAL.q), 'sanity: the original point must itself be on-curve');
  assert.ok(!isOnCurve(mutated.q), 'the mutated point must NOT be on-curve');
});

test('EC-PRIVATE-SCALAR-RANGE: d=0 fails V_scalar (1<=d<n)', () => {
  const mutated = EC_PRIVATE_SCALAR_RANGE.mutate(TOY_PRIVATE_MATERIAL, 'default');
  assert.equal(mutated.d, 0n);
  assert.deepEqual(mutated.q, TOY_PRIVATE_MATERIAL.q, 'q must remain untouched -- it is a downstream consequence, never written directly');
});

test('EC-PRIVATE-PAIR-MISMATCH: the substituted point IS on-curve but Q != dG for this material -- isolates V_pair from V_curve, independently re-verified', () => {
  const mutated = EC_PRIVATE_PAIR_MISMATCH.mutate(TOY_PRIVATE_MATERIAL, 'default');
  assert.ok(isOnCurve(mutated.q), 'the substituted point must still be genuinely on-curve');
  assert.ok(!isPair(mutated.d, mutated.q), 'but must NOT be the correct pairing for d');
  assert.equal(mutated.d, TOY_PRIVATE_MATERIAL.d, 'd itself must remain untouched');
});

for (const [impl, fixture] of [
  [EC_PUBLIC_OFF_CURVE, TOY_PUBLIC_MATERIAL],
  [EC_PRIVATE_SCALAR_RANGE, TOY_PRIVATE_MATERIAL],
  [EC_PRIVATE_PAIR_MISMATCH, TOY_PRIVATE_MATERIAL],
] as const) {
  test(`${impl.mutationId}: exists in the frozen registry, deterministic, conserves fields outside targets, does not mutate in place`, () => {
    assert.ok(MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId));
    const a = impl.mutate(fixture as never, 'default');
    const b = impl.mutate(fixture as never, 'default');
    assert.deepEqual(a, b);
    const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, a as unknown as Record<string, unknown>, impl.directInterventionTargets);
    assert.deepEqual(violations, []);
    assert.ok(impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, a as unknown as Record<string, unknown>, f)));
  });
}

// ---------------------------------------------------------------------
// Artifact-level: real SPKI/PKCS8 artifacts
// ---------------------------------------------------------------------

test('unmutated real artifacts import cleanly (sanity check before testing the mutations)', () => {
  const spki = encodeSpki(TOY_PUBLIC_MATERIAL);
  const pkcs8 = encodePkcs8(TOY_PRIVATE_MATERIAL);
  assert.doesNotThrow(() => importEcSer(spki, 'public'));
  assert.doesNotThrow(() => importEcSer(pkcs8, 'private'));
});

test('EC-ROLE-CONTAINER-MISMATCH: a real, valid SPKI presented with requestedRole flipped to private', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = EC_ROLE_CONTAINER_MISMATCH.mutate({ artifact, requestedRole: 'public' }, 'default');
  assert.equal(mutated.requestedRole, 'private');
  assert.deepEqual(mutated.artifact, artifact);
  assert.throws(() => importEcSer(mutated.artifact, mutated.requestedRole));
});

test('EC-CURVE-SUBSTITUTION: corrupts the real secp256r1 OID in a genuine SPKI artifact, breaking import', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = EC_CURVE_SUBSTITUTION.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importEcSer(mutated.artifact, 'public'));
});

test('EC-PUBLIC-POINT-ENCODING: corrupts the point form octet in a real SPKI, breaking import', () => {
  const artifact = encodeSpki(TOY_PUBLIC_MATERIAL);
  const mutated = EC_PUBLIC_POINT_ENCODING.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importEcSer(mutated.artifact, 'public'));
});

test('EC-PUBLIC-DER-MALFORMED and EC-PRIVATE-DER-MALFORMED: corrupt real artifacts structurally', () => {
  const spki = encodeSpki(TOY_PUBLIC_MATERIAL);
  const pkcs8 = encodePkcs8(TOY_PRIVATE_MATERIAL);
  const mutatedPub = EC_PUBLIC_DER_MALFORMED.mutate({ artifact: spki }, 'default');
  const mutatedPriv = EC_PRIVATE_DER_MALFORMED.mutate({ artifact: pkcs8 }, 'default');
  assert.notDeepEqual(mutatedPub.artifact, spki);
  assert.notDeepEqual(mutatedPriv.artifact, pkcs8);
  assert.throws(() => importEcSer(mutatedPub.artifact, 'public'));
  assert.throws(() => importEcSer(mutatedPriv.artifact, 'private'));
});

test('EC-PRIVATE-PARAMS-ABSENT: removes [0] from a real PKCS8 artifact -- common-but-not-portable, normalizes rather than rejects', () => {
  const artifact = encodePkcs8(TOY_PRIVATE_MATERIAL);
  const mutated = EC_PRIVATE_PARAMS_ABSENT.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  const result = importEcSer(mutated.artifact, 'private');
  assert.equal(result.normalized, true, '[0] absence is common-but-not-portable and must normalize, per D-061, not reject');
  assert.deepEqual(result.material, TOY_PRIVATE_MATERIAL);
});

test('EC-PRIVATE-PARAMS-MISMATCH: [0] present but wrong curve OID -- rejected, distinct from PARAMS-ABSENT', () => {
  const artifact = encodePkcs8(TOY_PRIVATE_MATERIAL);
  const mutated = EC_PRIVATE_PARAMS_MISMATCH.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importEcSer(mutated.artifact, 'private'));
});

test('EC-PRIVATE-PUBKEY-ABSENT: removes [1] from a real PKCS8 artifact -- excluded from D_common, rejected, NEVER normalized (sharp contrast with PARAMS-ABSENT)', () => {
  const artifact = encodePkcs8(TOY_PRIVATE_MATERIAL);
  const mutated = EC_PRIVATE_PUBKEY_ABSENT.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.throws(() => importEcSer(mutated.artifact, 'private'));
});

// ---------------------------------------------------------------------
// adapter-transform and capability-transform
// ---------------------------------------------------------------------

test('EC-NATIVE-EXPORT-LEAK: toggles adapterReconstructsPubkey, material stays untouched', () => {
  const state = { material: TOY_PRIVATE_MATERIAL, adapterReconstructsPubkey: false };
  const mutated = EC_NATIVE_EXPORT_LEAK.mutate(state, 'default');
  assert.equal(mutated.adapterReconstructsPubkey, true);
  assert.deepEqual(mutated.material, TOY_PRIVATE_MATERIAL);
});

test('EC-ERROR-MAP-SWAP: mutates declaredErrorClass', () => {
  const state = { triggeringCondition: 'off-curve-point', declaredErrorClass: 'invalid_membership' };
  const mutated = EC_ERROR_MAP_SWAP.mutate(state, 'default');
  assert.notEqual(mutated.declaredErrorClass, 'invalid_membership');
});

test('EC-CAPABILITY-MANIFEST-MISMATCH: mutates a copy, never a frozen manifest object', () => {
  const declaration = Object.freeze({ capabilityId: 'ec-ser.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = EC_CAPABILITY_MANIFEST_MISMATCH.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  assert.equal(declaration.support, 'supported');
});

// ---------------------------------------------------------------------
// Gamma_0 subset checks + correspondence audit
// ---------------------------------------------------------------------

test('EC-ser non-material mechanisms: DirectInterventionTargets is a SUBSET of Gamma_0', () => {
  const cases: Array<{ mutationId: string; targets: readonly string[]; fieldToClause: Record<string, string> }> = [
    { mutationId: 'EC-ERROR-MAP-SWAP', targets: EC_ERROR_MAP_SWAP.directInterventionTargets, fieldToClause: { declaredErrorClass: 'ec-ser.error' } },
    { mutationId: 'EC-CAPABILITY-MANIFEST-MISMATCH', targets: EC_CAPABILITY_MANIFEST_MISMATCH.directInterventionTargets, fieldToClause: { support: 'ec-ser.cap' } },
  ];
  for (const { mutationId, targets, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(targets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${mutationId}: unmapped ${unmapped.join(', ')}`);
  }
});

test('M2.4.6 correspondence audit: EC-ser is 14/14, nothing phantom, nothing missing', () => {
  const registryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'ec-ser').map((e) => e.mutationId));
  const implementedIds = new Set(EC_SER_ALL_MUTATION_IDS);
  assert.equal(registryIds.size, 14);
  assert.equal(implementedIds.size, 14);
  assert.deepEqual([...registryIds].sort(), [...implementedIds].sort());
});
