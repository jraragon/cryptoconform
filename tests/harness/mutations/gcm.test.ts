import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  GCM_REQUEST_MUTATIONS, GCM_AUTHENTICATION_BYPASS, GCM_ARTIFACT_C_T_SWAP,
  GCM_ARTIFACT_STRUCTURE_CORRUPTION, GCM_PROVIDER_CAPABILITY_MISMATCH,
  GCM_ERROR_MISCLASSIFICATION, GCM_ALL_MUTATION_IDS,
} from '../../../harness/mutations/gcm.js';
import { touchedFieldsOutsideAllowed, fieldChanged, directTargetsAreSubsetOfGamma0 } from '../../../harness/mutations/framework.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { buildAeadArtifact, KEY_LEN_BYTES, IV_LEN_BYTES, TAG_LEN_BYTES, type GcmEncryptRequest } from '../../../src/contract/gcm.js';

function baseFixture(): GcmEncryptRequest {
  return {
    key: new Uint8Array(KEY_LEN_BYTES).fill(0x11),
    plaintext: new Uint8Array([1, 2, 3, 4]),
    aad: undefined,
    iv: new Uint8Array(IV_LEN_BYTES).fill(0x22),
    tagLengthBits: TAG_LEN_BYTES * 8,
  };
}

// A REAL AES-256-GCM artifact via Node's webcrypto, not fabricated bytes --
// grounds the artifact-transform tests in genuine cryptography.
async function realArtifact(): Promise<Uint8Array> {
  const fixture = baseFixture();
  const key = await webcrypto.subtle.importKey('raw', fixture.key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertextWithTag = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: fixture.iv, tagLength: fixture.tagLengthBits },
    key, fixture.plaintext,
  ));
  const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - TAG_LEN_BYTES);
  const tag = ciphertextWithTag.slice(ciphertextWithTag.length - TAG_LEN_BYTES);
  return buildAeadArtifact(fixture.iv, ciphertext, tag);
}

// ---------------------------------------------------------------------
// request-transform: 8 classes, same four-property pattern as HKDF
// ---------------------------------------------------------------------
for (const impl of GCM_REQUEST_MUTATIONS) {
  const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === impl.mutationId);

  test(`${impl.mutationId}: exists in the frozen registry`, () => {
    assert.ok(registryEntry, `${impl.mutationId} must correspond to a registry entry`);
  });

  for (const instance of registryEntry?.stimulusInstances ?? [{ stimulusInstanceId: 'default' }]) {
    const stimulusId = instance.stimulusInstanceId;

    test(`${impl.mutationId} [${stimulusId}]: deterministic`, () => {
      const fixture = baseFixture();
      assert.deepEqual(impl.mutate(fixture, stimulusId), impl.mutate(fixture, stimulusId));
    });

    test(`${impl.mutationId} [${stimulusId}]: fields outside directInterventionTargets are conserved`, () => {
      const fixture = baseFixture();
      const mutated = impl.mutate(fixture, stimulusId) as unknown as Record<string, unknown>;
      const violations = touchedFieldsOutsideAllowed(fixture as unknown as Record<string, unknown>, mutated, impl.directInterventionTargets);
      assert.deepEqual(violations, []);
    });

    test(`${impl.mutationId} [${stimulusId}]: target field actually changes`, () => {
      const fixture = baseFixture();
      const mutated = impl.mutate(fixture, stimulusId) as unknown as Record<string, unknown>;
      assert.ok(impl.directInterventionTargets.some((f) => fieldChanged(fixture as unknown as Record<string, unknown>, mutated, f)));
    });

    test(`${impl.mutationId} [${stimulusId}]: does not mutate the input fixture in place`, () => {
      const fixture = baseFixture();
      const snap = { key: Array.from(fixture.key), plaintext: Array.from(fixture.plaintext), aad: fixture.aad ? Array.from(fixture.aad) : undefined, iv: Array.from(fixture.iv), tagLengthBits: fixture.tagLengthBits };
      impl.mutate(fixture, stimulusId);
      const after = { key: Array.from(fixture.key), plaintext: Array.from(fixture.plaintext), aad: fixture.aad ? Array.from(fixture.aad) : undefined, iv: Array.from(fixture.iv), tagLengthBits: fixture.tagLengthBits };
      assert.deepEqual(after, snap);
    });
  }
}

test('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS: the three instances (80,16,0) share ONE mutationId, tagLengthBits set correctly for each', () => {
  const impl = GCM_REQUEST_MUTATIONS.find((m) => m.mutationId === 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS')!;
  assert.equal(impl.mutate(baseFixture(), 'tagLength-80').tagLengthBits, 80);
  assert.equal(impl.mutate(baseFixture(), 'tagLength-below-floor-16').tagLengthBits, 16);
  assert.equal(impl.mutate(baseFixture(), 'tagLength-below-floor-0').tagLengthBits, 0);
  assert.equal(impl.mutationId, 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS');
});

test('GCM-AAD-ABSENT-EMPTY-DIVERGENCE: toggles undefined <-> empty specifically', () => {
  const impl = GCM_REQUEST_MUTATIONS.find((m) => m.mutationId === 'GCM-AAD-ABSENT-EMPTY-DIVERGENCE')!;
  assert.deepEqual(impl.mutate(baseFixture(), 'default').aad, new Uint8Array(0));
  assert.equal(impl.mutate({ ...baseFixture(), aad: new Uint8Array(0) }, 'default').aad, undefined);
});

// ---------------------------------------------------------------------
// artifact-transform: 3 classes, grounded in a REAL AES-GCM artifact
// ---------------------------------------------------------------------

test('GCM-AUTHENTICATION-BYPASS: all four tamper instances change exactly their own target, artifact stays valid-length', async () => {
  const artifact = await realArtifact();
  for (const instanceId of ['TAG-TAMPER', 'IV-TAMPER', 'CIPHERTEXT-TAMPER'] as const) {
    const state = { artifact, aad: undefined };
    const mutated = GCM_AUTHENTICATION_BYPASS.mutate(state, instanceId);
    assert.notDeepEqual(mutated.artifact, artifact, `${instanceId} must change the artifact bytes`);
    assert.equal(mutated.artifact.length, artifact.length, `${instanceId} must not change artifact length`);
    assert.deepEqual(mutated.aad, undefined, `${instanceId} must not touch aad`);
  }
  const aadTamper = GCM_AUTHENTICATION_BYPASS.mutate({ artifact, aad: undefined }, 'AAD-TAMPER');
  assert.deepEqual(aadTamper.artifact, artifact, 'AAD-TAMPER must not touch the artifact');
  assert.notEqual(aadTamper.aad, undefined);
});

test('GCM-AUTHENTICATION-BYPASS: does not mutate the input artifact in place', async () => {
  const artifact = await realArtifact();
  const snapshot = Array.from(artifact);
  GCM_AUTHENTICATION_BYPASS.mutate({ artifact, aad: undefined }, 'TAG-TAMPER');
  assert.deepEqual(Array.from(artifact), snapshot);
});

test('GCM-ARTIFACT-C-T-SWAP: swaps ciphertext and tag when lengths match, changes the artifact', async () => {
  // Build a fixture whose ciphertext length equals TAG_LEN_BYTES (16 bytes plaintext).
  const fixture = { ...baseFixture(), plaintext: new Uint8Array(TAG_LEN_BYTES).fill(0x5) };
  const key = await webcrypto.subtle.importKey('raw', fixture.key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: fixture.iv, tagLength: fixture.tagLengthBits }, key, fixture.plaintext));
  const artifact = buildAeadArtifact(fixture.iv, ct.slice(0, ct.length - TAG_LEN_BYTES), ct.slice(ct.length - TAG_LEN_BYTES));

  const mutated = GCM_ARTIFACT_C_T_SWAP.mutate({ artifact }, 'default');
  assert.notDeepEqual(mutated.artifact, artifact);
  assert.equal(mutated.artifact.length, artifact.length);
});

test('GCM-ARTIFACT-STRUCTURE-CORRUPTION: truncates below the structural floor, deterministically', async () => {
  const artifact = await realArtifact();
  const mutated = GCM_ARTIFACT_STRUCTURE_CORRUPTION.mutate({ artifact }, 'default');
  assert.ok(mutated.artifact.length < artifact.length);
  assert.deepEqual(mutated.artifact, GCM_ARTIFACT_STRUCTURE_CORRUPTION.mutate({ artifact }, 'default').artifact);
});

// ---------------------------------------------------------------------
// capability-transform and adapter-transform: 2 classes
// ---------------------------------------------------------------------

test('GCM-PROVIDER-CAPABILITY-MISMATCH: mutates a copy, never a frozen manifest object', () => {
  const declaration = Object.freeze({ capabilityId: 'gcm.provider.support', kind: 'provider-support' as const, support: 'supported' as const });
  const mutated = GCM_PROVIDER_CAPABILITY_MISMATCH.mutate(declaration, 'default');
  assert.equal(mutated.support, 'unsupported');
  assert.equal(declaration.support, 'supported');
  assert.notEqual(mutated, declaration);
});

test('GCM-ERROR-MISCLASSIFICATION: mutates declaredErrorClass deterministically', () => {
  const state = { triggeringCondition: 'undersized-ciphertext', declaredErrorClass: 'authentication_failure' };
  const mutated = GCM_ERROR_MISCLASSIFICATION.mutate(state, 'default');
  assert.notEqual(mutated.declaredErrorClass, state.declaredErrorClass);
  assert.equal(mutated.triggeringCondition, state.triggeringCondition);
});

// ---------------------------------------------------------------------
// registry-level Gamma_0 subset check, for the non-request mechanisms
// ---------------------------------------------------------------------

test('GCM non-request mechanisms: DirectInterventionTargets is a SUBSET of Gamma_0, never equal to it where Gamma_0 has downstream clauses', () => {
  const cases: Array<{ mutationId: string; targets: readonly string[]; fieldToClause: Record<string, string> }> = [
    { mutationId: 'GCM-AUTHENTICATION-BYPASS', targets: GCM_AUTHENTICATION_BYPASS.directInterventionTargets, fieldToClause: { artifact: 'gcm.authentication', aad: 'gcm.authentication' } },
    { mutationId: 'GCM-ARTIFACT-STRUCTURE-CORRUPTION', targets: GCM_ARTIFACT_STRUCTURE_CORRUPTION.directInterventionTargets, fieldToClause: { artifact: 'gcm.artifact' } },
    { mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', targets: GCM_PROVIDER_CAPABILITY_MISMATCH.directInterventionTargets, fieldToClause: { support: 'gcm.cap.provider' } },
  ];
  for (const { mutationId, targets, fieldToClause } of cases) {
    const registryEntry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
    const { isSubset, unmapped } = directTargetsAreSubsetOfGamma0(targets, fieldToClause, registryEntry.gamma0);
    assert.ok(isSubset, `${mutationId}: unmapped targets ${unmapped.join(', ')}`);
  }
  // GCM-AUTHENTICATION-BYPASS and GCM-ARTIFACT-STRUCTURE-CORRUPTION both
  // have a validation-layer clause beyond their own direct targets --
  // genuine subset, confirmed explicitly.
  const authBypass = MUTATION_REGISTRY.find((e) => e.mutationId === 'GCM-AUTHENTICATION-BYPASS')!;
  assert.ok(authBypass.gamma0.includes('gcm.validation'));
});

test('M2.4.6 correspondence audit: GCM is 13/13, nothing phantom, nothing missing', () => {
  const gcmRegistryIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'gcm').map((e) => e.mutationId));
  const implementedIds = new Set(GCM_ALL_MUTATION_IDS);
  assert.equal(gcmRegistryIds.size, 13);
  assert.equal(implementedIds.size, 13);
  assert.deepEqual([...gcmRegistryIds].sort(), [...implementedIds].sort());
});
