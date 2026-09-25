import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolvePssArtifactFixture, resolvePssVerificationStimulusFixture, resolvePssFalseRejectStimulusFixture,
  isPssFalseRejectClass, PSS_ARTIFACT_MUTATION_IDS, PSS_ARTIFACT_STIMULUS_PAIRS,
  PSS_SECOND_SIGNATURE_MATERIAL_ID,
} from '../../../../harness/phase-c/fixtures/pss-artifact.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, loadFrozenMaterialRecords, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { PssValidSignatureArtifact, Rsa3072KeyPairMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { SALT_LEN_BYTES } from '../../../../src/contract/pss.js';

const pool = loadFrozenMaterialPool();
const falseRejectId = () => PSS_ARTIFACT_MUTATION_IDS.find(isPssFalseRejectClass)!;
const falseAcceptId = () => PSS_ARTIFACT_MUTATION_IDS.find((id) => !isPssFalseRejectClass(id))!;

async function verifies(signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  const { webcrypto } = await import('node:crypto');
  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const pub = await webcrypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: b64u(rsa.n), e: b64u(rsa.e) }, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify'],
  );
  return webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: SALT_LEN_BYTES }, pub, signature, message);
}

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.8: PSSArtifactMutationIDs == ResolvedPSSArtifactMutationIDs (2 classes, 2 pairs)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'pss' && e.mechanism === 'artifact-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...PSS_ARTIFACT_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 2);
  assert.equal(PSS_ARTIFACT_STIMULUS_PAIRS.length, 2);
  for (const [m, s] of PSS_ARTIFACT_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolvePssArtifactFixture(m, s, pool), `${m}::${s}`);
  }
});

test('M3.2.4b-2.8: TWO shapes -- both being artifact-transform does not make them share one', () => {
  const a = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  const b = resolvePssFalseRejectStimulusFixture(falseRejectId(), 'default', pool);
  assert.deepEqual(Object.keys(a).sort(), ['message', 'signature']);
  assert.deepEqual(Object.keys(b).sort(), ['alternateSignature', 'message', 'signature']);
});

test('M3.2.4b-2.8: Gamma_0 cannot separate these two -- shape selection comes from directInterventionTargets', () => {
  const gammas = PSS_ARTIFACT_MUTATION_IDS.map(
    (id) => JSON.stringify(MUTATION_REGISTRY.find((e) => e.mutationId === id)!.gamma0),
  );
  assert.equal(new Set(gammas).size, 1, 'both classes share the same Gamma_0');
  // ...so the discriminator must be the intervention targets, and it is.
  assert.equal(PSS_ARTIFACT_MUTATION_IDS.filter(isPssFalseRejectClass).length, 1);
});

// --- Valid(A_0) = true, by identity to frozen material ---------------------

test('M3.2.4b-2.8: A_0 IS the frozen material -- byte-identical, not merely the right length', () => {
  const a0 = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');
  const f = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  assert.deepEqual(Buffer.from(f.signature), Buffer.from(a0.signature));
  assert.deepEqual(Buffer.from(f.message), Buffer.from(a0.message));
});

test('M3.2.4b-2.8: Valid(A_0) = true, verified cryptographically OUTSIDE the resolver', async () => {
  const f = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  assert.equal(await verifies(f.signature, f.message), true);
});

test('M3.2.4b-2.8: the resolver is not a verifier -- no cryptography inside it', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-artifact.ts', import.meta.url), 'utf8');
  for (const forbidden of ['subtle', 'createVerify', 'webcrypto', 'createHash']) {
    assert.ok(!src.includes(forbidden), `a fixture resolver must not perform cryptography; found '${forbidden}'`);
  }
  const noMutate = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(noMutate));
});

// --- The false-reject pair's own preconditions -----------------------------

test('M3.2.4b-2.8: BOTH signatures are independently valid over the SAME message', async () => {
  const f = resolvePssFalseRejectStimulusFixture(falseRejectId(), 'default', pool);
  assert.equal(await verifies(f.signature, f.message), true, 'sigma_1 must verify');
  assert.equal(await verifies(f.alternateSignature, f.message), true, 'sigma_2 must verify');
  assert.notDeepEqual(Buffer.from(f.signature), Buffer.from(f.alternateSignature), 'and they must differ');
});

test('M3.2.4b-2.8: after the swap BOTH remain valid -- the correct verify() outcome is true either way', async () => {
  const base = resolvePssFalseRejectStimulusFixture(falseRejectId(), 'default', pool);
  const mutated = getMutationImplementation(falseRejectId()).mutate(base, 'default') as typeof base;
  assert.deepEqual(Buffer.from(mutated.signature), Buffer.from(base.alternateSignature), 'roles swapped');
  assert.deepEqual(Buffer.from(mutated.alternateSignature), Buffer.from(base.signature));
  assert.equal(await verifies(mutated.signature, mutated.message), true,
    'a backend rejecting the swapped-in alternate is the false-reject this class catches');
});

test('M3.2.4b-2.8: the second signature is genuinely frozen material, cross-qualified like the first', () => {
  const records = loadFrozenMaterialRecords();
  const second = records.find((r) => r.materialId === PSS_SECOND_SIGNATURE_MATERIAL_ID);
  assert.ok(second, 'the corpus extension must be present');
  assert.equal(second!.materialType, 'pss-valid-signature');
  assert.equal(second!.provenance.origin, 'generated-during-m3');
  assert.equal(second!.provenance.generatorVersion, 'M3.2.4b-2.8');
  // Same key, and the extension declares its dependence on the first.
  const value = second!.value as PssValidSignatureArtifact;
  assert.equal(value.sourceMaterialId, PHASE_C_MATERIAL_IDS.rsa);
  assert.ok(second!.provenance.sourceMaterialIds?.includes(PHASE_C_MATERIAL_IDS.pssSignature));
});

test('M3.2.4b-2.8: the corpus extension left sigma_01 byte-identical -- appended, never rewritten', () => {
  const first = loadFrozenMaterialRecords().find((r) => r.materialId === PHASE_C_MATERIAL_IDS.pssSignature)!;
  assert.equal(first.sha256, '1bee1e121b2b8d2a1fbcfd07ef49319bb92ce9e872dfdeaa82984db51074627b');
  assert.equal(first.provenance.generatorVersion, 'M3.2.4a-6', 'its original provenance is preserved');
});

// --- Fresh-copy semantics and frozen-corpus isolation ----------------------

test('M3.2.4b-2.8: successive resolutions return DISTINCT arrays with IDENTICAL bytes', () => {
  const a = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  const b = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  assert.notEqual(a.signature, b.signature, 'not the same reference');
  assert.deepEqual(Buffer.from(a.signature), Buffer.from(b.signature), 'but the same bytes');
});

test('M3.2.4b-2.8: mutate(A_0) != A_0, AND the frozen corpus is unchanged afterwards', () => {
  const a0 = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');
  const before = Buffer.from(a0.signature);

  const base = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  const mutated = getMutationImplementation(falseAcceptId()).mutate(base, 'default') as typeof base;
  assert.notDeepEqual(Buffer.from(mutated.signature), Buffer.from(base.signature), 'the artifact really is perturbed');

  const after = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');
  assert.deepEqual(Buffer.from(after.signature), before, 'the frozen corpus must be untouched by any mutation');

  // And a fresh resolution still yields the original.
  const again = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  assert.deepEqual(Buffer.from(again.signature), before);
});

test('M3.2.4b-2.8: the corrupted signature no longer verifies -- the intervention is real', async () => {
  const base = resolvePssVerificationStimulusFixture(falseAcceptId(), 'default', pool);
  const mutated = getMutationImplementation(falseAcceptId()).mutate(base, 'default') as typeof base;
  assert.equal(await verifies(mutated.signature, mutated.message), false,
    'a backend returning true here is the false-accept this class catches');
});

// --- Fail-closed -----------------------------------------------------------

test('M3.2.4b-2.8: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  assert.throws(() => resolvePssArtifactFixture(falseAcceptId(), 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolvePssArtifactFixture('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER', pool), FixtureResolutionError);
  assert.throws(() => resolvePssArtifactFixture('PSS-HASH-PROFILE-BYPASS', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.8: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-artifact.ts', import.meta.url), 'utf8');
  for (const id of PSS_ARTIFACT_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
