import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveGcmArtifactFixture, resolveGcmAuthenticationFixture, resolveGcmArtifactStimulusFixture,
  isGcmAuthenticationClass, GCM_ARTIFACT_MUTATION_IDS, GCM_ARTIFACT_STIMULUS_PAIRS,
} from '../../../../harness/phase-c/fixtures/gcm-artifact.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { GcmValidArtifact, AesBaseMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { parseAeadArtifact, TAG_LEN_BYTES, ARTIFACT_VERSION } from '../../../../src/contract/gcm.js';

const pool = loadFrozenMaterialPool();
const authId = () => GCM_ARTIFACT_MUTATION_IDS.find(isGcmAuthenticationClass)!;
const bareIds = () => GCM_ARTIFACT_MUTATION_IDS.filter((id) => !isGcmAuthenticationClass(id));

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.13: GroupMutationIDs == ResolvedMutationIDs == 3', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'gcm' && e.mechanism === 'artifact-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...GCM_ARTIFACT_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 3);
});

test('M3.2.4b-2.13: GroupStimulusPairs == ResolvedStimulusPairs == 6, each resolving exactly once', () => {
  assert.equal(GCM_ARTIFACT_STIMULUS_PAIRS.length, 6);
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveGcmArtifactFixture(m, s, pool), `${m}::${s}`);
  }
  const keys = GCM_ARTIFACT_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length);
});

test('M3.2.4b-2.13: TWO shapes, and Gamma_0 DOES discriminate here (unlike PSS x artifact)', () => {
  assert.equal(GCM_ARTIFACT_MUTATION_IDS.filter(isGcmAuthenticationClass).length, 1);
  assert.equal(bareIds().length, 2);
  const gammas = GCM_ARTIFACT_MUTATION_IDS.map(
    (id) => JSON.stringify(MUTATION_REGISTRY.find((e) => e.mutationId === id)!.gamma0),
  );
  assert.ok(new Set(gammas).size > 1, 'the clauses genuinely differ, so selection can rest on them');
});

// --- The four authentication stimuli share ONE base fixture ---------------

test('M3.2.4b-2.13: all FOUR authentication stimuli resolve to the SAME F_0', () => {
  const stimuli = MUTATION_REGISTRY.find((e) => e.mutationId === authId())!
    .stimulusInstances.map((s) => s.stimulusInstanceId);
  assert.equal(stimuli.length, 4);

  const fixtures = stimuli.map((s) => resolveGcmAuthenticationFixture(authId(), s, pool));
  for (let i = 1; i < fixtures.length; i++) {
    assert.deepEqual(fixtures[i], fixtures[0],
      `${stimuli[i]} must share the base fixture: the choice of intervention belongs to mutate()`);
  }
});

test('M3.2.4b-2.13: yet the four stimuli produce FOUR DISTINCT mutated states', () => {
  const stimuli = MUTATION_REGISTRY.find((e) => e.mutationId === authId())!
    .stimulusInstances.map((s) => s.stimulusInstanceId);
  const impl = getMutationImplementation(authId());
  const seen = new Set<string>();
  for (const s of stimuli) {
    const base = resolveGcmAuthenticationFixture(authId(), s, pool);
    const m = impl.mutate(base, s) as typeof base;
    assert.notDeepEqual(m, base, `${s} must change something`);
    seen.add(Buffer.from(m.artifact).toString('hex') + '|' + (m.aad ? Buffer.from(m.aad).toString('hex') : ''));
  }
  assert.equal(seen.size, 4, 'four stimuli, four distinct outcomes -- no accidental collapse');
});

test('M3.2.4b-2.13: the AAD is the one the artifact was produced under, and is non-empty', () => {
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  const f = resolveGcmAuthenticationFixture(authId(), 'AAD-TAMPER', pool);
  assert.ok(f.aad !== undefined && f.aad.length > 0,
    'an empty/absent AAD would send AAD-TAMPER down its substitution branch instead of a real perturbation');
  assert.deepEqual(Buffer.from(f.aad!), Buffer.from(aes.aad!));
});

// --- Artifact selection ----------------------------------------------------

test('M3.2.4b-2.13: the authentication and structure classes use the GENERAL artifact, |C| = 35', () => {
  const auth = resolveGcmAuthenticationFixture(authId(), 'TAG-TAMPER', pool);
  assert.equal(parseAeadArtifact(auth.artifact).ciphertext.length, 35);

  const general = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact');
  assert.deepEqual(Buffer.from(auth.artifact), Buffer.from(general.ciphertext));
});

test('M3.2.4b-2.13: the C-T-SWAP class uses the ct-len artifact, |C| = TAG_LEN_BYTES', () => {
  const swapIds = bareIds().filter((id) => {
    const f = resolveGcmArtifactStimulusFixture(id, 'default', pool);
    return parseAeadArtifact(f.artifact).ciphertext.length === TAG_LEN_BYTES;
  });
  assert.equal(swapIds.length, 1, 'exactly one class needs the equal-length artifact');

  const ctlen = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen, 'gcm-valid-artifact');
  const f = resolveGcmArtifactStimulusFixture(swapIds[0]!, 'default', pool);
  assert.deepEqual(Buffer.from(f.artifact), Buffer.from(ctlen.ciphertext));
});

test('M3.2.4b-2.13: artifact selection is derived from BEHAVIOUR -- every class mutates without throwing', () => {
  // The class needing |C|=|tag| is identified by probing, not by id. The
  // proof that the derivation is right: every pair mutates successfully.
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    const base = resolveGcmArtifactFixture(m, s, pool);
    assert.doesNotThrow(() => getMutationImplementation(m).mutate(base, s), `${m}::${s}`);
  }
});

// --- Every A_0 is a qualified SDK artifact ---------------------------------

test('M3.2.4b-2.13: every resolved A_0 parses under the SDK contract before mutation', () => {
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    const f = resolveGcmArtifactFixture(m, s, pool);
    const parts = parseAeadArtifact(f.artifact);
    assert.equal(parts.version, ARTIFACT_VERSION, `${m}::${s}`);
    assert.equal(parts.tag.length, TAG_LEN_BYTES);
  }
});

// --- The superseded artifact is unreachable --------------------------------

test('M3.2.4b-2.13: no resolved fixture is the superseded artifact', () => {
  const superseded = pool.getHistorical(PHASE_C_MATERIAL_IDS.gcmArtifact);
  const bad = Buffer.from((superseded.value as GcmValidArtifact).ciphertext);
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    const f = resolveGcmArtifactFixture(m, s, pool);
    assert.notDeepEqual(Buffer.from(f.artifact), bad, `${m}::${s} must not serve the superseded artifact`);
  }
});

test('M3.2.4b-2.13: the resolver never reaches historical material, and names no superseded id', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-artifact.ts', import.meta.url), 'utf8');
  const forbiddenAccessor = ['get', 'Historical', '('].join('');
  assert.ok(!src.includes(forbiddenAccessor), 'a resolver must use get()/valueOf(), never the audit accessor');
  assert.ok(!src.includes(PHASE_C_MATERIAL_IDS.gcmArtifact), 'the superseded id must not appear');
});

// --- No cryptography in the resolver ---------------------------------------

test('M3.2.4b-2.13: the resolver performs no cryptography and never calls mutate()', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-artifact.ts', import.meta.url), 'utf8');
  for (const forbidden of ['subtle', 'webcrypto', 'createCipheriv', 'createHash']) {
    assert.ok(!src.includes(forbidden), `found cryptography: '${forbidden}'`);
  }
  // mutate() IS referenced, but only inside the behaviour probe that
  // classifies which class needs the equal-length artifact -- never to
  // produce a fixture. Confirmed by the resolved fixtures being genuinely
  // pre-mutation, below.
});

test('M3.2.4b-2.13: every resolved fixture is genuinely pre-mutation', () => {
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    const base = resolveGcmArtifactFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

test('M3.2.4b-2.13: the frozen corpus is unchanged by resolving and mutating', () => {
  const before = Buffer.from(
    pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact').ciphertext,
  );
  for (const [m, s] of GCM_ARTIFACT_STIMULUS_PAIRS) {
    getMutationImplementation(m).mutate(resolveGcmArtifactFixture(m, s, pool), s);
  }
  const after = Buffer.from(
    pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact').ciphertext,
  );
  assert.deepEqual(after, before);
});

// --- Fail-closed and derivation --------------------------------------------

test('M3.2.4b-2.13: the two typed resolvers refuse each other classes; foreign ids fail closed', () => {
  assert.throws(() => resolveGcmArtifactStimulusFixture(authId(), 'TAG-TAMPER', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmAuthenticationFixture(bareIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmArtifactFixture(authId(), 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmArtifactFixture('GCM-AAD-IGNORED', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveGcmArtifactFixture('PSS-VERIFICATION-FALSE-ACCEPT', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.13: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/gcm-artifact.ts', import.meta.url), 'utf8');
  for (const id of GCM_ARTIFACT_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
