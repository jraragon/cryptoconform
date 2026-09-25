import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveRsaArtifactFixture, resolveRsaArtifactStimulusFixture, resolveRsaPublicMaterialFixture,
  resolveRsaPrivateMaterialFixture, resolveRsaRoleContainerFixture,
  isRsaBareArtifactClass, isRsaPublicMaterialClass, isRsaPrivateMaterialClass, isRsaRoleContainerClass,
  RSA_ARTIFACT_MUTATION_IDS, RSA_ARTIFACT_STIMULUS_PAIRS,
} from '../../../../harness/phase-c/fixtures/rsa-ser-artifact.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../../../../harness/phase-c/material/load.js';
import type { Rsa3072KeyPairMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { importRsaSer } from '../../../../src/contract/rsa-ser.js';
import type { RsaPrivateMaterial } from '../../../../src/contract/rsa-ser.js';

const pool = loadFrozenMaterialPool();
const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
const bareIds = () => RSA_ARTIFACT_MUTATION_IDS.filter(isRsaBareArtifactClass);
const pubIds = () => RSA_ARTIFACT_MUTATION_IDS.filter(isRsaPublicMaterialClass);
const privIds = () => RSA_ARTIFACT_MUTATION_IDS.filter(isRsaPrivateMaterialClass);
const roleId = () => RSA_ARTIFACT_MUTATION_IDS.find(isRsaRoleContainerClass)!;
function gcd(a: bigint, b: bigint): bigint { return b === 0n ? a : gcd(b, a % b); }

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.15: GroupMutationIDs == ResolvedMutationIDs == 15', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'rsa-ser' && e.mechanism === 'artifact-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...RSA_ARTIFACT_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 15);
});

test('M3.2.4b-2.15: GroupStimulusPairs == ResolvedStimulusPairs == 19, each resolving exactly once', () => {
  assert.equal(RSA_ARTIFACT_STIMULUS_PAIRS.length, 19);
  for (const [m, s] of RSA_ARTIFACT_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveRsaArtifactFixture(m, s, pool), `${m}::${s}`);
  }
  const keys = RSA_ARTIFACT_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length);
});

test('M3.2.4b-2.15: the FOUR shapes are covered in the 6+5+3+1 distribution', () => {
  assert.equal(pubIds().length, 6);
  assert.equal(bareIds().length, 5);
  assert.equal(privIds().length, 3);
  assert.equal(RSA_ARTIFACT_MUTATION_IDS.filter(isRsaRoleContainerClass).length, 1);
  assert.equal(6 + 5 + 3 + 1, RSA_ARTIFACT_MUTATION_IDS.length);
});

test('M3.2.4b-2.15: shape classification is derived from intervention targets, not from ids', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-artifact.ts', import.meta.url), 'utf8');
  for (const id of RSA_ARTIFACT_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
  // A public-material class can only touch n and e, since those are the only
  // components RsaPublicMaterial has.
  for (const id of pubIds()) {
    const t = getMutationImplementation(id).directInterventionTargets.map(String);
    assert.ok(t.every((x) => x === 'n' || x === 'e'), `${id}: ${JSON.stringify(t)}`);
  }
  for (const id of privIds()) {
    const t = getMutationImplementation(id).directInterventionTargets.map(String);
    assert.ok(t.some((x) => !['n', 'e'].includes(x)), `${id}: ${JSON.stringify(t)}`);
  }
});

// --- The five relational stimuli --------------------------------------------

test('M3.2.4b-2.15: the five PRIVATE-RELATIONAL-BYPASS stimuli share ONE F_0', () => {
  const id = privIds().find((i) => MUTATION_REGISTRY.find((e) => e.mutationId === i)!.stimulusInstances.length === 5)!;
  const stimuli = MUTATION_REGISTRY.find((e) => e.mutationId === id)!.stimulusInstances.map((s) => s.stimulusInstanceId);
  assert.equal(stimuli.length, 5);
  const fixtures = stimuli.map((s) => resolveRsaPrivateMaterialFixture(id, s, pool));
  for (let i = 1; i < fixtures.length; i++) assert.deepEqual(fixtures[i], fixtures[0], stimuli[i]);
});

test('M3.2.4b-2.15: each of the five breaks EXACTLY its own CRT relation', () => {
  const id = privIds().find((i) => MUTATION_REGISTRY.find((e) => e.mutationId === i)!.stimulusInstances.length === 5)!;
  const impl = getMutationImplementation(id);
  const F0 = resolveRsaPrivateMaterialFixture(id, 'n-neq-pq', pool);
  const lambda = ((F0.p - 1n) * (F0.q - 1n)) / gcd(F0.p - 1n, F0.q - 1n);

  const checks: Record<string, (m: RsaPrivateMaterial) => boolean> = {
    'n-neq-pq': (m) => m.p * m.q === m.n,
    'ed-not-1': (m) => (m.e * m.d) % lambda === 1n,
    'edP-not-1': (m) => m.dP === m.d % (m.p - 1n),
    'edQ-not-1': (m) => m.dQ === m.d % (m.q - 1n),
    'qqInv-not-1': (m) => (m.qInv * m.q) % m.p === 1n,
  };

  // Every relation holds in the baseline.
  for (const [name, holds] of Object.entries(checks)) {
    assert.equal(holds(F0), true, `baseline must satisfy ${name}`);
  }
  // Each stimulus breaks its own and only its own.
  for (const stimulus of Object.keys(checks)) {
    const mutated = impl.mutate(F0, stimulus) as RsaPrivateMaterial;
    assert.equal(checks[stimulus]!(mutated), false, `${stimulus} must break its own relation`);
    for (const [other, holds] of Object.entries(checks)) {
      if (other === stimulus) continue;
      // A broken n propagates: n appears in no other check here, but d does,
      // so only genuinely independent relations are asserted to survive.
      if (stimulus === 'ed-not-1' && (other === 'edP-not-1' || other === 'edQ-not-1')) continue;
      assert.equal(holds(mutated), true, `${stimulus} must NOT break ${other}`);
    }
  }
});

// --- Artifact assignment ----------------------------------------------------

test('M3.2.4b-2.15: exactly TWO serialized classes require SPKI, established by probing', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, () => {
    const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
    return spkiBytes(r);
  });
  const onSpki = bareIds().filter((id) => {
    const f = resolveRsaArtifactStimulusFixture(id, 'default', pool);
    return Buffer.compare(Buffer.from(f.artifact), Buffer.from(spki)) === 0;
  });
  assert.equal(onSpki.length, 2, 'the two AlgorithmIdentifier classes');
  // And they genuinely reject the private container.
  const pki = resolveRsaArtifactStimulusFixture(bareIds().find((i) => !onSpki.includes(i))!, 'default', pool).artifact;
  for (const id of onSpki) {
    assert.throws(() => getMutationImplementation(id).mutate({ artifact: pki }, "default"), Error, id);
  }
});

test('M3.2.4b-2.15: the four role-agnostic classes use PrivateKeyInfo -- both containers are covered', () => {
  const used = new Set<string>();
  for (const id of [...bareIds(), roleId()]) {
    const f = id === roleId()
      ? resolveRsaRoleContainerFixture(id, 'default', pool)
      : resolveRsaArtifactStimulusFixture(id, 'default', pool);
    let role: string | undefined;
    for (const candidate of ['public', 'private'] as const) {
      try { role = importRsaSer(f.artifact, candidate).role; break; } catch { /* try the other */ }
    }
    assert.ok(role !== undefined, `${id}: its artifact imports under neither role`);
    used.add(role!);
  }
  assert.equal(used.size, 2, 'Coverage(SPKI) > 0 AND Coverage(PrivateKeyInfo) > 0');
});

test('M3.2.4b-2.15: artifacts come only from the qualified descriptors, never a direct encoder call', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-artifact.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('deriveArtifact'));
  const lines = src.split('\n');
  const start = lines.findIndex((l) => l.includes('const spkiEncoder'));
  const end = lines.findIndex((l) => l.includes('function derivedSpki'));
  assert.ok(start > 0 && end > start);
  const stray = lines.filter((l, i) => /encode(Spki|PrivateKeyInfo)\(/.test(l) && (i < start || i > end));
  assert.deepEqual(stray.map((l) => l.trim()), [], 'an encoder call outside the callback region bypasses the hash pin');
  assert.ok(!/[0-9a-f]{40,}/i.test(src), 'no long hex literal may appear');
});

// --- Material fixtures ------------------------------------------------------

test('M3.2.4b-2.15: material fixtures carry the frozen RSA-3072 key', () => {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const pub = resolveRsaPublicMaterialFixture(pubIds()[0]!, 'default', pool);
  assert.equal(pub.n, big(r.n));
  assert.equal(pub.e, big(r.e));
  assert.equal(pub.n.toString(2).length, 3072);

  const priv = resolveRsaPrivateMaterialFixture(privIds()[0]!, 'default', pool);
  assert.equal(priv.d, big(r.d));
  assert.equal(priv.p, big(r.p));
});

test('M3.2.4b-2.15: the private baseline satisfies every relation these classes exist to break', () => {
  const m = resolveRsaPrivateMaterialFixture(privIds()[0]!, 'default', pool);
  const lambda = ((m.p - 1n) * (m.q - 1n)) / gcd(m.p - 1n, m.q - 1n);
  assert.equal(m.p * m.q, m.n);
  assert.equal((m.e * m.d) % lambda, 1n);
  assert.equal(m.dP, m.d % (m.p - 1n));
  assert.equal(m.dQ, m.d % (m.q - 1n));
  assert.equal((m.qInv * m.q) % m.p, 1n);
  assert.notEqual(m.p, m.q, 'p = q would make the domain bypass a no-op');
});

// --- Role container ---------------------------------------------------------

test('M3.2.4b-2.15: the role-container baseline AGREES, and the mutation creates the mismatch', () => {
  const base = resolveRsaRoleContainerFixture(roleId(), 'default', pool);
  assert.doesNotThrow(() => importRsaSer(base.artifact, base.requestedRole),
    'artifact and requested role must agree before mutation');
  const mutated = getMutationImplementation(roleId()).mutate(base, 'default') as typeof base;
  assert.notEqual(mutated.requestedRole, base.requestedRole);
  assert.deepEqual(Buffer.from(mutated.artifact), Buffer.from(base.artifact), 'only the role is intervened on');
  assert.throws(() => importRsaSer(mutated.artifact, mutated.requestedRole), 'the mutated pairing must not import');
});

// --- H3 / isolation / fail-closed ------------------------------------------

test('M3.2.4b-2.15 (H3): all 19 pairs are genuinely pre-mutation, with no runtime cryptography', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/rsa-ser-artifact.ts', import.meta.url), 'utf8');
  for (const forbidden of ['webcrypto', 'subtle', 'generateKey', 'randomBytes']) {
    assert.ok(!src.includes(forbidden), `found '${forbidden}'`);
  }
  for (const [m, s] of RSA_ARTIFACT_STIMULUS_PAIRS) {
    const base = resolveRsaArtifactFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

test('M3.2.4b-2.15: the frozen corpus is unchanged by resolving and mutating all 19', () => {
  const before = Buffer.from(pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair').n);
  for (const [m, s] of RSA_ARTIFACT_STIMULUS_PAIRS) {
    getMutationImplementation(m).mutate(resolveRsaArtifactFixture(m, s, pool), s);
  }
  const after = Buffer.from(pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair').n);
  assert.deepEqual(after, before);
});

test('M3.2.4b-2.15: the four typed resolvers refuse each other classes; foreign ids fail closed', () => {
  assert.throws(() => resolveRsaArtifactStimulusFixture(pubIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaPublicMaterialFixture(privIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaPrivateMaterialFixture(pubIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaRoleContainerFixture(bareIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaArtifactFixture(bareIds()[0]!, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaArtifactFixture('RSA-SER-ERROR-MISCLASSIFICATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveRsaArtifactFixture('EC-CURVE-SUBSTITUTION', 'default', pool), FixtureResolutionError);
});

function spkiBytes(r: Rsa3072KeyPairMaterial): Uint8Array {
  // Local mirror of the sanctioned derivation, used only to identify which
  // artifact a fixture carries.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return encodeSpkiRef({ role: 'public', n: big(r.n), e: big(r.e) });
}
import { encodeSpki as encodeSpkiRef } from '../../../../src/contract/rsa-ser.js';
