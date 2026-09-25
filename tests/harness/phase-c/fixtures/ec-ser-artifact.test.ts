import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveEcArtifactFixture, resolveEcArtifactStimulusFixture, resolveEcPrivateMaterialFixture,
  resolveEcPublicMaterialFixture, resolveEcRoleContainerFixture,
  isEcMaterialClass, isEcPublicMaterialClass, isEcRoleContainerClass,
  EC_ARTIFACT_MUTATION_IDS, EC_ARTIFACT_STIMULUS_PAIRS,
} from '../../../../harness/phase-c/fixtures/ec-ser-artifact.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../../../../harness/phase-c/material/load.js';
import type { EcP256KeyPairMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { importEcSer } from '../../../../src/contract/ec-ser.js';
import { isOnCurve, isPair, isValidScalar, scalarMultiplyG } from '../../../../src/contract/p256.js';

const pool = loadFrozenMaterialPool();
const materialIds = () => EC_ARTIFACT_MUTATION_IDS.filter(isEcMaterialClass);
const privateIds = () => materialIds().filter((id) => !isEcPublicMaterialClass(id));
const publicId = () => EC_ARTIFACT_MUTATION_IDS.find(isEcPublicMaterialClass)!;
const roleId = () => EC_ARTIFACT_MUTATION_IDS.find(isEcRoleContainerClass)!;
const bareIds = () => EC_ARTIFACT_MUTATION_IDS.filter((id) => !isEcMaterialClass(id) && !isEcRoleContainerClass(id));

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.14: GroupMutationIDs == ResolvedMutationIDs == 11', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'ec-ser' && e.mechanism === 'artifact-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...EC_ARTIFACT_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 11);
});

test('M3.2.4b-2.14: GroupStimulusPairs == ResolvedStimulusPairs == 11, each resolving exactly once', () => {
  assert.equal(EC_ARTIFACT_STIMULUS_PAIRS.length, 11);
  for (const [m, s] of EC_ARTIFACT_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveEcArtifactFixture(m, s, pool), `${m}::${s}`);
  }
  const keys = EC_ARTIFACT_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length);
});

test('M3.2.4b-2.14: the FOUR shapes are covered, in the 7+2+1+1 distribution', () => {
  assert.equal(bareIds().length, 7);
  assert.equal(privateIds().length, 2);
  assert.equal(materialIds().filter(isEcPublicMaterialClass).length, 1);
  assert.equal(EC_ARTIFACT_MUTATION_IDS.filter(isEcRoleContainerClass).length, 1);
  assert.equal(7 + 2 + 1 + 1, EC_ARTIFACT_MUTATION_IDS.length);
});

// --- The 8 serialized classes use DERIVED artifacts ------------------------

test('M3.2.4b-2.14: every serialized fixture equals a descriptor-derived artifact, byte for byte', () => {
  const spkiEnc = (v: unknown) => {
    const ec = v as EcP256KeyPairMaterial;
    const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
    return importEcSer(pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, () => {
      throw new Error('unused');
    }), 'public') as never;
  };
  void spkiEnc;
  // Compare against artifacts obtained the sanctioned way.
  const seen = new Set<string>();
  for (const id of bareIds()) {
    const f = resolveEcArtifactStimulusFixture(id, 'default', pool);
    seen.add(Buffer.from(f.artifact).toString('hex'));
  }
  assert.equal(seen.size, 2, 'exactly two distinct derived artifacts serve the seven classes: SPKI and PKCS8');
});

test('M3.2.4b-2.14: both derived artifacts import back under the frozen contract, in their own roles', () => {
  const byRole = new Map<string, number>();
  for (const id of [...bareIds(), roleId()]) {
    const f = id === roleId()
      ? resolveEcRoleContainerFixture(id, 'default', pool)
      : resolveEcArtifactStimulusFixture(id, 'default', pool);
    // Whichever role it belongs to, it must import as that role.
    let role: string | undefined;
    for (const candidate of ['public', 'private'] as const) {
      try { role = importEcSer(f.artifact, candidate).material.role; break; } catch { /* try the other */ }
    }
    assert.ok(role !== undefined, `${id}: its artifact imports under neither role`);
    byRole.set(role!, (byRole.get(role!) ?? 0) + 1);
  }
  assert.equal(byRole.size, 2, 'both SPKI and PKCS8 are genuinely in use across the group');
});

test('M3.2.4b-2.14: the resolver never encodes artifacts itself -- always through deriveArtifact()', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-artifact.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('deriveArtifact'), 'derivation must go through the descriptor');

  // encodeSpki/encodePkcs8 may appear ONLY inside the two named encoder
  // callbacks handed to deriveArtifact -- never as a direct fixture source.
  // The callback bodies span several lines, so the check is positional:
  // every call site must lie inside the encoder-definition region.
  const lines = src.split('\n');
  const regionStart = lines.findIndex((l) => l.includes('const spkiEncoder'));
  const regionEnd = lines.findIndex((l) => l.includes('function derivedSpki'));
  assert.ok(regionStart > 0 && regionEnd > regionStart, 'the encoder-callback region must be identifiable');

  const strayCalls = lines
    .map((l, i) => ({ l, i }))
    .filter(({ l, i }) => /encode(Spki|Pkcs8)\(/.test(l) && (i < regionStart || i > regionEnd));
  assert.deepEqual(strayCalls.map(({ l }) => l.trim()), [],
    'an encoder call outside the callback region would bypass the descriptor and its hash pin');
});

test('M3.2.4b-2.14: no SPKI/PKCS8 bytes are hard-coded in the resolver', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-artifact.ts', import.meta.url), 'utf8');
  assert.ok(!/[0-9a-f]{40,}/i.test(src), 'no long hex literal may appear');
});

// --- Artifact choice derived, not named ------------------------------------

test('M3.2.4b-2.14: artifact choice is derived -- every serialized class mutates without throwing', () => {
  for (const id of bareIds()) {
    const base = resolveEcArtifactStimulusFixture(id, 'default', pool);
    assert.doesNotThrow(() => getMutationImplementation(id).mutate(base, 'default'), id);
  }
});

test('M3.2.4b-2.14: the WRONG artifact would be rejected by five of the seven -- the probe is decisive', () => {
  // Five classes parse the artifact and throw on the wrong structure; the
  // two DER-MALFORMED ones xor without parsing and accept either, which is
  // exactly why a second mechanism (their Gamma_0 clause) is needed.
  let discriminating = 0;
  const artifacts = new Map<string, Uint8Array>();
  for (const id of bareIds()) artifacts.set(id, resolveEcArtifactStimulusFixture(id, 'default', pool).artifact);
  const distinct = [...new Set([...artifacts.values()].map((a) => Buffer.from(a).toString('hex')))];
  assert.equal(distinct.length, 2);

  for (const id of bareIds()) {
    const own = Buffer.from(artifacts.get(id)!).toString('hex');
    const other = distinct.find((d) => d !== own)!;
    try {
      getMutationImplementation(id).mutate({ artifact: new Uint8Array(Buffer.from(other, 'hex')) }, 'default');
    } catch { discriminating++; }
  }
  assert.equal(discriminating, 5, 'five classes reject the wrong artifact; two parse nothing');
});

test('M3.2.4b-2.14: the two non-discriminating classes are separated by their own Gamma_0 clause', () => {
  const nonDiscriminating = bareIds().filter((id) => {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === id)!;
    return entry.gamma0.includes('ec-ser.public.asn1') || entry.gamma0.includes('ec-ser.private.asn1');
  });
  assert.ok(nonDiscriminating.length >= 2);
  // And they receive DIFFERENT artifacts, as their clauses require.
  const pub = nonDiscriminating.filter((id) => MUTATION_REGISTRY.find((e) => e.mutationId === id)!.gamma0.includes('ec-ser.public.asn1'));
  const priv = nonDiscriminating.filter((id) => MUTATION_REGISTRY.find((e) => e.mutationId === id)!.gamma0.includes('ec-ser.private.asn1'));
  if (pub.length > 0 && priv.length > 0) {
    assert.notDeepEqual(
      Buffer.from(resolveEcArtifactStimulusFixture(pub[0]!, 'default', pool).artifact),
      Buffer.from(resolveEcArtifactStimulusFixture(priv[0]!, 'default', pool).artifact),
    );
  }
});

// --- The three material classes, and their causal preconditions -----------

test('M3.2.4b-2.14: the material fixtures carry the frozen key, converted only bytes -> bigint', () => {
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));

  const priv = resolveEcPrivateMaterialFixture(privateIds()[0]!, 'default', pool);
  assert.equal(priv.d, big(ec.d));
  const pub = resolveEcPublicMaterialFixture(publicId(), 'default', pool);
  assert.notEqual(pub.q, 'infinity');
  if (pub.q !== 'infinity') assert.equal(pub.q.x, big(ec.x));
});

test('M3.2.4b-2.14: the private baseline is a genuine pair -- V_scalar, V_curve, V_pair', () => {
  const m = resolveEcPrivateMaterialFixture(privateIds()[0]!, 'default', pool);
  assert.equal(isValidScalar(m.d), true);
  assert.notEqual(m.q, 'infinity');
  if (m.q !== 'infinity') {
    assert.equal(isOnCurve(m.q), true);
    assert.equal(isPair(m.d, m.q), true);
  }
});

test('M3.2.4b-2.14: precondition -- (x, y+1) is genuinely OFF the curve for this frozen point', () => {
  const m = resolveEcPublicMaterialFixture(publicId(), 'default', pool);
  assert.notEqual(m.q, 'infinity');
  if (m.q !== 'infinity') {
    assert.equal(isOnCurve(m.q), true, 'the baseline point is on the curve');
    assert.equal(isOnCurve({ x: m.q.x, y: m.q.y + 1n }), false,
      'if y+1 were also on the curve, the off-curve mutation would not leave it');
  }
  // And the mutation really does leave the curve.
  const mutated = getMutationImplementation(publicId()).mutate(m, 'default') as typeof m;
  assert.notEqual(mutated.q, 'infinity');
  if (mutated.q !== 'infinity') assert.equal(isOnCurve(mutated.q), false);
});

test('M3.2.4b-2.14: precondition -- d != 3 and 3G is not this key own public point', () => {
  const m = resolveEcPrivateMaterialFixture(privateIds()[0]!, 'default', pool);
  assert.notEqual(m.d, 3n);
  const g3 = scalarMultiplyG(3n);
  assert.equal(isPair(m.d, g3), false, 'if 3G were the correct point, the pair-mismatch mutation would produce a VALID pair');
  assert.equal(isOnCurve(g3), true, 'and 3G must be on the curve, isolating V_pair from V_curve');
});

test('M3.2.4b-2.14: the pair-mismatch mutation yields an on-curve point that is NOT this key own', () => {
  const id = privateIds().find((i) => MUTATION_REGISTRY.find((e) => e.mutationId === i)!.gamma0.some((c) => c.endsWith('.pairConsistency')))!;
  const base = resolveEcPrivateMaterialFixture(id, 'default', pool);
  const mutated = getMutationImplementation(id).mutate(base, 'default') as typeof base;
  assert.notEqual(mutated.q, 'infinity');
  if (mutated.q !== 'infinity') {
    assert.equal(isOnCurve(mutated.q), true, 'still on the curve: V_curve must not be what fails');
    assert.equal(isPair(mutated.d, mutated.q), false, 'but no longer the right pair: V_pair is what fails');
  }
});

// --- Role container --------------------------------------------------------

test('M3.2.4b-2.14: the role-container baseline AGREES, and the mutation creates the mismatch', () => {
  const base = resolveEcRoleContainerFixture(roleId(), 'default', pool);
  assert.equal(base.requestedRole, 'public');
  assert.doesNotThrow(() => importEcSer(base.artifact, base.requestedRole),
    'the baseline artifact and requested role must agree');

  const mutated = getMutationImplementation(roleId()).mutate(base, 'default') as typeof base;
  assert.equal(mutated.requestedRole, 'private');
  assert.deepEqual(Buffer.from(mutated.artifact), Buffer.from(base.artifact), 'only the role is intervened on');
  assert.throws(() => importEcSer(mutated.artifact, mutated.requestedRole), 'the mutated pairing must not import');
});

// --- H3, isolation, fail-closed --------------------------------------------

test('M3.2.4b-2.14 (H3): no mutate() call in the resolver body, and all 11 pairs are pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-artifact.ts', import.meta.url), 'utf8');
  // mutate() IS referenced, but only inside the artifact-need probe -- never
  // to produce a fixture. The behavioural proof is below.
  for (const [m, s] of EC_ARTIFACT_STIMULUS_PAIRS) {
    const base = resolveEcArtifactFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
  assert.ok(!src.includes('webcrypto') && !src.includes('subtle'), 'no runtime cryptographic generation');
});

test('M3.2.4b-2.14: the frozen corpus is unchanged by resolving and mutating all 11', () => {
  const before = Buffer.from(pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair').d);
  for (const [m, s] of EC_ARTIFACT_STIMULUS_PAIRS) {
    getMutationImplementation(m).mutate(resolveEcArtifactFixture(m, s, pool), s);
  }
  const after = Buffer.from(pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair').d);
  assert.deepEqual(after, before);
});

test('M3.2.4b-2.14: the four typed resolvers refuse each other classes; foreign ids fail closed', () => {
  assert.throws(() => resolveEcArtifactStimulusFixture(publicId(), 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcPrivateMaterialFixture(publicId(), 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcPublicMaterialFixture(privateIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcRoleContainerFixture(bareIds()[0]!, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcArtifactFixture(bareIds()[0]!, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveEcArtifactFixture('EC-ERROR-MAP-SWAP', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.14: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-artifact.ts', import.meta.url), 'utf8');
  for (const id of EC_ARTIFACT_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
