import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveEcSerAdapterFixture, resolveEcNativeExportFixture, resolveEcSerErrorMappingFixture,
  isEcSerErrorMappingClass, EC_SER_ADAPTER_MUTATION_IDS, EC_SER_ADAPTER_STIMULUS_PAIRS,
  EC_SER_BASELINE_ADAPTER_RECONSTRUCTS_PUBKEY, EC_SER_BASELINE_DECLARED_ERROR_CLASS,
  EC_SER_BASELINE_TRIGGERING_CONDITION,
} from '../../../../harness/phase-c/fixtures/ec-ser-adapter.js';
import { resolveRsaSerAdapterFixture } from '../../../../harness/phase-c/fixtures/rsa-ser-adapter.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { EcP256KeyPairMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { isValidScalar, isOnCurve, isPair } from '../../../../src/contract/p256.js';

const pool = loadFrozenMaterialPool();
const errorId = () => EC_SER_ADAPTER_MUTATION_IDS.find(isEcSerErrorMappingClass)!;
const exportId = () => EC_SER_ADAPTER_MUTATION_IDS.find((id) => !isEcSerErrorMappingClass(id))!;

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.12: 2 classes, 2 pairs, TWO shapes', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'ec-ser' && e.mechanism === 'adapter-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...EC_SER_ADAPTER_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 2);
  assert.equal(EC_SER_ADAPTER_STIMULUS_PAIRS.length, 2);
  for (const [m, s] of EC_SER_ADAPTER_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveEcSerAdapterFixture(m, s, pool), `${m}::${s}`);
  }
  assert.equal(EC_SER_ADAPTER_MUTATION_IDS.filter(isEcSerErrorMappingClass).length, 1);
});

// --- Finding 1: first adapter fixture reaching material DIRECTLY ----------

test('M3.2.4b-2.12: the export-leak fixture carries REAL frozen key material -- H1 applies in full, not vacuously', () => {
  const f = resolveEcNativeExportFixture(exportId(), 'default', pool);
  const frozen = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const toBig = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));

  assert.equal(f.material.role, 'private');
  assert.equal(f.material.d, toBig(frozen.d), 'the scalar is the frozen one, not a fresh value');
  // AffinePoint admits 'infinity', which has no coordinates -- narrow rather
  // than assume, since a frozen point at infinity would be a real defect.
  assert.notEqual(f.material.q, 'infinity', 'the frozen public point must not be the point at infinity');
  if (f.material.q !== 'infinity') {
    assert.equal(f.material.q.x, toBig(frozen.x));
    assert.equal(f.material.q.y, toBig(frozen.y));
  }
});

test('M3.2.4b-2.12: the carried material genuinely satisfies V_scalar, V_curve and V_pair', () => {
  const f = resolveEcNativeExportFixture(exportId(), 'default', pool);
  assert.equal(isValidScalar(f.material.d), true);
  assert.equal(isOnCurve(f.material.q), true);
  assert.equal(isPair(f.material.d, f.material.q), true,
    'the whole point of this class is the (d,Q) relationship; a violating fixture would void it');
});

test('M3.2.4b-2.12: the bytes -> bigint conversion happens at the boundary, and only in that direction', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-adapter.ts', import.meta.url), 'utf8');
  // The pool stores fixed-width bytes; the M1 contract type uses bigint.
  // bytes -> bigint is total and lossless. The reverse (bigint -> bytes) is
  // the direction that reintroduces width ambiguity -- H4's own defect --
  // and must not appear here.
  assert.ok(!src.includes('toString(16)'), 'no bigint -> hex conversion may appear in this resolver');
  assert.ok(!src.includes('padStart'), 'no width padding may appear -- that belongs to the material schema');
});

// --- Finding 2: the error-mapping shape, fifth operation -------------------

test('M3.2.4b-2.12: the error-mapping shape recurs for a FIFTH operation, and needs no material', () => {
  const ecSer = resolveEcSerErrorMappingFixture(errorId(), 'default', pool);
  const rsaSer = resolveRsaSerAdapterFixture('RSA-SER-ERROR-MISCLASSIFICATION', 'default', pool);
  assert.deepEqual(Object.keys(ecSer).sort(), Object.keys(rsaSer).sort());
  assert.deepEqual(Object.keys(ecSer).sort(), ['declaredErrorClass', 'triggeringCondition']);
  // Same shape, different content -- the two serialization operations do not
  // share a fixture merely because they share a mechanism.
  assert.notDeepEqual(ecSer, rsaSer);
});

test('M3.2.4b-2.12: the baseline follows EC-ser own validation stage order', () => {
  const f = resolveEcSerErrorMappingFixture(errorId(), 'default', pool);
  assert.equal(f.declaredErrorClass, EC_SER_BASELINE_DECLARED_ERROR_CLASS);
  assert.equal(f.declaredErrorClass, 'invalid_key', 'V_pair failure raises invalid_key');
  assert.equal(f.triggeringCondition, EC_SER_BASELINE_TRIGGERING_CONDITION);
});

test('M3.2.4b-2.12: the mutation claims off-curve for a point that demonstrably PASSED V_curve', () => {
  const base = resolveEcSerErrorMappingFixture(errorId(), 'default', pool);
  const mutated = getMutationImplementation(errorId()).mutate(base, 'default') as typeof base;
  assert.equal(base.declaredErrorClass, 'invalid_key');
  assert.equal(mutated.declaredErrorClass, 'invalid_membership');
  assert.equal(mutated.triggeringCondition, base.triggeringCondition, 'only the declared class is intervened on');
});

test('M3.2.4b-2.12: both toggled classes are genuinely raised by the frozen contract, at their own stages', async () => {
  const { readFileSync } = await import('node:fs');
  const contract = readFileSync(new URL('../../../../src/contract/ec-ser.ts', import.meta.url), 'utf8');
  assert.ok(contract.includes('ec-ser.curveMembership'), 'V_curve stage exists');
  assert.ok(contract.includes("'invalid_membership'"));
  assert.ok(contract.includes('ec-ser.pairConsistency'), 'V_pair stage exists');
  assert.ok(contract.includes("'invalid_key'"));
  // V_pair is reached only after V_curve passes, which is what makes the
  // mutated claim contradictory rather than merely wrong.
  assert.ok(contract.indexOf('ec-ser.curveMembership') < contract.lastIndexOf('ec-ser.pairConsistency'));
});

// --- Baselines are the correct starting values -----------------------------

test('M3.2.4b-2.12: the export baseline declares NO reconstruction, and the mutation enables it', () => {
  const base = resolveEcNativeExportFixture(exportId(), 'default', pool);
  assert.equal(base.adapterReconstructsPubkey, EC_SER_BASELINE_ADAPTER_RECONSTRUCTS_PUBKEY);
  assert.equal(base.adapterReconstructsPubkey, false, 'a correct adapter uses the point it was given');

  const mutated = getMutationImplementation(exportId()).mutate(base, 'default') as typeof base;
  assert.equal(mutated.adapterReconstructsPubkey, true);
  assert.deepEqual(mutated.material, base.material, 'the material is not a direct intervention target');
});

// --- H3, isolation, fail-closed --------------------------------------------

test('M3.2.4b-2.12 (H3): no mutate() call, and both pairs are genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-adapter.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of EC_SER_ADAPTER_STIMULUS_PAIRS) {
    const base = resolveEcSerAdapterFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

test('M3.2.4b-2.12: the frozen corpus is unaffected by resolving or mutating', () => {
  const before = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const beforeD = Buffer.from(before.d);
  const base = resolveEcNativeExportFixture(exportId(), 'default', pool);
  getMutationImplementation(exportId()).mutate(base, 'default');
  const after = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  assert.deepEqual(Buffer.from(after.d), beforeD);
});

test('M3.2.4b-2.12: the two typed resolvers refuse each other classes; foreign ids fail closed', () => {
  assert.throws(() => resolveEcSerErrorMappingFixture(exportId(), 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcNativeExportFixture(errorId(), 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcSerAdapterFixture(errorId(), 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveEcSerAdapterFixture('RSA-SER-ERROR-MISCLASSIFICATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveEcSerAdapterFixture('EC-CAPABILITY-MANIFEST-MISMATCH', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.12: shape selection is derived from Gamma_0, cross-checked against the registry', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/ec-ser-adapter.ts', import.meta.url), 'utf8');
  for (const id of EC_SER_ADAPTER_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === id)!;
    assert.equal(isEcSerErrorMappingClass(id), entry.gamma0.some((c) => c.endsWith('.error')));
  }
});
