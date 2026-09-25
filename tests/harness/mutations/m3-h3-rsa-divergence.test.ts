import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../harness/phase-c/material/load.js';
import type { Rsa3072KeyPairMaterial } from '../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../harness/phase-c/mutation-index.js';
import { TOY_PRIVATE_MATERIAL } from '../../../harness/mutations/rsa-ser.js';
import type { RsaPrivateMaterial } from '../../../src/contract/rsa-ser.js';

const pool = loadFrozenMaterialPool();
const DIVERGENCE_ID = 'RSA-SER-PRIVATE-MATERIAL-DIVERGENCE';

function gcd(a: bigint, b: bigint): bigint { return b === 0n ? a : gcd(b, a % b); }
function lambdaOf(p: bigint, q: bigint): bigint { return ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n); }

function frozenPrivate(): RsaPrivateMaterial {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
  return {
    role: 'private', n: big(r.n), e: big(r.e), d: big(r.d),
    p: big(r.p), q: big(r.q), dP: big(r.dp), dQ: big(r.dq), qInv: big(r.qi),
  };
}
const diverge = (m: RsaPrivateMaterial) =>
  getMutationImplementation(DIVERGENCE_ID).mutate(m, 'default') as RsaPrivateMaterial;

// ---------------------------------------------------------------------
// M3-H3 -- inherited defect from M2, discovered during M3.2.4b-2.15's own
// exhaustive inspection and remediated prospectively.
//
// RSA-SER-PRIVATE-MATERIAL-DIVERGENCE IGNORED its argument and returned
// TOY_PRIVATE_MATERIAL with recomputed exponents. Self-consistent while its
// only caller was a unit test on the toy key, but it silently voids the
// class's meaning under Phase C: fed the real 3072-bit frozen key it
// returned a 12-bit one, so the observed "divergence" would have been
// 3072-vs-12 bits -- a different universe rather than divergent material
// for the same key.
//
// The scientific intent is unchanged; only the implementation now derives
// from its input. M2's frozen artifacts are untouched, exactly as with
// M3-H1a/M3-H1b.
// ---------------------------------------------------------------------

test('M3-H3: the mutation DEPENDS on its argument -- different inputs give different outputs', () => {
  const real = frozenPrivate();
  const fromReal = diverge(real);
  const fromToy = diverge(TOY_PRIVATE_MATERIAL);
  assert.notEqual(fromReal.n, fromToy.n, 'a hard-coded constant would make these identical');
  assert.notEqual(fromReal.d, fromToy.d);
});

test('M3-H3: fed the real frozen key, the result is NOT the toy material', () => {
  const out = diverge(frozenPrivate());
  assert.notEqual(out.n, TOY_PRIVATE_MATERIAL.n);
  assert.equal(out.n.toString(2).length, 3072, 'the modulus stays 3072 bits, not 12');
});

test('M3-H3: the modulus and primes are PRESERVED -- same key, divergent material', () => {
  const F0 = frozenPrivate();
  const F1 = diverge(F0);
  assert.equal(F1.n, F0.n);
  assert.equal(F1.p, F0.p);
  assert.equal(F1.q, F0.q);
  assert.equal(F1.qInv, F0.qInv, 'qInv depends only on p and q, which are unchanged');
});

test('M3-H3: the public exponent genuinely diverges', () => {
  const F0 = frozenPrivate();
  const F1 = diverge(F0);
  assert.equal(F1.e, 7n);
  assert.notEqual(F1.e, F0.e, `the frozen key uses e=${F0.e}`);
});

test('M3-H3: the result is a mathematically VALID RSA private key', () => {
  const F0 = frozenPrivate();
  const F1 = diverge(F0);
  const lambda = lambdaOf(F1.p, F1.q);

  assert.equal(F1.p * F1.q, F1.n, 'n = pq');
  assert.equal((F1.e * F1.d) % lambda, 1n, 'ed = 1 mod lambda(n)');
  assert.equal(F1.dP, F1.d % (F1.p - 1n), 'dP = d mod (p-1)');
  assert.equal(F1.dQ, F1.d % (F1.q - 1n), 'dQ = d mod (q-1)');
  assert.equal((F1.qInv * F1.q) % F1.p, 1n, 'qInv*q = 1 mod p');
});

test('M3-H3: F_1 != F_0 -- the mutation genuinely changes the material', () => {
  const F0 = frozenPrivate();
  const F1 = diverge(F0);
  const s = (m: RsaPrivateMaterial) => JSON.stringify(m, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  assert.notEqual(s(F1), s(F0));
  // Specifically, exactly the four declared intervention targets changed.
  assert.deepEqual(
    (['e', 'd', 'dP', 'dQ'] as const).filter((k) => F1[k] !== F0[k]),
    ['e', 'd', 'dP', 'dQ'],
  );
  assert.deepEqual(
    (['n', 'p', 'q', 'qInv'] as const).filter((k) => F1[k] !== F0[k]),
    [], 'nothing outside the declared targets may change',
  );
});

test('M3-H3: it still works on the toy key -- the M2 unit-test domain is not broken', () => {
  const out = diverge(TOY_PRIVATE_MATERIAL);
  const lambda = lambdaOf(out.p, out.q);
  assert.equal(out.e, 7n);
  assert.equal((out.e * out.d) % lambda, 1n);
  // The original hard-coded values were d=223, dP=43, dQ=15 for the toy key;
  // deriving them must reproduce exactly those, so the correction preserves
  // the original behaviour on the domain where it was correct.
  assert.equal(out.d, 223n);
  assert.equal(out.dP, 43n);
  assert.equal(out.dQ, 15n);
});

test("M3-H3: a key for which e'=7 is invalid raises, rather than yielding a broken tuple", () => {
  // p=7, q=11 -> lambda = lcm(6,10) = 30, and gcd(7,30) = 1... so pick a key
  // where gcd(7, lambda) != 1: p=29, q=43 -> lambda = lcm(28,42) = 84,
  // gcd(7,84) = 7.
  const bad: RsaPrivateMaterial = {
    role: 'private', n: 29n * 43n, e: 5n, d: 1n, p: 29n, q: 43n, dP: 1n, dQ: 1n, qInv: 1n,
  };
  assert.equal(gcd(7n, lambdaOf(bad.p, bad.q)), 7n, 'the fixture must genuinely violate the condition');
  assert.throws(() => diverge(bad), /gcd\(7, lambda\(n\)\) != 1/);
});

test('M3-H3: no cryptographic generation -- pure modular arithmetic over frozen values', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/mutations/rsa-ser.ts', import.meta.url), 'utf8');
  for (const forbidden of ['webcrypto', 'subtle', 'generateKey', 'randomBytes']) {
    assert.ok(!src.includes(forbidden), `found '${forbidden}'`);
  }
});

test('M3-H3: the sibling PUBLIC-MATERIAL-DIVERGENCE was NOT changed functionally', () => {
  // It already used its argument; only its toy-specific comment was
  // misleading. Confirm it still derives from its input.
  const F0 = frozenPrivate();
  const pub = { role: 'public' as const, n: F0.n, e: F0.e };
  const out = getMutationImplementation('RSA-SER-PUBLIC-MATERIAL-DIVERGENCE').mutate(pub, 'default') as typeof pub;
  assert.equal(out.n, F0.n, 'the modulus comes from the input, not a constant');
  assert.equal(out.e, 7n);
  assert.equal(gcd(7n, lambdaOf(F0.p, F0.q)), 1n, "e'=7 is valid for the frozen key");
});
