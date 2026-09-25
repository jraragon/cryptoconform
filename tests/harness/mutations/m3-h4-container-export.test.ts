import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../harness/phase-c/material/load.js';
import type { Rsa3072KeyPairMaterial } from '../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../harness/phase-c/mutation-index.js';
import { TOY_PUBLIC_MATERIAL } from '../../../harness/mutations/rsa-ser.js';
import type { RsaPublicMaterial } from '../../../src/contract/rsa-ser.js';
import { encodeSpki } from '../../../src/contract/rsa-ser.js';

const pool = loadFrozenMaterialPool();
const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
const CONTAINER_ID = 'RSA-SER-CONTAINER-EXPORT-DIVERGENCE';
const DER_ID = 'RSA-SER-DER-EXPORT-DIVERGENCE';

function frozenPublic(): RsaPublicMaterial {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  return { role: 'public', n: big(r.n), e: big(r.e) };
}
const mutateWith = (id: string, m: RsaPublicMaterial) =>
  getMutationImplementation(id).mutate(m, 'default') as RsaPublicMaterial;

// ---------------------------------------------------------------------
// M3-H4 -- a SECOND kind of inherited TOY specialization, distinct from
// M3-H3's. Found while implementing the RSA artifact resolvers, before the
// binding was closed.
//
//     M3-H3   a TOY constant accidentally REPLACES experimental material
//     M3-H4   a TOY-oriented FORMULA degenerates to a no-op
//
// `e: 65537n % material.n` diverged correctly on the toy key
// (65537 mod 3233 = 877 != 17) but on any real modulus reduces to 65537 --
// exactly the frozen key's own exponent -- so mutate(F_0) = F_0 and the
// intervention vanished.
// ---------------------------------------------------------------------

test('M3-H4: the defect is real -- the historic formula degenerates on a 3072-bit modulus', () => {
  const F0 = frozenPublic();
  assert.equal(65537n % F0.n, 65537n, 'the modulus exceeds 65537, so the reduction is the identity');
  assert.equal(F0.e, 65537n, 'and the frozen key own exponent IS 65537 -- hence the no-op');
});

test('M3-H4: on the real key the mutation now genuinely diverges', () => {
  const F0 = frozenPublic();
  const F1 = mutateWith(CONTAINER_ID, F0);
  assert.notEqual(F1.e, F0.e);
  assert.equal(F1.e, 7n, 'the deterministic fallback');
});

test('M3-H4: the historic TOY behaviour is preserved exactly -- 877, as before', () => {
  const toy: RsaPublicMaterial = { role: 'public', n: TOY_PUBLIC_MATERIAL.n, e: TOY_PUBLIC_MATERIAL.e };
  const out = mutateWith(CONTAINER_ID, toy);
  assert.equal(65537n % toy.n, 877n);
  assert.equal(out.e, 877n, 'the first branch still applies where it worked');
  assert.notEqual(out.e, toy.e);
});

test('M3-H4: only e changes -- n is untouched', () => {
  const F0 = frozenPublic();
  const F1 = mutateWith(CONTAINER_ID, F0);
  assert.equal(F1.n, F0.n);
  assert.equal(F1.role, F0.role);
});

test('M3-H4: the post-condition e\' != e holds for every key tried, including adversarial ones', () => {
  const cases: RsaPublicMaterial[] = [
    frozenPublic(),
    { role: 'public', n: TOY_PUBLIC_MATERIAL.n, e: TOY_PUBLIC_MATERIAL.e },
    // A key whose exponent IS the historic result, forcing the fallback.
    { role: 'public', n: 3233n, e: 877n },
    // A key whose exponent is the fallback, forcing the historic branch.
    { role: 'public', n: 3233n, e: 7n },
  ];
  for (const m of cases) {
    const out = mutateWith(CONTAINER_ID, m);
    assert.notEqual(out.e, m.e, `no-op for n=${m.n}, e=${m.e}`);
  }
});

test('M3-H4: a key for which NO divergent exponent is available raises rather than silently no-op', () => {
  // n small enough that 65537 mod n === 7 === e leaves both branches equal.
  const n = 65530n; // 65537 mod 65530 = 7
  assert.equal(65537n % n, 7n);
  const degenerate: RsaPublicMaterial = { role: 'public', n, e: 7n };
  assert.throws(() => mutateWith(CONTAINER_ID, degenerate), /would be a no-op/);
});

test('M3-H4: the mutated material is still consumable by the frozen M1 encoder', () => {
  const F1 = mutateWith(CONTAINER_ID, frozenPublic());
  assert.doesNotThrow(() => encodeSpki(F1));
});

// ---------------------------------------------------------------------
// Finding B -- RSA-SER-DER-EXPORT-DIVERGENCE, inspected and NOT changed.
//
// Its small modulus is a CONSTRUCTED DER boundary case, not a TOY residue.
// Gamma_0 here is der-syntax, and 0xFF01's leading significant octet has
// MSB = 1: DER encodes INTEGER as two's-complement signed, so a positive
// value with a high leading bit needs a protective zero octet. Pinning that
// encoding fixes the intent by evidence rather than by comment.
// ---------------------------------------------------------------------

test('finding B: the DER export probe is intentional -- it forces the 00 FF 01 INTEGER content', () => {
  const F0 = frozenPublic();
  const F1 = mutateWith(DER_ID, F0);
  assert.equal(F1.n, 0xff01n, 'the constructed probe value');
  assert.equal(F1.e, F0.e, 'only n is intervened on');

  // Its top significant byte has MSB set, which is what makes the padding
  // path mandatory.
  const magnitude = Buffer.from(F1.n.toString(16).padStart(4, '0'), 'hex');
  assert.equal(magnitude[0]! & 0x80, 0x80, 'leading octet must have MSB = 1');

  // And the frozen encoder really does emit the protective zero: the SPKI
  // must contain the 00 FF 01 sequence.
  const der = Buffer.from(encodeSpki(F1)).toString('hex');
  assert.ok(der.includes('00ff01'), `expected 00 FF 01 in the encoding; got ${der}`);
});

test('finding B: its Gamma_0 is der-syntax, not material divergence -- the reason it is NOT a defect', async () => {
  const { MUTATION_REGISTRY } = await import('../../../harness/registry/mutations.js');
  const der = MUTATION_REGISTRY.find((e) => e.mutationId === DER_ID)!;
  const container = MUTATION_REGISTRY.find((e) => e.mutationId === CONTAINER_ID)!;
  assert.deepEqual(der.gamma0, ['der-syntax'], 'a syntactic intervention: a small probe value is the point');
  assert.deepEqual(container.gamma0, ['container'], 'not a syntactic probe, so a no-op there is a genuine defect');
});

test('finding B: it is NOT a no-op -- the distinction from H4 rests on behaviour, not on size', () => {
  const F0 = frozenPublic();
  const F1 = mutateWith(DER_ID, F0);
  assert.notEqual(F1.n, F0.n, 'small does not mean absent');
});
