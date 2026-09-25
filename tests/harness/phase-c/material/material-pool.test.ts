import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateMaterial, MaterialSchemaViolationError,
  type EcP256KeyPairMaterial, type Rsa3072KeyPairMaterial, type AesBaseMaterial,
  type FrozenMaterialRecord, type DerivedArtifactDescriptor,
} from '../../../../harness/phase-c/material/schema.js';
import {
  computeMaterialIdentity, verifyMaterialRecord, MaterialIdentityViolationError, sha256Hex,
} from '../../../../harness/phase-c/material/canonical-identity.js';
import { FrozenMaterialPool, MaterialPoolError } from '../../../../harness/phase-c/material/pool.js';
import { canonicalEncode } from '../../../../harness/canonical/canonical-encode.js';

// ---------------------------------------------------------------------
// Fixtures for these tests only. Deliberately structurally valid but
// cryptographically meaningless: M3.2.4a-5 delivers the pool MACHINERY;
// the real frozen bytes are generated once in a later step. Using
// placeholder bytes here keeps the machinery's own tests independent of
// the material generation that will consume it.
// ---------------------------------------------------------------------

function ecMaterial(): EcP256KeyPairMaterial {
  return { curve: 'P-256', x: new Uint8Array(32).fill(1), y: new Uint8Array(32).fill(2), d: new Uint8Array(32).fill(3) };
}
function rsaMaterial(): Rsa3072KeyPairMaterial {
  return {
    modulusBits: 3072,
    n: new Uint8Array(384).fill(0xaa), e: new Uint8Array([0x01, 0x00, 0x01]),
    d: new Uint8Array(384).fill(0xbb),
    p: new Uint8Array(192).fill(0xcc), q: new Uint8Array(192).fill(0xdd),
    dp: new Uint8Array(192).fill(0xee), dq: new Uint8Array(192).fill(0x11), qi: new Uint8Array(192).fill(0x22),
  };
}
function aesMaterial(): AesBaseMaterial {
  return { key: new Uint8Array(32).fill(7), iv: new Uint8Array(12).fill(8), plaintext: new Uint8Array([1, 2, 3, 4]) };
}

function record(materialId: string, materialType: FrozenMaterialRecord['materialType'], value: Parameters<typeof computeMaterialIdentity>[1]): FrozenMaterialRecord {
  const { canonicalEncoding, sha256 } = computeMaterialIdentity(materialType, value);
  return {
    materialId, materialType, schemaVersion: '1.0', value,
    canonicalEncoding, sha256,
    provenance: { origin: 'generated-during-m3', generator: 'test-fixture' },
  };
}

// --- 1. Schema -------------------------------------------------------------

test('schema: a well-formed P-256 material validates', () => {
  assert.doesNotThrow(() => validateMaterial('ec-p256-keypair', ecMaterial()));
});

test('schema: FieldNormalization enforces exact P-256 widths -- a 31-byte scalar is refused (the H4 class of defect, prevented structurally)', () => {
  const short = { ...ecMaterial(), d: new Uint8Array(31).fill(3) };
  assert.throws(() => validateMaterial('ec-p256-keypair', short), MaterialSchemaViolationError);
});

test('schema: bigint is refused outright -- frozen material stores normalized bytes only', () => {
  const withBigint = { curve: 'P-256', x: 1n, y: new Uint8Array(32), d: new Uint8Array(32) } as unknown as EcP256KeyPairMaterial;
  assert.throws(() => validateMaterial('ec-p256-keypair', withBigint), MaterialSchemaViolationError);
});

test('schema: RSA-3072 component widths are enforced, and e must be odd', () => {
  assert.doesNotThrow(() => validateMaterial('rsa-3072-keypair', rsaMaterial()));
  assert.throws(() => validateMaterial('rsa-3072-keypair', { ...rsaMaterial(), n: new Uint8Array(383) }), MaterialSchemaViolationError);
  assert.throws(() => validateMaterial('rsa-3072-keypair', { ...rsaMaterial(), p: new Uint8Array(191) }), MaterialSchemaViolationError);
  assert.throws(() => validateMaterial('rsa-3072-keypair', { ...rsaMaterial(), e: new Uint8Array([0x02]) }), MaterialSchemaViolationError);
});

test('schema: AES material enforces AES-256 key and 96-bit GCM IV, the frozen portable profile', () => {
  assert.doesNotThrow(() => validateMaterial('aes-base-material', aesMaterial()));
  assert.throws(() => validateMaterial('aes-base-material', { ...aesMaterial(), key: new Uint8Array(16) }), MaterialSchemaViolationError);
  assert.throws(() => validateMaterial('aes-base-material', { ...aesMaterial(), iv: new Uint8Array(16) }), MaterialSchemaViolationError);
});

// --- 2. Canonical hash -----------------------------------------------------

test('canonical identity: H = SHA256(canonicalEncode(value)), reproducible and derived, never asserted', () => {
  const value = ecMaterial();
  const { canonicalEncoding, sha256 } = computeMaterialIdentity('ec-p256-keypair', value);
  assert.equal(canonicalEncoding, canonicalEncode(value));
  assert.equal(sha256, sha256Hex(canonicalEncode(value)));
  // Deterministic across invocations.
  assert.equal(computeMaterialIdentity('ec-p256-keypair', value).sha256, sha256);
});

test('canonical identity: distinct materials never share a hash', () => {
  const a = computeMaterialIdentity('ec-p256-keypair', ecMaterial()).sha256;
  const b = computeMaterialIdentity('ec-p256-keypair', { ...ecMaterial(), d: new Uint8Array(32).fill(4) }).sha256;
  assert.notEqual(a, b);
});

test('canonical identity: hashing an invalid value is impossible -- validation runs first', () => {
  const bad = { ...ecMaterial(), x: new Uint8Array(31) };
  assert.throws(() => computeMaterialIdentity('ec-p256-keypair', bad), MaterialSchemaViolationError);
});

// --- 3. Corruption detection ----------------------------------------------

test('corruption: a tampered value is detected -- the stored hash is recomputed, never trusted', () => {
  const good = record('ec-1', 'ec-p256-keypair', ecMaterial());
  const tampered: FrozenMaterialRecord = { ...good, value: { ...ecMaterial(), d: new Uint8Array(32).fill(9) } };
  assert.throws(() => verifyMaterialRecord(tampered), MaterialIdentityViolationError);
});

test('corruption: a tampered sha256 field is detected', () => {
  const good = record('ec-2', 'ec-p256-keypair', ecMaterial());
  const tampered: FrozenMaterialRecord = { ...good, sha256: 'f'.repeat(64) };
  assert.throws(() => verifyMaterialRecord(tampered), MaterialIdentityViolationError);
});

test('corruption: a tampered canonicalEncoding field is detected', () => {
  const good = record('ec-3', 'ec-p256-keypair', ecMaterial());
  const tampered: FrozenMaterialRecord = { ...good, canonicalEncoding: good.canonicalEncoding + 'x' };
  assert.throws(() => verifyMaterialRecord(tampered), MaterialIdentityViolationError);
});

test('corruption: an unrecognised schemaVersion is refused', () => {
  const good = record('ec-4', 'ec-p256-keypair', ecMaterial());
  const wrong = { ...good, schemaVersion: '2.0' } as unknown as FrozenMaterialRecord;
  assert.throws(() => verifyMaterialRecord(wrong), MaterialIdentityViolationError);
});

test('corruption: the pool verifies every record at construction, fail-closed', () => {
  const good = record('ec-5', 'ec-p256-keypair', ecMaterial());
  const tampered: FrozenMaterialRecord = { ...good, sha256: '0'.repeat(64) };
  assert.throws(() => new FrozenMaterialPool([tampered]), MaterialIdentityViolationError);
});

// --- 4. Duplicate materialId ----------------------------------------------

test('pool: a duplicate materialId is refused (I_pool1)', () => {
  const a = record('dup', 'ec-p256-keypair', ecMaterial());
  const b = record('dup', 'rsa-3072-keypair', rsaMaterial());
  assert.throws(() => new FrozenMaterialPool([a, b]), MaterialPoolError);
});

// --- 5. Derived dependency -------------------------------------------------

test('pool: a derived artifact referencing an absent source material is refused -- no orphan derivations', () => {
  const ec = record('ec-src', 'ec-p256-keypair', ecMaterial());
  const orphan: DerivedArtifactDescriptor = {
    artifactId: 'spki-1', sourceMaterialId: 'does-not-exist', derivation: 'encode-spki', expectedSha256: '0'.repeat(64),
  };
  assert.throws(() => new FrozenMaterialPool([ec], [orphan]), MaterialPoolError);
});

test('pool: a derived artifact is regenerated by a frozen encoder and checked against its pinned hash', () => {
  const ec = record('ec-src2', 'ec-p256-keypair', ecMaterial());
  const encoder = (v: unknown) => (v as EcP256KeyPairMaterial).x; // stand-in for a frozen pure encoder
  const expected = sha256Hex(canonicalEncode(encoder(ecMaterial())));
  const descriptor: DerivedArtifactDescriptor = {
    artifactId: 'spki-2', sourceMaterialId: 'ec-src2', derivation: 'encode-spki', expectedSha256: expected,
  };
  const pool = new FrozenMaterialPool([ec], [descriptor]);
  assert.deepEqual(pool.deriveArtifact('spki-2', encoder as never), ecMaterial().x);
});

test('pool: a derived artifact whose encoder output no longer matches the pinned hash is refused -- a freeze violation, never silently accepted', () => {
  const ec = record('ec-src3', 'ec-p256-keypair', ecMaterial());
  const descriptor: DerivedArtifactDescriptor = {
    artifactId: 'spki-3', sourceMaterialId: 'ec-src3', derivation: 'encode-spki', expectedSha256: 'a'.repeat(64),
  };
  const pool = new FrozenMaterialPool([ec], [descriptor]);
  const driftedEncoder = (v: unknown) => (v as EcP256KeyPairMaterial).y; // encoder changed
  assert.throws(() => pool.deriveArtifact('spki-3', driftedEncoder as never), MaterialPoolError);
});

test('pool: an artifact record naming a sourceMaterialId not in the pool is refused', () => {
  const artifact = record('gcm-1', 'gcm-valid-artifact', {
    ciphertext: new Uint8Array([1, 2, 3]), sourceMaterialId: 'missing-aes',
  });
  assert.throws(() => new FrozenMaterialPool([artifact]), MaterialPoolError);
});

// --- 6. No runtime generation ---------------------------------------------

test('pool: requesting material that was never frozen fails closed (I_pool3) -- there is no generation path', () => {
  const pool = new FrozenMaterialPool([record('ec-only', 'ec-p256-keypair', ecMaterial())]);
  assert.throws(() => pool.get('rsa-never-frozen'), MaterialPoolError);
});

test('pool: the module exposes no generation entry point at all -- I_pool3 is structural, not advisory', async () => {
  const mod = await import('../../../../harness/phase-c/material/pool.js');
  const exported = Object.keys(mod);
  for (const name of exported) {
    assert.ok(!/generate|create[A-Z]|mint|makeKey/i.test(name), `pool exports '${name}', which looks like a generation entry point`);
  }
});

test('pool: requesting a material under the wrong type is refused', () => {
  const pool = new FrozenMaterialPool([record('ec-typed', 'ec-p256-keypair', ecMaterial())]);
  assert.throws(() => pool.valueOf('ec-typed', 'rsa-3072-keypair'), MaterialPoolError);
});

test('pool: a valid multi-material pool loads, and identities are stable and complete', () => {
  const aes = record('aes-1', 'aes-base-material', aesMaterial());
  const artifact = record('gcm-2', 'gcm-valid-artifact', { ciphertext: new Uint8Array([9, 9]), sourceMaterialId: 'aes-1' });
  const pool = new FrozenMaterialPool([aes, artifact, record('rsa-1', 'rsa-3072-keypair', rsaMaterial())]);
  assert.deepEqual(pool.materialIds(), ['aes-1', 'gcm-2', 'rsa-1']);
  assert.equal(pool.identities().length, 3);
  assert.equal(pool.identities().every((i) => i.sha256.length === 64), true);
});
