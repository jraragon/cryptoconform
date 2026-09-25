import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  loadFrozenMaterialPool, loadDerivedArtifactDescriptors,
  PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS,
} from '../../../../harness/phase-c/material/load.js';
import { MaterialPoolError } from '../../../../harness/phase-c/material/pool.js';
import type { Rsa3072KeyPairMaterial, MaterialValue } from '../../../../harness/phase-c/material/schema.js';
import type { RsaPublicMaterial, RsaPrivateMaterial } from '../../../../src/contract/rsa-ser.js';
import { encodeSpki, encodePrivateKeyInfo, importRsaSer } from '../../../../src/contract/rsa-ser.js';

const pool = loadFrozenMaterialPool();
const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));

function toPublic(v: MaterialValue): RsaPublicMaterial {
  const r = v as Rsa3072KeyPairMaterial;
  return { role: 'public', n: big(r.n), e: big(r.e) };
}
function toPrivate(v: MaterialValue): RsaPrivateMaterial {
  const r = v as Rsa3072KeyPairMaterial;
  return {
    role: 'private', n: big(r.n), e: big(r.e), d: big(r.d),
    p: big(r.p), q: big(r.q), dP: big(r.dp), dQ: big(r.dq), qInv: big(r.qi),
  };
}
const spkiEncoder = (v: MaterialValue) => encodeSpki(toPublic(v));
const pkiEncoder = (v: MaterialValue) => encodePrivateKeyInfo(toPrivate(v));

// ---------------------------------------------------------------------
// M3.2.4b-2.15-D -- RSA derived-artifact qualification.
//
// Scope is deliberately availability + identity + qualification. Which class
// consumes which artifact is a binding decision, verified in -R.
// ---------------------------------------------------------------------

test('M3.2.4b-2.15-D: the corpus now carries FOUR descriptors -- two EC, two RSA', () => {
  const descriptors = loadDerivedArtifactDescriptors();
  assert.equal(descriptors.length, 4);
  assert.deepEqual(
    descriptors.map((d) => d.artifactId).sort(),
    [...Object.values(PHASE_C_DERIVED_ARTIFACT_IDS)].sort(),
  );
});

test('M3.2.4b-2.15-D: both RSA descriptors derive from the frozen RSA-3072 material', () => {
  const rsa = loadDerivedArtifactDescriptors().filter(
    (d) => d.artifactId === PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki
      || d.artifactId === PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo,
  );
  assert.equal(rsa.length, 2);
  for (const d of rsa) {
    assert.equal(d.sourceMaterialId, PHASE_C_MATERIAL_IDS.rsa);
    assert.equal(d.expectedSha256.length, 64);
  }
});

test('M3.2.4b-2.15-D: the derivation names the REAL M1 encoder, not an approximate label', () => {
  const byId = new Map(loadDerivedArtifactDescriptors().map((d) => [d.artifactId, d.derivation]));
  assert.equal(byId.get(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki), 'encode-spki');
  assert.equal(byId.get(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo), 'encode-private-key-info',
    "RSA's private container is produced by encodePrivateKeyInfo, not encodePkcs8");
  // And EC's own use of 'encode-pkcs8' is untouched: two different encoders
  // must not share one identifier.
  assert.equal(byId.get(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8), 'encode-pkcs8');
});

// --- Positive derivation ---------------------------------------------------

test('M3.2.4b-2.15-D: both RSA artifacts derive to their pinned hashes, deterministically', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder);
  const pki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder);
  assert.deepEqual(
    Buffer.from(pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder)),
    Buffer.from(spki),
  );
  assert.notDeepEqual(Buffer.from(spki), Buffer.from(pki), 'the two containers are genuinely different');
  assert.ok(pki.length > spki.length, 'PrivateKeyInfo is the structurally richer container');
});

test('M3.2.4b-2.15-D: both import back under the frozen contract, IN THEIR OWN ROLES', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder);
  const pki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder);
  assert.equal(importRsaSer(spki, 'public').role, 'public');
  assert.equal(importRsaSer(pki, 'private').role, 'private');
});

test('M3.2.4b-2.15-D: Encode(Import(A)) === A for both -- canonical, not merely parseable', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder);
  const pki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder);
  assert.deepEqual(
    Buffer.from(encodeSpki(importRsaSer(spki, 'public') as RsaPublicMaterial)),
    Buffer.from(spki),
  );
  assert.deepEqual(
    Buffer.from(encodePrivateKeyInfo(importRsaSer(pki, 'private') as RsaPrivateMaterial)),
    Buffer.from(pki),
  );
});

test('M3.2.4b-2.15-D: the derived material matches the frozen source key', () => {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder);
  const back = importRsaSer(spki, 'public') as RsaPublicMaterial;
  assert.equal(back.n, big(r.n));
  assert.equal(back.e, big(r.e));
});

// --- The pin must be seen to REJECT ---------------------------------------

test('M3.2.4b-2.15-D: a CROSSED encoder is rejected by the hash pin, in both directions', () => {
  assert.throws(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, pkiEncoder), MaterialPoolError);
  assert.throws(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, spkiEncoder), MaterialPoolError);
});

test("M3.2.4b-2.15-D: EC's encoder against an RSA descriptor is rejected -- descriptors are not interchangeable", () => {
  // Structurally the encoders accept the same MaterialValue type, so nothing
  // but the hash prevents this; that is exactly what makes the pin load-bearing.
  const wrongMaterialEncoder = (v: MaterialValue) => {
    const r = v as Rsa3072KeyPairMaterial;
    return new Uint8Array(r.n); // plausible bytes, wrong derivation entirely
  };
  assert.throws(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, wrongMaterialEncoder), MaterialPoolError);
});

test('M3.2.4b-2.15-D: a single flipped byte is rejected, for each RSA artifact', () => {
  for (const [id, enc] of [
    [PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder],
    [PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder],
  ] as const) {
    const drifted = (v: MaterialValue) => {
      const out = new Uint8Array(enc(v));
      out[out.length - 1] = out[out.length - 1]! ^ 0x01;
      return out;
    };
    assert.throws(() => pool.deriveArtifact(id, drifted), MaterialPoolError, id);
  }
});

// --- Bytes must NOT be stored, and the corpus stays intact ----------------

test('M3.2.4b-2.15-D: no RSA derived bytes are stored -- only the recipe and hash', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const nodePath = await import('node:path');
  const corpusPath = nodePath.join(
    nodePath.dirname(fileURLToPath(new URL('../../../../harness/phase-c/material/load.ts', import.meta.url))),
    'frozen-material.json',
  );
  const raw = readFileSync(corpusPath, 'utf8');
  for (const [id, enc] of [
    [PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder],
    [PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder],
  ] as const) {
    const bytes = pool.deriveArtifact(id, enc);
    assert.ok(!raw.includes(Buffer.from(bytes).toString('hex')), `${id}: bytes must not appear in the corpus`);
    assert.ok(raw.includes(id), `${id}: its descriptor must appear`);
  }
});

test('M3.2.4b-2.15-D: the record count is unchanged -- descriptors are not records', () => {
  assert.equal(pool.materialIds().length, 9);
  assert.equal(pool.derivedArtifactIds().length, 4);
});

test("M3.2.4b-2.15-D: EC's two descriptors still derive correctly -- the union extension broke nothing", async () => {
  const { encodeSpki: ecSpki, encodePkcs8: ecPkcs8 } = await import('../../../../src/contract/ec-ser.js');
  const ec = pool.valueOf(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair') as { x: Uint8Array; y: Uint8Array; d: Uint8Array };
  const q = { x: big(ec.x), y: big(ec.y) };
  assert.doesNotThrow(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, () => ecSpki({ role: 'public', q })));
  assert.doesNotThrow(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, () => ecPkcs8({ role: 'private', d: big(ec.d), q })));
});
