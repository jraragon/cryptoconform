import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  loadFrozenMaterialPool, loadDerivedArtifactDescriptors,
  PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS,
} from '../../../../harness/phase-c/material/load.js';
import { MaterialPoolError } from '../../../../harness/phase-c/material/pool.js';
import type { EcP256KeyPairMaterial, MaterialValue } from '../../../../harness/phase-c/material/schema.js';
import type { EcPublicMaterial, EcPrivateMaterial } from '../../../../src/contract/ec-ser.js';
import { encodeSpki, encodePkcs8, importEcSer } from '../../../../src/contract/ec-ser.js';

const pool = loadFrozenMaterialPool();

// ---------------------------------------------------------------------
// M3.2.4b-2.14-D -- DerivedArtifactDescriptor, connected to the real corpus.
//
// The mechanism was designed and unit-tested in M3.2.4a-5 with synthetic
// fixtures, but the corpus carried no descriptors and the loader read none,
// so deriveArtifact() was unreachable from real material. These tests hold
// the now-materialized mechanism to its purpose:
//     StoredMaterial            = bytes + hash
//     DerivedArtifactDescriptor = recipe + expectedHash
// and, critically, exercise the FAILURE of the pin -- not only the happy
// path -- since an expectedHash that is never seen to reject is decorative.
// ---------------------------------------------------------------------

function toPublic(v: MaterialValue): EcPublicMaterial {
  const ec = v as EcP256KeyPairMaterial;
  const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
  return { role: 'public', q: { x: big(ec.x), y: big(ec.y) } };
}
function toPrivate(v: MaterialValue): EcPrivateMaterial {
  const ec = v as EcP256KeyPairMaterial;
  const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
  return { role: 'private', d: big(ec.d), q: { x: big(ec.x), y: big(ec.y) } };
}
const spkiEncoder = (v: MaterialValue) => encodeSpki(toPublic(v));
const pkcs8Encoder = (v: MaterialValue) => encodePkcs8(toPrivate(v));

// --- The descriptors are genuinely carried by the corpus ------------------

test('M3.2.4b-2.14-D: the corpus carries the two pinned EC descriptors', () => {
  // Scoped to the EC pair: M3.2.4b-2.15-D later added two RSA descriptors,
  // so an unqualified total would drift. The EC assertions stay exact.
  const ecIds: readonly string[] = [PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8];
  const descriptors = loadDerivedArtifactDescriptors().filter((d) => ecIds.includes(d.artifactId));
  assert.equal(descriptors.length, 2);
  assert.deepEqual(descriptors.map((d) => d.artifactId).sort(), [...ecIds].sort());
  for (const d of descriptors) {
    assert.equal(d.sourceMaterialId, PHASE_C_MATERIAL_IDS.ec, 'both derive from the frozen EC keypair');
    assert.equal(d.expectedSha256.length, 64);
  }
});

test('M3.2.4b-2.14-D: the pool exposes them through its normal API', () => {
  const exposed = [...pool.derivedArtifactIds()];
  assert.ok(exposed.includes(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki));
  assert.ok(exposed.includes(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8));
  // The full set is pinned by name, so a missing or renamed descriptor is
  // still a loud failure rather than a silent absence.
  assert.deepEqual(exposed, [...Object.values(PHASE_C_DERIVED_ARTIFACT_IDS)].sort());
});

test('M3.2.4b-2.14-D: each descriptor names its own encoder, and they differ', () => {
  const byId = new Map(loadDerivedArtifactDescriptors().map((d) => [d.artifactId, d.derivation]));
  assert.equal(byId.get(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki), 'encode-spki');
  assert.equal(byId.get(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8), 'encode-pkcs8');
});

// --- Positive derivation ---------------------------------------------------

test('M3.2.4b-2.14-D: deriveArtifact reproduces the SPKI whose hash the descriptor pins', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder);
  assert.ok(spki.length > 0);
  // Deterministic across calls: same recipe, same bytes.
  assert.deepEqual(
    Buffer.from(pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder)),
    Buffer.from(spki),
  );
});

test('M3.2.4b-2.14-D: deriveArtifact reproduces the PKCS8 whose hash the descriptor pins', () => {
  const pkcs8 = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, pkcs8Encoder);
  assert.ok(pkcs8.length > 0);
  assert.notDeepEqual(
    Buffer.from(pkcs8),
    Buffer.from(pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder)),
    'the two derived artifacts are genuinely different objects',
  );
});

test('M3.2.4b-2.14-D: both derived artifacts import back under the frozen contract, in their own roles', () => {
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder);
  const pkcs8 = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, pkcs8Encoder);
  assert.equal(importEcSer(spki, 'public').material.role, 'public');
  assert.equal(importEcSer(pkcs8, 'private').material.role, 'private');
});

test('M3.2.4b-2.14-D: the derived material matches the frozen source material', () => {
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
  const spki = pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder);
  const back = importEcSer(spki, 'public').material as EcPublicMaterial;
  assert.notEqual(back.q, 'infinity');
  if (back.q !== 'infinity') {
    assert.equal(back.q.x, big(ec.x));
    assert.equal(back.q.y, big(ec.y));
  }
});

// --- The pin must be seen to REJECT ---------------------------------------

test('M3.2.4b-2.14-D: a WRONG encoder is rejected by the hash pin -- the failure path, not only the happy one', () => {
  // PKCS8 bytes offered against the SPKI descriptor.
  assert.throws(
    () => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, pkcs8Encoder),
    MaterialPoolError,
  );
  assert.throws(
    () => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, spkiEncoder),
    MaterialPoolError,
  );
});

test('M3.2.4b-2.14-D: a single flipped byte in the encoder output is rejected', () => {
  const drifted = (v: MaterialValue) => {
    const out = new Uint8Array(encodeSpki(toPublic(v)));
    out[out.length - 1] = out[out.length - 1]! ^ 0x01;
    return out;
  };
  assert.throws(() => pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, drifted), MaterialPoolError);
});

test('M3.2.4b-2.14-D: an unknown artifactId fails closed', () => {
  assert.throws(() => pool.deriveArtifact('no-such-derived-artifact', spkiEncoder), MaterialPoolError);
});

// --- Bytes must NOT be stored ---------------------------------------------

test('M3.2.4b-2.14-D: the derived bytes are NOT duplicated into the corpus -- only the recipe and hash', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');
  const corpusPath = path.join(
    path.dirname(fileURLToPath(new URL('../../../../harness/phase-c/material/load.ts', import.meta.url))),
    'frozen-material.json',
  );
  const raw = readFileSync(corpusPath, 'utf8');

  for (const [id, encoder] of [
    [PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder],
    [PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, pkcs8Encoder],
  ] as const) {
    const bytes = pool.deriveArtifact(id, encoder);
    assert.ok(!raw.includes(Buffer.from(bytes).toString('hex')),
      `${id}: derived bytes must not appear in the corpus`);
  }
  // The descriptors themselves must be there, though.
  assert.ok(raw.includes(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki));
  assert.ok(raw.includes(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8));
});

test('M3.2.4b-2.14-D: the whole corpus still loads and verifies fail-closed', () => {
  assert.doesNotThrow(() => loadFrozenMaterialPool());
  assert.equal(loadFrozenMaterialPool().materialIds().length, 9, 'no record was added: descriptors are not records');
});
