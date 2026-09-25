// M3.2.4b-2.14-D -- prospective corpus integration of the
// DerivedArtifactDescriptor mechanism.
//
// The mechanism was defined and unit-tested in M3.2.4a-5, but had never been
// materialized: the corpus carried no descriptors and the loader read none,
// so FrozenMaterialPool.deriveArtifact() was unreachable from real material.
// EC-ser x artifact-transform is the group it was designed for -- 8 of its
// 11 classes consume SPKI or PKCS8 derived from the frozen EC keypair.
//
// This is NOT a reopening of M3.2.4a-5. The design was right; it simply had
// not been connected to the experimental corpus yet.
//
// --- What is frozen, and what deliberately is not ---
//
//     StoredMaterial            = bytes + hash
//     DerivedArtifactDescriptor = recipe + expectedHash
//
// The derived bytes are NOT duplicated into the corpus. What is pinned is
// their identity, so that
//     "I can produce it"   !=   "this is the artifact I froze"
// -- precisely the distinction whose absence let a webcrypto-output artifact
// pass as an SDK artifact in M3.2.4b-2.13.

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalEncode } from '../harness/canonical/canonical-encode.js';
import { sha256Hex } from '../harness/phase-c/material/canonical-identity.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../harness/phase-c/material/load.js';
import type { EcP256KeyPairMaterial } from '../harness/phase-c/material/schema.js';
import type { EcPublicMaterial, EcPrivateMaterial } from '../src/contract/ec-ser.js';
import { encodeSpki, encodePkcs8, importEcSer } from '../src/contract/ec-ser.js';

const CORPUS = path.join(path.dirname(fileURLToPath(import.meta.url)), '../harness/phase-c/material/frozen-material.json');
const log = (m: string) => process.stdout.write(m + '\n');

function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(b).toString('hex'));
}

async function main(): Promise<void> {
  const pool = loadFrozenMaterialPool();
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  log('== loaded frozen EC P-256 material ==');

  // The bytes -> bigint boundary again, in the safe direction only.
  const d = bytesToBigInt(ec.d);
  const q = { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) };
  const publicMaterial: EcPublicMaterial = { role: 'public', q };
  const privateMaterial: EcPrivateMaterial = { role: 'private', d, q };

  // Derive through the FROZEN M1 encoders -- the only sanctioned derivation.
  const spki = encodeSpki(publicMaterial);
  const pkcs8 = encodePkcs8(privateMaterial);
  log(`   SPKI  ${spki.length} bytes`);
  log(`   PKCS8 ${pkcs8.length} bytes`);

  // Qualification: each derived artifact must be consumable by the frozen
  // contract, in its own role. Producing bytes is not enough -- that was the
  // GCM lesson.
  const backSpki = importEcSer(spki, 'public');
  const backPkcs8 = importEcSer(pkcs8, 'private');
  if (backSpki.material.role !== 'public') throw new Error('SPKI did not import as public material');
  if (backPkcs8.material.role !== 'private') throw new Error('PKCS8 did not import as private material');
  log('   both import back under the frozen contract, in their own roles');

  // Round-trip identity: re-encoding the imported material must reproduce
  // the exact bytes, or the derivation is not canonical.
  if (Buffer.compare(Buffer.from(encodeSpki(backSpki.material as EcPublicMaterial)), Buffer.from(spki)) !== 0) {
    throw new Error('SPKI round trip is not canonical');
  }
  if (Buffer.compare(Buffer.from(encodePkcs8(backPkcs8.material as EcPrivateMaterial)), Buffer.from(pkcs8)) !== 0) {
    throw new Error('PKCS8 round trip is not canonical');
  }
  log('   both round-trip canonically');

  // The hash is computed exactly as deriveArtifact() will recompute it.
  const spkiHash = sha256Hex(canonicalEncode(spki));
  const pkcs8Hash = sha256Hex(canonicalEncode(pkcs8));

  const descriptors = [
    {
      artifactId: PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki,
      sourceMaterialId: PHASE_C_MATERIAL_IDS.ec,
      derivation: 'encode-spki',
      expectedSha256: spkiHash,
    },
    {
      artifactId: PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8,
      sourceMaterialId: PHASE_C_MATERIAL_IDS.ec,
      derivation: 'encode-pkcs8',
      expectedSha256: pkcs8Hash,
    },
  ];

  const corpus = JSON.parse(readFileSync(CORPUS, 'utf8')) as Record<string, unknown>;
  const existing = (corpus['derivedArtifacts'] as unknown[] | undefined) ?? [];
  if (existing.length > 0) { log('== descriptors already present -- refusing to regenerate =='); return; }
  corpus['derivedArtifacts'] = descriptors;
  writeFileSync(CORPUS, JSON.stringify(corpus, null, 2) + '\n');

  for (const d of descriptors) log(`   ${d.artifactId.padEnd(26)} ${d.derivation.padEnd(14)} ${d.expectedSha256}`);

  // The bytes must NOT have leaked into the corpus.
  const raw = readFileSync(CORPUS, 'utf8');
  for (const [label, bytes] of [['SPKI', spki], ['PKCS8', pkcs8]] as const) {
    if (raw.includes(Buffer.from(bytes).toString('hex'))) {
      throw new Error(`${label} bytes were stored in the corpus; only the recipe and hash may be`);
    }
  }
  log('== descriptors frozen; no derived bytes stored ==');
}

main().catch((e) => { process.stderr.write('INTEGRATION FAILED: ' + String(e) + '\n'); process.exit(1); });
