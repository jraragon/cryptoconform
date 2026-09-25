// M3.2.4b-2.15-D -- RSA derived-artifact qualification.
//
// Materializes descriptors for BOTH RSA containers the frozen contract
// supports, so that Phase C can exercise each:
//     A_pub  = SPKI(K_pub)
//     A_priv = PrivateKeyInfo(K_priv)
//
// Scope is deliberately availability + identity + qualification. WHICH class
// consumes which artifact is a binding decision and belongs to -R:
//     D = availability + identity + qualification
//     R = experimental binding
//
// --- Why both, rather than SPKI alone ---
//
// Two of the six serialized classes empirically REQUIRE SPKI (they intervene
// on the AlgorithmIdentifier at a position only SPKI has there, and throw on
// PrivateKeyInfo). The other four are role-agnostic: their Gamma_0 clauses
// -- der-syntax, container, exact-consumption, role-container -- name no
// role at all, and both containers satisfy them.
//
// Qualifying only SPKI would therefore leave Coverage(PrivateKeyInfo) = 0:
// a container that the contract supports and that we had qualified, yet
// which never participates in Phase C. That is precisely the nominal
// infrastructure the DerivedArtifactDescriptor integration existed to avoid.
// Freezing both yields Coverage(SPKI) > 0 AND Coverage(PrivateKeyInfo) > 0
// without touching a single mutation, adding a class, or multiplying stimuli.

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalEncode } from '../harness/canonical/canonical-encode.js';
import { sha256Hex } from '../harness/phase-c/material/canonical-identity.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../harness/phase-c/material/load.js';
import type { Rsa3072KeyPairMaterial } from '../harness/phase-c/material/schema.js';
import type { RsaPublicMaterial, RsaPrivateMaterial } from '../src/contract/rsa-ser.js';
import { encodeSpki, encodePrivateKeyInfo, importRsaSer } from '../src/contract/rsa-ser.js';

const CORPUS = path.join(path.dirname(fileURLToPath(import.meta.url)), '../harness/phase-c/material/frozen-material.json');
const log = (m: string) => process.stdout.write(m + '\n');
const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));

async function main(): Promise<void> {
  const pool = loadFrozenMaterialPool();
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  log('== loaded frozen RSA-3072 material ==');

  const pub: RsaPublicMaterial = { role: 'public', n: big(r.n), e: big(r.e) };
  const priv: RsaPrivateMaterial = {
    role: 'private', n: big(r.n), e: big(r.e), d: big(r.d),
    p: big(r.p), q: big(r.q), dP: big(r.dp), dQ: big(r.dq), qInv: big(r.qi),
  };

  const spki = encodeSpki(pub);
  const pki = encodePrivateKeyInfo(priv);
  log(`   SPKI            ${spki.length} bytes`);
  log(`   PrivateKeyInfo  ${pki.length} bytes`);

  // Qualification: each must import back under the frozen contract IN ITS
  // OWN ROLE, and re-encode to the exact same bytes. Producing bytes is not
  // enough -- the GCM lesson.
  const backPub = importRsaSer(spki, 'public');
  const backPriv = importRsaSer(pki, 'private');
  if (backPub.role !== 'public') throw new Error('SPKI did not import as public material');
  if (backPriv.role !== 'private') throw new Error('PrivateKeyInfo did not import as private material');
  if (Buffer.compare(Buffer.from(encodeSpki(backPub as RsaPublicMaterial)), Buffer.from(spki)) !== 0) {
    throw new Error('SPKI round trip is not canonical');
  }
  if (Buffer.compare(Buffer.from(encodePrivateKeyInfo(backPriv as RsaPrivateMaterial)), Buffer.from(pki)) !== 0) {
    throw new Error('PrivateKeyInfo round trip is not canonical');
  }
  log('   both import in their own roles and round-trip canonically');

  const descriptors = [
    {
      artifactId: PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki,
      sourceMaterialId: PHASE_C_MATERIAL_IDS.rsa,
      derivation: 'encode-spki',
      expectedSha256: sha256Hex(canonicalEncode(spki)),
    },
    {
      artifactId: PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo,
      sourceMaterialId: PHASE_C_MATERIAL_IDS.rsa,
      // Names the REAL encoder, not an approximately equivalent label.
      derivation: 'encode-private-key-info',
      expectedSha256: sha256Hex(canonicalEncode(pki)),
    },
  ];

  const corpus = JSON.parse(readFileSync(CORPUS, 'utf8')) as Record<string, unknown>;
  const existing = ((corpus['derivedArtifacts'] as { artifactId: string }[] | undefined) ?? []);
  if (existing.some((d) => d.artifactId === PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki)) {
    log('== RSA descriptors already present -- refusing to regenerate ==');
    return;
  }
  corpus['derivedArtifacts'] = [...existing, ...descriptors];
  writeFileSync(CORPUS, JSON.stringify(corpus, null, 2) + '\n');

  for (const d of descriptors) log(`   ${d.artifactId.padEnd(38)} ${d.derivation.padEnd(24)} ${d.expectedSha256}`);

  const raw = readFileSync(CORPUS, 'utf8');
  for (const [label, bytes] of [['SPKI', spki], ['PrivateKeyInfo', pki]] as const) {
    if (raw.includes(Buffer.from(bytes).toString('hex'))) {
      throw new Error(`${label} bytes leaked into the corpus; only the recipe and hash may be stored`);
    }
  }
  log(`== descriptors frozen; no derived bytes stored; ${(corpus['derivedArtifacts'] as unknown[]).length} descriptors total ==`);
}

main().catch((e) => { process.stderr.write('QUALIFICATION FAILED: ' + String(e) + '\n'); process.exit(1); });
