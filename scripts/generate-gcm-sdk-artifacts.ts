// M3.2.4b-2.13 -- GCM artifact corpus remediation.
//
// Generates the two SDK-format artifacts GCM x artifact-transform requires,
// and marks gcm-valid-artifact-01 as superseded WITHOUT touching its bytes,
// hash or original provenance.
//
// --- The qualification defect this remediates ---
//
// gcm-valid-artifact-01 holds the raw output of webcrypto.subtle.encrypt,
// i.e. C||tag. That is cryptographically valid and decrypts correctly, so
// M3.2.4a-6's own check (Decrypt(K,IV,AAD,A_0) = PT) passed truthfully.
// But it is not an artifact of the SDK contract under experiment:
//     A_SDK = version || IV || C || tag
// and parseAeadArtifact rejects the frozen value outright
// ([malformed_artifact] unsupported artifact version 140, expected 1).
// All three artifact-transform classes call parseAeadArtifact, so none
// could have consumed it.
//
// The generation was reproducible and its validation was true; what was
// insufficient was the QUALIFICATION CRITERION. PSS did not expose this
// because an RSA-PSS signature carries no SDK-specific envelope.
//
// --- Strengthened gate, applied to every artifact frozen here ---
//
//     Valid(A_0) = Valid_SDK-format(A_0) AND Valid_cryptographic(A_0)
//
// concretely:
//   1. parseAeadArtifact(A_0) yields { version=1, IV, C, tag }
//   2. serialize(parse(A_0)) === A_0        (canonical, not merely parseable)
//   3. Decrypt(K, IV, AAD, C||tag) = PT     (cryptographically genuine)
//   4. for the swap artifact additionally |C| = TAG_LEN_BYTES
//
// Two artifacts rather than one, because M2's own contract requires it:
// GCM-ARTIFACT-C-T-SWAP throws unless |C| = TAG_LEN_BYTES, and its comment
// states the caller must supply such a fixture. Minimising record count by
// forcing one artifact to serve all three classes would mean redesigning
// the corpus around a convenience rather than respecting a stated
// precondition.

import { webcrypto, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalEncode } from '../harness/canonical/canonical-encode.js';
import { validateMaterial } from '../harness/phase-c/material/schema.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../harness/phase-c/material/load.js';
import type { AesBaseMaterial } from '../harness/phase-c/material/schema.js';
import {
  buildAeadArtifact, parseAeadArtifact, ARTIFACT_VERSION, TAG_LEN_BYTES, IV_LEN_BYTES,
} from '../src/contract/gcm.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(__dirname, '../harness/phase-c/material/frozen-material.json');

const GENERAL_ID = 'gcm-sdk-artifact-general-01';
const SWAP_ID = 'gcm-sdk-artifact-ctlen-01';
const SUPERSEDED_ID = PHASE_C_MATERIAL_IDS.gcmArtifact; // gcm-valid-artifact-01

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const log = (m: string) => process.stdout.write(m + '\n');

async function makeSdkArtifact(
  key: Uint8Array, iv: Uint8Array, aad: Uint8Array | undefined, plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const params: Record<string, unknown> = { name: 'AES-GCM', iv, tagLength: TAG_LEN_BYTES * 8 };
  if (aad !== undefined) params['additionalData'] = aad;
  const raw = new Uint8Array(await webcrypto.subtle.encrypt(params as unknown as AesGcmParams, cryptoKey, plaintext));
  // WebCrypto returns C||tag; the SDK's own domain is version||IV||C||tag.
  const ciphertext = raw.slice(0, raw.length - TAG_LEN_BYTES);
  const tag = raw.slice(raw.length - TAG_LEN_BYTES);
  return buildAeadArtifact(iv, ciphertext, tag);
}

async function qualify(
  label: string, artifact: Uint8Array,
  key: Uint8Array, iv: Uint8Array, aad: Uint8Array | undefined, plaintext: Uint8Array,
  requiredCiphertextLen?: number,
): Promise<void> {
  // 1. SDK-format parse.
  const parts = parseAeadArtifact(artifact);
  if (parts.version !== ARTIFACT_VERSION) throw new Error(`${label}: version ${parts.version} != ${ARTIFACT_VERSION}`);
  if (parts.iv.length !== IV_LEN_BYTES) throw new Error(`${label}: IV ${parts.iv.length} != ${IV_LEN_BYTES}`);
  if (parts.tag.length !== TAG_LEN_BYTES) throw new Error(`${label}: tag ${parts.tag.length} != ${TAG_LEN_BYTES}`);
  if (hex(parts.iv) !== hex(iv)) throw new Error(`${label}: embedded IV differs from the frozen AES IV`);

  // 2. Canonical round trip -- parseable is not enough.
  const reserialized = buildAeadArtifact(parts.iv, parts.ciphertext, parts.tag);
  if (hex(reserialized) !== hex(artifact)) throw new Error(`${label}: serialize(parse(A)) != A`);

  // 3. Cryptographically genuine.
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const params: Record<string, unknown> = { name: 'AES-GCM', iv: parts.iv, tagLength: TAG_LEN_BYTES * 8 };
  if (aad !== undefined) params['additionalData'] = aad;
  const combined = new Uint8Array(parts.ciphertext.length + parts.tag.length);
  combined.set(parts.ciphertext); combined.set(parts.tag, parts.ciphertext.length);
  const out = new Uint8Array(await webcrypto.subtle.decrypt(params as unknown as AesGcmParams, cryptoKey, combined));
  if (hex(out) !== hex(plaintext)) throw new Error(`${label}: Decrypt(K,IV,AAD,C||tag) != PT`);

  // 4. Class-specific precondition.
  if (requiredCiphertextLen !== undefined && parts.ciphertext.length !== requiredCiphertextLen) {
    throw new Error(`${label}: |C|=${parts.ciphertext.length}, required ${requiredCiphertextLen}`);
  }

  log(`   ${label}: SDK-format OK, round-trip OK, decrypt OK, |C|=${parts.ciphertext.length}`);
}

async function main(): Promise<void> {
  const pool = loadFrozenMaterialPool();
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');
  log('== loaded frozen AES material ==');

  // Demonstrate the defect explicitly, so the remediation is evidenced
  // rather than asserted.
  const old = pool.getHistorical(SUPERSEDED_ID);
  const oldBytes = (old.value as { ciphertext: Uint8Array }).ciphertext;
  let oldParses = true;
  try { parseAeadArtifact(oldBytes); } catch { oldParses = false; }
  log(`== defect: ${SUPERSEDED_ID} (${oldBytes.length} B) parses under the SDK contract? ${oldParses} ==`);
  if (oldParses) throw new Error('expected the superseded artifact NOT to parse; the defect premise is wrong');

  // --- General artifact: the frozen plaintext, in SDK format -------------
  const general = await makeSdkArtifact(aes.key, aes.iv, aes.aad, aes.plaintext);
  await qualify(GENERAL_ID, general, aes.key, aes.iv, aes.aad, aes.plaintext);

  // --- Swap artifact: |C| = TAG_LEN_BYTES ------------------------------
  // AES-GCM is a stream cipher mode, so |C| = |PT|; a 16-byte plaintext
  // yields exactly the ciphertext length C-T-SWAP requires.
  const swapPlaintext = new Uint8Array(Buffer.from('PhaseC-CTSwap-16', 'utf8'));
  if (swapPlaintext.length !== TAG_LEN_BYTES) {
    throw new Error(`swap plaintext is ${swapPlaintext.length} bytes, must be ${TAG_LEN_BYTES}`);
  }
  const swap = await makeSdkArtifact(aes.key, aes.iv, aes.aad, swapPlaintext);
  await qualify(SWAP_ID, swap, aes.key, aes.iv, aes.aad, swapPlaintext, TAG_LEN_BYTES);

  // --- Freeze ------------------------------------------------------------
  const toStorable = (v: unknown): unknown => {
    if (v instanceof Uint8Array) return { __bytes__: hex(v) };
    if (v !== null && typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) o[k] = toStorable((v as Record<string, unknown>)[k]);
      return o;
    }
    return v;
  };

  const corpus = JSON.parse(readFileSync(CORPUS, 'utf8')) as { schemaVersion: string; records: Record<string, unknown>[] };
  const createdAt = new Date().toISOString();

  for (const [materialId, artifact] of [[GENERAL_ID, general], [SWAP_ID, swap]] as const) {
    if (corpus.records.some((r) => r['materialId'] === materialId)) {
      log(`   ${materialId} already present -- skipping`);
      continue;
    }
    const value = { ciphertext: artifact, sourceMaterialId: PHASE_C_MATERIAL_IDS.aes };
    validateMaterial('gcm-valid-artifact', value);
    const canonicalEncoding = canonicalEncode(value);
    const sha256 = createHash('sha256').update(canonicalEncoding, 'utf8').digest('hex');
    corpus.records.push({
      materialId, materialType: 'gcm-valid-artifact', schemaVersion: '1.0',
      value: toStorable(value), canonicalEncoding, sha256,
      qualification: 'sdk-aead-artifact',
      provenance: {
        origin: 'generated-during-m3',
        generator: 'scripts/generate-gcm-sdk-artifacts.ts',
        generatorVersion: 'M3.2.4b-2.13',
        sourceMaterialIds: [PHASE_C_MATERIAL_IDS.aes],
        createdAt,
      },
    });
    log(`   frozen ${materialId}  ${sha256}`);
  }

  // --- Supersede 01: annotate the RECORD only ----------------------------
  const target = corpus.records.find((r) => r['materialId'] === SUPERSEDED_ID);
  if (!target) throw new Error(`${SUPERSEDED_ID} not found in the corpus`);
  const beforeSha = target['sha256'];
  target['qualification'] = 'webcrypto-output';
  target['supersededBy'] = [GENERAL_ID, SWAP_ID];
  if (target['sha256'] !== beforeSha) throw new Error('supersession must not alter the frozen hash');
  log(`== ${SUPERSEDED_ID}: qualification='webcrypto-output', superseded, hash unchanged (${String(beforeSha).slice(0, 16)}...) ==`);

  writeFileSync(CORPUS, JSON.stringify(corpus, null, 2) + '\n');
  log(`== corpus now ${corpus.records.length} records ==`);
}

main().catch((e) => { process.stderr.write('REMEDIATION FAILED: ' + String(e) + '\n'); process.exit(1); });
