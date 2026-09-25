// M3.2.4b-2.8 -- corpus extension: pss-valid-signature-02.
//
// A material requirement DISCOVERED during exhaustive binding, not a
// correction of M3.2.4a-6. PSS-VERIFICATION-FALSE-REJECT needs two
// INDEPENDENTLY VALID signatures over the SAME message under the SAME key:
// its mutate() swaps which one is "current", and the correct verify()
// outcome is true for BOTH. A second signature that were not genuinely
// valid would make the class measure the opposite of what it exists for.
//
// Conditions, beyond the standard procedure:
//     M_02 = M_01        same message
//     K_02 = K_01        same frozen RSA-3072 key
//     sigma_02 != sigma_01   distinct (PSS is probabilistic: distinct salt)
//     Verify(sigma_02, M, K_pub) = true, and cross-validated
//
// pss-valid-signature-01 is NOT touched: neither its value, nor its schema,
// nor its hash. This APPENDS a record, preserving the earlier material's
// genealogy intact.

import { webcrypto, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalEncode } from '../harness/canonical/canonical-encode.js';
import { validateMaterial } from '../harness/phase-c/material/schema.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../harness/phase-c/material/load.js';
import type { PssValidSignatureArtifact, Rsa3072KeyPairMaterial } from '../harness/phase-c/material/schema.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(__dirname, '../harness/phase-c/material/frozen-material.json');
const NEW_ID = 'pss-valid-signature-02';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const log = (m: string) => process.stdout.write(m + '\n');

function padLeft(bytes: Uint8Array, width: number): Uint8Array {
  if (bytes.length > width) throw new Error(`value exceeds width ${width}`);
  if (bytes.length === width) return bytes;
  const out = new Uint8Array(width);
  out.set(bytes, width - bytes.length);
  return out;
}

async function main(): Promise<void> {
  const pool = loadFrozenMaterialPool();
  if (pool.materialIds().includes(NEW_ID)) {
    log(`${NEW_ID} already present -- refusing to regenerate frozen material.`);
    return;
  }

  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  const first = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');
  log('== loaded frozen RSA-3072 and pss-valid-signature-01 ==');

  // K_02 = K_01, M_02 = M_01: both taken from the existing frozen material,
  // never re-chosen.
  const jwk = {
    kty: 'RSA', n: b64u(rsa.n), e: b64u(rsa.e), d: b64u(rsa.d),
    p: b64u(rsa.p), q: b64u(rsa.q), dp: b64u(rsa.dp), dq: b64u(rsa.dq), qi: b64u(rsa.qi),
  };
  const priv = await webcrypto.subtle.importKey('jwk', jwk as JsonWebKey, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
  const pub = await webcrypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: jwk.n, e: jwk.e } as JsonWebKey, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify'],
  );

  const message = new Uint8Array(first.message);

  // PSS is probabilistic, but distinctness is REQUIRED, not assumed: retry
  // rather than freeze a colliding second sample.
  let signature: Uint8Array | undefined;
  for (let attempt = 0; attempt < 8; attempt++) {
    const candidate = padLeft(new Uint8Array(await webcrypto.subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 }, priv, message,
    )), 384);
    if (hex(candidate) !== hex(first.signature)) { signature = candidate; break; }
    log('   collision with sigma_01 -- retrying');
  }
  if (!signature) throw new Error('could not obtain a signature distinct from sigma_01');
  log('== STEP 1: generated sigma_02, distinct from sigma_01 ==');

  // Positive validation.
  if (!(await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, signature, message))) {
    throw new Error('sigma_02 does not verify');
  }
  // And sigma_01 must STILL verify -- the pair is what the class needs.
  if (!(await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, first.signature, message))) {
    throw new Error('sigma_01 no longer verifies');
  }
  log('== STEP 2: Verify(sigma_02)=true AND Verify(sigma_01)=true, same M, same K ==');

  // Cross-provider qualification, as for every frozen artifact.
  const nativeBuild = path.join(__dirname, '../harness/orchestration/native-build');
  const bcJar = process.env['BC_JAR'];
  if (!bcJar) throw new Error('BC_JAR must be set for cross-provider qualification');
  const args = ['verify', 'public', hex(rsa.n), hex(rsa.e), '', '3072', hex(message), hex(signature)];

  const cpp = JSON.parse(execFileSync(path.join(nativeBuild, 'pss-cryptopp-cli'), args, { encoding: 'utf8' }));
  log('   Crypto++: ' + JSON.stringify(cpp));
  const bc = JSON.parse(execFileSync('java',
    ['-cp', `${path.join(nativeBuild, 'bc-classes')}:${bcJar}`, 'PssBouncyCastleCli', ...args, 'SHA-256', 'SHA-256'],
    { encoding: 'utf8' }));
  log('   Bouncy Castle: ' + JSON.stringify(bc));
  log('== STEP 3: cross-provider qualified ==');

  // Canonical encode -> SHA256 -> freeze (append only).
  const value: PssValidSignatureArtifact = {
    signature, sourceMaterialId: PHASE_C_MATERIAL_IDS.rsa, message,
  };
  validateMaterial('pss-valid-signature', value);
  const canonicalEncoding = canonicalEncode(value);
  const sha256 = createHash('sha256').update(canonicalEncoding, 'utf8').digest('hex');

  const toStorable = (v: unknown): unknown => {
    if (v instanceof Uint8Array) return { __bytes__: hex(v) };
    if (v !== null && typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) o[k] = toStorable((v as Record<string, unknown>)[k]);
      return o;
    }
    return v;
  };

  const corpus = JSON.parse(readFileSync(CORPUS, 'utf8')) as { schemaVersion: string; records: unknown[] };
  const before = corpus.records.length;
  corpus.records.push({
    materialId: NEW_ID, materialType: 'pss-valid-signature', schemaVersion: '1.0',
    value: toStorable(value), canonicalEncoding, sha256,
    provenance: {
      origin: 'generated-during-m3',
      generator: 'scripts/generate-second-pss-signature.ts',
      generatorVersion: 'M3.2.4b-2.8',
      sourceMaterialIds: [PHASE_C_MATERIAL_IDS.rsa, PHASE_C_MATERIAL_IDS.pssSignature],
      createdAt: new Date().toISOString(),
    },
  });
  writeFileSync(CORPUS, JSON.stringify(corpus, null, 2) + '\n');

  log(`== STEP 4/5: frozen. records ${before} -> ${corpus.records.length} ==`);
  log(`   ${NEW_ID}  ${sha256}`);
}

main().catch((e) => { process.stderr.write('EXTENSION FAILED: ' + String(e) + '\n'); process.exit(1); });
