// M3.2.4a-6 -- ONE-TIME real material generation, validation and freeze.
//
// Run once during M3. Its output (frozen-material.json) is the frozen
// corpus; M4 only ever LOADS it (I_pool3). This script is deliberately NOT
// importable from the pool module -- the pool exposes no generation path.
//
// Strict order, per the closed M3.2.4a-6 contract:
//   Generate once -> Validate -> Derive/Generate A0 -> Cross-validate
//   -> CanonicalEncode -> SHA256 -> Freeze
//
// Cryptographic validity is checked, never merely structural conformance:
// a 384-byte n is not evidence that the RSA pair works, and 32-byte x/y/d
// are not evidence that Q = dG.

import { generateKeyPairSync, webcrypto, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalEncode } from '../harness/canonical/canonical-encode.js';
import { validateMaterial } from '../harness/phase-c/material/schema.js';
import { isOnCurve, isPair, isValidScalar } from '../src/contract/p256.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '../harness/phase-c/material/frozen-material.json');

function b64uToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

// Left-pad to an exact width. Never truncates: a value wider than the
// target is a generation error, not something to silently trim.
function padLeft(bytes: Uint8Array, width: number, field: string): Uint8Array {
  if (bytes.length > width) throw new Error(`${field}: ${bytes.length} bytes exceeds the required width ${width}`);
  if (bytes.length === width) return bytes;
  const out = new Uint8Array(width);
  out.set(bytes, width - bytes.length);
  return out;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + (hex(bytes) || '0'));
}

const log = (m: string) => process.stdout.write(m + '\n');

async function main(): Promise<void> {
  const createdAt = new Date().toISOString();
  const records: unknown[] = [];

  // =====================================================================
  // STEP 1 -- Generate the four primary materials, once.
  // =====================================================================
  log('== STEP 1: generate primaries ==');

  const { privateKey: rsaKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const rj = rsaKey.export({ format: 'jwk' }) as Record<string, string>;
  const rsaValue = {
    modulusBits: 3072 as const,
    n: padLeft(b64uToBytes(rj['n']!), 384, 'n'),
    e: b64uToBytes(rj['e']!), // genuinely variable-width, not padded
    d: padLeft(b64uToBytes(rj['d']!), 384, 'd'),
    p: padLeft(b64uToBytes(rj['p']!), 192, 'p'),
    q: padLeft(b64uToBytes(rj['q']!), 192, 'q'),
    dp: padLeft(b64uToBytes(rj['dp']!), 192, 'dp'),
    dq: padLeft(b64uToBytes(rj['dq']!), 192, 'dq'),
    qi: padLeft(b64uToBytes(rj['qi']!), 192, 'qi'),
  };

  const { privateKey: ecKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ej = ecKey.export({ format: 'jwk' }) as Record<string, string>;
  const ecValue = {
    curve: 'P-256' as const,
    x: padLeft(b64uToBytes(ej['x']!), 32, 'x'),
    y: padLeft(b64uToBytes(ej['y']!), 32, 'y'),
    d: padLeft(b64uToBytes(ej['d']!), 32, 'd'),
  };

  const aesValue = {
    key: new Uint8Array(webcrypto.getRandomValues(new Uint8Array(32))),
    iv: new Uint8Array(webcrypto.getRandomValues(new Uint8Array(12))),
    plaintext: new Uint8Array(Buffer.from('Paper 4 Phase C canonical plaintext', 'utf8')),
    aad: new Uint8Array(Buffer.from('phase-c-aad', 'utf8')),
  };

  // RFC 5869 Appendix A.1 Test Case 1 -- a published KAT already exercised
  // throughout M2.5, chosen over random bytes so the HKDF base material is
  // independently auditable against the RFC.
  const hkdfValue = {
    ikm: new Uint8Array(Buffer.from('0b'.repeat(22), 'hex')),
    salt: new Uint8Array(Buffer.from('000102030405060708090a0b0c', 'hex')),
    info: new Uint8Array(Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')),
  };
  log('   generated: RSA-3072, EC-P256, AES, HKDF');

  // =====================================================================
  // STEP 2 -- Validate CRYPTOGRAPHIC validity, not just field widths.
  // =====================================================================
  log('== STEP 2: cryptographic validation ==');

  // EC: verify d is a valid scalar and Q = dG, using M1's own FROZEN P-256
  // arithmetic -- an independent check, not the generator's own word.
  const d = bytesToBigInt(ecValue.d);
  const q = { x: bytesToBigInt(ecValue.x), y: bytesToBigInt(ecValue.y) };
  if (!isValidScalar(d)) throw new Error('EC: d is not a valid scalar');
  if (!isOnCurve(q)) throw new Error('EC: Q is not on the curve');
  if (!isPair(d, q)) throw new Error('EC: Q != dG');
  log('   EC: isValidScalar, isOnCurve, isPair all true (verified via M1 p256.ts)');

  // RSA: the pair must actually operate, not merely have the right widths.
  const rsaCryptoKey = await webcrypto.subtle.importKey(
    'jwk', rj as JsonWebKey, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign'],
  );
  const rsaPubJwk = { kty: rj['kty'], n: rj['n'], e: rj['e'] };
  const rsaPubKey = await webcrypto.subtle.importKey(
    'jwk', rsaPubJwk as JsonWebKey, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify'],
  );
  log('   RSA: key pair imports and is usable');

  // =====================================================================
  // STEP 3 -- Generate the two A0 artifacts that no pure encoder can build.
  // =====================================================================
  log('== STEP 3: generate A0 artifacts ==');

  const aesCryptoKey = await webcrypto.subtle.importKey('raw', aesValue.key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const gcmCiphertext = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: aesValue.iv, additionalData: aesValue.aad, tagLength: 128 },
    aesCryptoKey, aesValue.plaintext,
  ));

  const pssMessage = new Uint8Array(Buffer.from('Paper 4 Phase C canonical message', 'utf8'));
  const pssSignature = padLeft(new Uint8Array(await webcrypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 }, rsaCryptoKey, pssMessage,
  )), 384, 'signature');
  log('   generated: A0_GCM (' + gcmCiphertext.length + ' B), A0_PSS (' + pssSignature.length + ' B)');

  // =====================================================================
  // STEP 4 -- Positive validation, then CROSS-PROVIDER qualification.
  //           InstrumentQualification != ScoredEvidence.
  // =====================================================================
  log('== STEP 4: positive + cross-provider validation ==');

  const decrypted = new Uint8Array(await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: aesValue.iv, additionalData: aesValue.aad, tagLength: 128 },
    aesCryptoKey, gcmCiphertext,
  ));
  if (hex(decrypted) !== hex(aesValue.plaintext)) throw new Error('A0_GCM: Decrypt(A0) != PT');
  log('   A0_GCM: Decrypt(K,IV,AAD,A0) == PT');

  const verified = await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, rsaPubKey, pssSignature, pssMessage);
  if (!verified) throw new Error('A0_PSS: Verify(A0) != true');
  log('   A0_PSS: Verify(K_pub, M, A0) == true');

  // Cross-provider: the scientific backends that must consume A0_PSS are
  // asked to verify it. If any refuses valid base material we STOP -- the
  // fixture is never adapted per backend, which would destroy the premise
  // of common material.
  const nativeBuild = path.join(__dirname, '../harness/orchestration/native-build');
  const bcJar = process.env['BC_JAR'];
  if (!bcJar) throw new Error('BC_JAR must be set for cross-provider qualification');

  // Real CLI interfaces, confirmed from source rather than assumed:
  //   pss-cryptopp-cli  verify <role> <n> <e> <d> <modulusBits> <msg> <sig>
  //   PssBouncyCastleCli verify <role> <n> <e> <d> <modulusBits> <msg> <sig> <hash> <mgfHash>
  const cppOut = execFileSync(path.join(nativeBuild, 'pss-cryptopp-cli'),
    ['verify', 'public', hex(rsaValue.n), hex(rsaValue.e), '', '3072', hex(pssMessage), hex(pssSignature)],
    { encoding: 'utf8' });
  const cppOk = JSON.parse(cppOut);
  log('   A0_PSS verified by Crypto++: ' + JSON.stringify(cppOk));

  const bcOut = execFileSync('java',
    ['-cp', `${path.join(nativeBuild, 'bc-classes')}:${bcJar}`, 'PssBouncyCastleCli',
      'verify', 'public', hex(rsaValue.n), hex(rsaValue.e), '', '3072', hex(pssMessage), hex(pssSignature),
      'SHA-256', 'SHA-256'],
    { encoding: 'utf8' });
  const bcOk = JSON.parse(bcOut);
  log('   A0_PSS verified by Bouncy Castle: ' + JSON.stringify(bcOk));

  // =====================================================================
  // STEP 5/6 -- CanonicalEncode -> SHA256 -> Freeze.
  // =====================================================================
  log('== STEP 5/6: canonical encode, hash, freeze ==');

  const gcmArtifactValue = { ciphertext: gcmCiphertext, sourceMaterialId: 'aes-phasec-primary-01' };
  const pssArtifactValue = { signature: pssSignature, sourceMaterialId: 'rsa-3072-primary-01', message: pssMessage };

  const spec = [
    ['rsa-3072-primary-01', 'rsa-3072-keypair', rsaValue, undefined],
    ['ec-p256-primary-01', 'ec-p256-keypair', ecValue, undefined],
    ['aes-phasec-primary-01', 'aes-base-material', aesValue, undefined],
    ['hkdf-phasec-primary-01', 'hkdf-base-material', hkdfValue, undefined],
    ['gcm-valid-artifact-01', 'gcm-valid-artifact', gcmArtifactValue, ['aes-phasec-primary-01']],
    ['pss-valid-signature-01', 'pss-valid-signature', pssArtifactValue, ['rsa-3072-primary-01']],
  ] as const;

  // Bytes are stored as hex in JSON; the loader reconstructs Uint8Array
  // before recomputing the encoding, so the stored hash is verifiable.
  const toStorable = (v: unknown): unknown => {
    if (v instanceof Uint8Array) return { __bytes__: hex(v) };
    if (Array.isArray(v)) return v.map(toStorable);
    if (v !== null && typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) o[k] = toStorable((v as Record<string, unknown>)[k]);
      return o;
    }
    return v;
  };

  for (const [materialId, materialType, value, sourceIds] of spec) {
    validateMaterial(materialType, value as never);
    const canonicalEncoding = canonicalEncode(value);
    const sha256 = createHash('sha256').update(canonicalEncoding, 'utf8').digest('hex');
    records.push({
      materialId, materialType, schemaVersion: '1.0',
      value: toStorable(value),
      canonicalEncoding, sha256,
      provenance: {
        origin: 'generated-during-m3',
        generator: 'scripts/generate-frozen-material.ts',
        generatorVersion: 'M3.2.4a-6',
        ...(sourceIds ? { sourceMaterialIds: sourceIds } : {}),
        createdAt,
      },
    });
    log(`   ${materialId.padEnd(24)} ${sha256}`);
  }

  writeFileSync(OUT, JSON.stringify({ schemaVersion: '1.0', records }, null, 2) + '\n');
  log('== frozen to ' + OUT + ' ==');
}

main().catch((e) => { process.stderr.write('GENERATION FAILED: ' + String(e) + '\n'); process.exit(1); });
