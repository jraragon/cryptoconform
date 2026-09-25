import { webcrypto } from 'node:crypto';
import { importRsaSer, exportRsaSer, type RsaKeyMaterial } from '../../contract/rsa-ser.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex } from '../../evidence/record.js';

/**
 * WebCrypto RSA Key Serialization adapter.
 *
 * CRITICAL: Accept_C is NEVER
 * delegated to subtle.importKey(). The flow is strictly:
 *   1. importRsaSer(artifact, role) -- OUR OWN C_struct/C_profile/C_math
 *      classifier, using OUR OWN DER parser (src/contract/der.ts), runs
 *      FIRST. If it rejects, subtle.importKey is NEVER CALLED -- literal
 *      proof that WebCrypto's native errors play no role in classification.
 *   2. ONLY once our own Accept_C has already admitted the artifact is
 *      subtle.importKey invoked, purely to test genuine interop (does
 *      WebCrypto ALSO accept what we accept) -- not to (re-)validate it.
 *      If WebCrypto unexpectedly throws here, that is a genuinely
 *      unexpected native failure on an already-admitted artifact and is
 *      re-thrown, not normalized into any SDK error class.
 *
 * Export mirrors this: our own exportRsaSer(material) is a pure function
 * producing the canonical SDK DER with NO WebCrypto involvement at all.
 * WebCrypto's own native export is invoked SEPARATELY (via a CryptoKey
 * built from the same already-admitted material through JWK, not through
 * our DER bytes) purely to compare against our canonical output -- an
 * R_byte question, kept conceptually distinct from R_ser.
 */

function realizationId(): string {
  return `node:${process.version} webcrypto RSA-ser (OpenSSL-backed; see sec:environment)`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function bigIntToBase64Url(n: bigint, byteLength?: number): string {
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex');
  if (byteLength !== undefined && bytes.length < byteLength) {
    const padded = Buffer.alloc(byteLength);
    bytes.copy(padded, byteLength - bytes.length);
    bytes = padded;
  }
  return bytes.toString('base64url');
}

/**
 * Builds a WebCrypto CryptoKey from already-admitted RsaKeyMaterial via
 * JWK -- deliberately NOT via our DER bytes, so this path exercises
 * WebCrypto's material handling independent of its own DER parser.
 * RSA-OAEP is used as the vehicle algorithm (arbitrary among the three
 * WebCrypto RSA identities -- irrelevant to the serialized bytes, since
 * the design freeze confirms rsaEncryption is generic).
 */
async function materialToCryptoKey(material: RsaKeyMaterial): Promise<CryptoKey> {
  if (material.role === 'public') {
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: bigIntToBase64Url(material.n),
      e: bigIntToBase64Url(material.e),
      ext: true,
    };
    return webcrypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  }
  const jwk: JsonWebKey = {
    kty: 'RSA',
    n: bigIntToBase64Url(material.n),
    e: bigIntToBase64Url(material.e),
    d: bigIntToBase64Url(material.d),
    p: bigIntToBase64Url(material.p),
    q: bigIntToBase64Url(material.q),
    dp: bigIntToBase64Url(material.dP),
    dq: bigIntToBase64Url(material.dQ),
    qi: bigIntToBase64Url(material.qInv),
    ext: true,
  };
  return webcrypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

export interface RsaSerImportEvidenceRecord {
  readonly operation: 'RSA-ser';
  readonly direction: 'import';
  readonly backend: { readonly name: 'webcrypto'; readonly realization: string };
  readonly clauseIds: string[];
  readonly mutationId: null;
  readonly input: { readonly role: 'public' | 'private'; readonly artifactHex: string };
  readonly outcome:
    | { readonly kind: 'accept'; readonly modulusBits: number }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
  readonly timestampIso: string;
}

export interface RsaSerExportEvidenceRecord {
  readonly operation: 'RSA-ser';
  readonly direction: 'export';
  readonly backend: { readonly name: 'webcrypto'; readonly realization: string };
  readonly clauseIds: string[];
  readonly mutationId: null;
  readonly input: { readonly role: 'public' | 'private' };
  readonly outcome:
    | { readonly kind: 'accept'; readonly artifactHex: string }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
  readonly timestampIso: string;
}

/**
 * I_p = API_p . Adapter_p for (RSA-ser import, WebCrypto). Also returns the
 * validated material and the CryptoKey obtained by feeding the SAME raw
 * artifact to WebCrypto's native subtle.importKey -- exposed for the test
 * suite's interop/R_byte checks, not part of the EvidenceRecord itself.
 */
export async function rsaSerWebCryptoImport(
  artifact: Uint8Array,
  role: 'public' | 'private',
): Promise<{ record: RsaSerImportEvidenceRecord; material?: RsaKeyMaterial; nativeCryptoKey?: CryptoKey }> {
  const input = { role, artifactHex: toHex(artifact) };

  let material: RsaKeyMaterial;
  try {
    material = importRsaSer(artifact, role); // Accept_C -- WebCrypto not touched yet
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        record: {
          operation: 'RSA-ser',
          direction: 'import',
          backend: { name: 'webcrypto', realization: realizationId() },
          clauseIds: err.clauseIds,
          mutationId: null,
          input,
          outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
          timestampIso: nowIso(),
        },
      };
    }
    throw err;
  }

  const format = role === 'public' ? 'spki' : 'pkcs8';
  const usages: KeyUsage[] = role === 'public' ? ['encrypt'] : ['decrypt'];
  let nativeCryptoKey: CryptoKey;
  try {
    nativeCryptoKey = await webcrypto.subtle.importKey(
      format,
      artifact as BufferSource,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      usages,
    );
  } catch (err) {
    throw new Error(
      `WebCrypto natively rejected an artifact this adapter's own Accept_C already admitted (role=${role}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const modulusBits = material.n.toString(2).length;
  return {
    record: {
      operation: 'RSA-ser',
      direction: 'import',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds:
        role === 'public'
          ? ['rsa-ser.der-syntax', 'rsa-ser.exact-consumption', 'rsa-ser.container', 'rsa-ser.role-container', 'rsa-ser.algorithm-id', 'rsa-ser.algorithm-params', 'rsa-ser.public-validity', 'rsa-ser.public-material']
          : ['rsa-ser.der-syntax', 'rsa-ser.exact-consumption', 'rsa-ser.container', 'rsa-ser.role-container', 'rsa-ser.algorithm-id', 'rsa-ser.algorithm-params', 'rsa-ser.private-domain', 'rsa-ser.private-relations', 'rsa-ser.private-material'],
      mutationId: null,
      input,
      outcome: { kind: 'accept', modulusBits },
      timestampIso: nowIso(),
    },
    material,
    nativeCryptoKey,
  };
}

/**
 * I_p = API_p . Adapter_p for (RSA-ser export, WebCrypto). `sdkArtifact` is
 * OUR OWN canonical output (pure function, no WebCrypto call) -- exposed
 * for the caller to compare against `webCryptoArtifact` (WebCrypto's native
 * export from the same material, via JWK) for the R_byte question. Only
 * `unsupported` is a legal export-time SDK error (D-056); not modeled in
 * M1 (no capability manifest yet).
 */
export async function rsaSerWebCryptoExport(
  material: RsaKeyMaterial,
): Promise<{ record: RsaSerExportEvidenceRecord; sdkArtifact: Uint8Array; webCryptoArtifact: Uint8Array }> {
  const sdkArtifact = exportRsaSer(material);

  const cryptoKey = await materialToCryptoKey(material);
  const format = material.role === 'public' ? 'spki' : 'pkcs8';
  const webCryptoArtifactBuffer = await webcrypto.subtle.exportKey(format, cryptoKey);
  const webCryptoArtifact = new Uint8Array(webCryptoArtifactBuffer);

  return {
    record: {
      operation: 'RSA-ser',
      direction: 'export',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds:
        material.role === 'public'
          ? ['rsa-ser.der-syntax', 'rsa-ser.container', 'rsa-ser.algorithm-id', 'rsa-ser.algorithm-params', 'rsa-ser.public-material']
          : ['rsa-ser.der-syntax', 'rsa-ser.container', 'rsa-ser.algorithm-id', 'rsa-ser.algorithm-params', 'rsa-ser.private-material'],
      mutationId: null,
      input: { role: material.role },
      outcome: { kind: 'accept', artifactHex: toHex(sdkArtifact) },
      timestampIso: nowIso(),
    },
    sdkArtifact,
    webCryptoArtifact,
  };
}
